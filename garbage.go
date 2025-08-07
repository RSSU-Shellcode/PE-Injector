package injector

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"text/template"
)

// The role of the junk code is to make the instruction sequence
// as featureless as possible.
var (
	//go:embed junk/*_x86.asm
	defaultJunkCodeFSX86 embed.FS

	//go:embed junk/*_x64.asm
	defaultJunkCodeFSX64 embed.FS

	defaultJunkCodeX86 = readJunkCodeTemplates(defaultJunkCodeFSX86)
	defaultJunkCodeX64 = readJunkCodeTemplates(defaultJunkCodeFSX64)
)

func readJunkCodeTemplates(efs embed.FS) []string {
	var templates []string
	err := fs.WalkDir(efs, ".", func(name string, entry fs.DirEntry, _ error) error {
		if entry.IsDir() {
			return nil
		}
		file, err := efs.Open(name)
		if err != nil {
			panic(err)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}
		templates = append(templates, string(data))
		return nil
	})
	if err != nil {
		panic(err)
	}
	return templates
}

type junkCodeCtx struct {
	// for replace registers
	Reg map[string]string

	// for insert random instruction pair
	Switch map[string]bool

	// for random immediate data
	BYTE  map[string]int8
	WORD  map[string]int16
	DWORD map[string]int32
	QWORD map[string]int64

	// for random immediate data with [0, 32) and [0, 64)
	Less32 map[string]int
	Less64 map[string]int
}

// the output garbage instruction length is no limit.
func (inj *Injector) garbageInst() []byte {
	if inj.opts.NoGarbage {
		return nil
	}
	// dynamically adjust probability
	var junkCodes []string
	switch inj.arch {
	case "386":
		junkCodes = inj.getJunkCodeX86()
	case "amd64":
		junkCodes = inj.getJunkCodeX64()
	}
	switch inj.rand.Intn(1 + len(junkCodes)) {
	case 0:
		return inj.garbageMultiByteNOP()
	default:
		return inj.garbageTemplate()
	}
}

func (inj *Injector) getJunkCodeX86() []string {
	if len(inj.opts.JunkCodeX86) > 0 {
		return inj.opts.JunkCodeX86
	}
	return defaultJunkCodeX86
}

func (inj *Injector) getJunkCodeX64() []string {
	if len(inj.opts.JunkCodeX64) > 0 {
		return inj.opts.JunkCodeX64
	}
	return defaultJunkCodeX64
}

func (inj *Injector) garbageMultiByteNOP() []byte {
	var nop []byte
	switch inj.rand.Intn(2) {
	case 0:
		nop = []byte{0x90}
	case 1:
		nop = []byte{0x66, 0x90}
	}
	return nop
}

// #nosec G115
func (inj *Injector) garbageTemplate() []byte {
	var junkCodes []string
	switch inj.arch {
	case "386":
		junkCodes = inj.getJunkCodeX86()
	case "amd64":
		junkCodes = inj.getJunkCodeX64()
	}
	// select random junk code template
	idx := inj.rand.Intn(len(junkCodes))
	junkCode := junkCodes[idx]
	// process assembly source
	tpl, err := template.New("junk_code").Funcs(template.FuncMap{
		"dr": toRegDWORD,
	}).Parse(junkCode)
	if err != nil {
		panic("invalid junk code template")
	}
	// initialize random data
	switches := make(map[string]bool)
	BYTE := make(map[string]int8)
	WORD := make(map[string]int16)
	DWORD := make(map[string]int32)
	QWORD := make(map[string]int64)
	Less32 := make(map[string]int)
	Less64 := make(map[string]int)
	for i := 'A'; i <= 'Z'; i++ {
		b := inj.rand.Intn(2) == 0
		switches[string(i)] = b
		switches[string(i+0x20)] = b
		BYTE[string(i)] = int8(inj.rand.Int31() % 128)
		WORD[string(i)] = int16(inj.rand.Int31() % 32768)
		DWORD[string(i)] = inj.rand.Int31()
		QWORD[string(i)] = inj.rand.Int63()
		Less32[string(i)] = inj.rand.Intn(32)
		Less64[string(i)] = inj.rand.Intn(64)
	}
	ctx := junkCodeCtx{
		Reg:    inj.buildRandomRegisterMap(),
		Switch: switches,
		BYTE:   BYTE,
		WORD:   WORD,
		DWORD:  DWORD,
		QWORD:  QWORD,
		Less32: Less32,
		Less64: Less64,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to build junk code assembly source: %s", err))
	}
	// assemble junk code
	inst, err := inj.assemble(buf.String())
	if err != nil {
		panic(fmt.Sprintf("failed to assemble junk code: %s", err))
	}
	return inst
}
