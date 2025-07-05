package injector

import (
	"bytes"
	"embed"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// The role of the shellcode loader is used to decrypt shellcode
// in the tail section to a new RWX page, then create thread at
// the decrypted shellcode.
var (
	//go:embed loader/loader_x86.asm
	defaultLoaderX86 string

	//go:embed loader/loader_x64.asm
	defaultLoaderX64 string
)

var (
	registerX86 = []string{
		"eax", "ebx", "ecx",
		"edx", "esi", "edi",
	}

	registerX64 = []string{
		"rax", "rbx", "rcx",
		"rdx", "rsi", "rdi",
		"r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15",
	}

	regVolatile = []string{
		"rax", "rcx", "rdx", "r8", "r9",
	}

	regStable = []string{
		"rbx", "rsi", "rdi",
		"r10", "r11", "r12", "r13", "r14", "r15",
	}
)

var (
	separator = []byte{0x8F, 0x17, 0x97, 0x3C} // split each instruction
	gpaOffset = []byte{0x33, 0x22, 0x11, 0xFF} // GetProcAddress offset in IAT
)

type loaderCtx struct {
	// for replace registers
	Reg  map[string]string
	RegV map[string]string
	RegS map[string]string

	LackProcedure bool

	LackCreateThread   bool
	LackVirtualAlloc   bool
	LackVirtualProtect bool

	LoadLibraryWOnly bool

	// "kernel32.dll\0" has 13 or 26 bytes
	Kernel32    []uint64
	Kernel32Key []uint64
}

func (inj *Injector) buildLoader() ([][]byte, error) {
	var (
		src string
	)
	switch inj.arch {
	case "386":
		src = inj.getLoaderX86()
	case "amd64":
		src = inj.getLoaderX64()
	}
	// create assembly source
	tpl, err := template.New("loader").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"dr":  toRegDWORD,
		"is":  insertSeparator,
	}).Parse(src)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	ctx := loaderCtx{
		Reg:  inj.buildRandomRegisterMap(),
		RegV: inj.buildVolatileRegisterMap(),
		RegS: inj.buildStableRegisterMap(),

		LackProcedure: true,

		LoadLibraryWOnly: true,

		Kernel32:    []uint64{1, 2, 3, 4},
		Kernel32Key: []uint64{11, 12, 13, 14},
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	inst, err := inj.assemble(buf.String())
	if err != nil {
		return nil, err
	}
	fmt.Println(buf.String())
	fmt.Println(len(inst))
	fmt.Println(inst)
	return nil, nil
}

func (inj *Injector) getLoaderX86() string {
	if inj.opts.LoaderX86 != "" {
		return inj.opts.LoaderX86
	}
	return defaultLoaderX86
}

func (inj *Injector) getLoaderX64() string {
	if inj.opts.LoaderX64 != "" {
		return inj.opts.LoaderX64
	}
	return defaultLoaderX64
}

func (inj *Injector) buildRandomRegisterMap() map[string]string {
	var reg []string
	switch inj.arch {
	case "386":
		reg = make([]string, len(registerX86))
		copy(reg, registerX86)
	case "amd64":
		reg = make([]string, len(registerX64))
		copy(reg, registerX64)
	}
	inj.regBox = reg
	register := make(map[string]string, 16)
	switch inj.arch {
	case "386":
		for _, reg := range registerX86 {
			register[reg] = inj.selectRegister()
		}
	case "amd64":
		for _, reg := range registerX64 {
			register[reg] = inj.selectRegister()
		}
	}
	return register
}

func (inj *Injector) buildVolatileRegisterMap() map[string]string {
	reg := make([]string, len(regVolatile))
	copy(reg, regVolatile)
	inj.regBox = reg
	register := make(map[string]string, len(regVolatile))
	for _, reg := range regVolatile {
		register[reg] = inj.selectRegister()
	}
	return register
}

func (inj *Injector) buildStableRegisterMap() map[string]string {
	reg := make([]string, len(regStable))
	copy(reg, regStable)
	inj.regBox = reg
	register := make(map[string]string, len(regStable))
	for _, reg := range regStable {
		register[reg] = inj.selectRegister()
	}
	return register
}

// selectRegister is used to make sure each register will be selected once.
func (inj *Injector) selectRegister() string {
	idx := inj.rand.Intn(len(inj.regBox))
	reg := inj.regBox[idx]
	// remove selected register
	inj.regBox = append(inj.regBox[:idx], inj.regBox[idx+1:]...)
	return reg
}

func toDB(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteString(".byte ")
	for i := 0; i < len(b); i++ {
		builder.WriteString("0x")
		s := hex.EncodeToString([]byte{b[i]})
		builder.WriteString(strings.ToUpper(s))
		builder.WriteString(", ")
	}
	return builder.String()
}

func toHex(v any) string {
	return fmt.Sprintf("0x%X", v)
}

// convert r8 -> r8d, rax -> eax
func toRegDWORD(reg string) string {
	_, err := strconv.Atoi(reg[1:])
	if err == nil {
		return reg + "d"
	}
	return strings.ReplaceAll(reg, "r", "e")
}

// for split each instruction
func insertSeparator() string {
	return ";" + toDB(separator) + ";"
}
