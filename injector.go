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

	// assembler
	engine *keystone.Engine

	// context arguments
	opts *Options
	img  *pe.File
	dup  []byte
	arch string

	// for write shellcode loader
	caves []*codeCave

	// for select random register
	regBox []string
}

// Options contains options about inject shellcode.
type Options struct {
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
func (inj *Injector) Inject(shellcode, image []byte, opts *Options) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	if opts == nil {
		opts = new(Options)
	}
	inj.opts = opts
	// check image architecture
	peFile, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, err
	}
	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
	default:
		return nil, errors.New("unknown pe image architecture type")
	}
	inj.img = peFile
	inj.arch = arch
	// make duplicate about pe image
	dup := make([]byte, len(image))
	copy(dup, image)
	inj.dup = dup
	// scan code cave in image text section
	err = inj.scanCodeCave()
	if err != nil {
		return nil, fmt.Errorf("failed to scan code cave: %s", err)
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
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = inj.rand.Int63()
	}
	inj.rand.Seed(seed)
	// record the last seed
	inj.seed = seed
	// build shellcode loader
	loader, err := inj.buildLoader()
	if err != nil {
		return nil, fmt.Errorf("failed to build loader: %s", err)
	}

	fmt.Println(len(loader))

	// clean context data
	inj.img = nil
	inj.dup = nil
	inj.caves = nil
	return nil, nil
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
