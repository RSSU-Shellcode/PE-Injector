package injector

import (
	"bytes"
	cr "crypto/rand"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
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
	arch string

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
		seed: seed,
		rand: rng,
	}
	return &injector
}

// Inject is used to inject shellcode to a PE image.
func (inj *Injector) Inject(shellcode, image []byte, opts *Options) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	peFile, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return nil, err
	}
	// check image architecture
	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "amd64"
	default:
		return nil, errors.New("unknown pe image architecture type")
	}
	inj.arch = arch
	// check image text section tail has enough
	// space for write shellcode loader
	var text *pe.Section
	for _, section := range peFile.Sections {
		if section.Name == ".text" {
			text = section
			break
		}
	}
	if text == nil {
		return nil, errors.New("cannot find .text section in image")
	}

	data, _ := text.Data()
	fmt.Println(len(data))

	fmt.Println(text.Size)
	fmt.Println(text.VirtualSize)

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
