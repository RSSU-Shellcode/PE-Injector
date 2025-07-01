package injector

import (
	cr "crypto/rand"
	"encoding/binary"
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
	arch int
	opts *Options

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
func NewInjector(seed int64) *Injector {
	if seed == 0 {
		buf := make([]byte, 8)
		_, err := cr.Read(buf)
		if err == nil {
			seed = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115
		} else {
			seed = time.Now().UTC().UnixNano()
		}
	}
	rng := rand.New(rand.NewSource(seed)) // #nosec
	injector := Injector{
		seed: seed,
		rand: rng,
	}
	return &injector
}

// Encode is used to encode input shellcode to a unique shellcode.
func (inj *Injector) Encode(image, shellcode []byte, opts *Options) ([]byte, error) {

	return nil, nil
}
