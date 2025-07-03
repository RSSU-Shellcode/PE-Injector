package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RSSU-Shellcode/PE-Injector"
)

var (
	opts  injector.Options
	sc    string
	hexSC bool
	in    string
	out   string
)

func init() {
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for generate loader")
	flag.StringVar(&opts.LoaderX86, "ldr-x86", "", "specify the x86 loader template file path")
	flag.StringVar(&opts.LoaderX64, "ldr-x64", "", "specify the x64 loader template file path")
	flag.StringVar(&sc, "sc", "", "set input shellcode file path")
	flag.BoolVar(&hexSC, "hex", false, "input shellcode with hex format")
	flag.StringVar(&in, "i", "", "set input pe image file path")
	flag.StringVar(&out, "o", "", "set output pe image file path")
	flag.Parse()
}

func main() {
	if in == "" {
		flag.Usage()
		return
	}
	if out == "" {
		err := os.Mkdir("output", 0700)
		checkError(err)
		out = filepath.Join("output", filepath.Base(in))
	}

	opts.LoaderX86 = loadSourceTemplate(opts.LoaderX86)
	opts.LoaderX64 = loadSourceTemplate(opts.LoaderX64)

	inj := injector.NewInjector()
	seed := opts.RandSeed
	if seed == 0 {
		seed = inj.Seed()
	}
	fmt.Println("random seed:", seed)

	fmt.Printf("read input shellcode from \"%s\"\n", sc)
	shellcode, err := os.ReadFile(sc) // #nosec
	checkError(err)
	if hexSC {
		shellcode, err = hex.DecodeString(string(shellcode))
		checkError(err)
	}
	fmt.Println("input shellcode size:", len(shellcode))

	fmt.Printf("read input PE image from \"%s\"\n", in)
	image, err := os.ReadFile(in) // #nosec
	checkError(err)
	fmt.Println("input PE image size:", len(image))

	output, err := inj.Inject(shellcode, image, &opts)
	checkError(err)

	fmt.Printf("write output image to \"%s\"\n", out)
	err = os.WriteFile(out, output, 0600)
	checkError(err)

	err = inj.Close()
	checkError(err)
}

func loadSourceTemplate(path string) string {
	if path == "" {
		return ""
	}
	fmt.Println("load custom loader template:", path)
	asm, err := os.ReadFile(path) // #nosec
	checkError(err)
	return string(asm)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
