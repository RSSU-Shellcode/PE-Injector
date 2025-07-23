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
	img   string
	sc    string
	hexSC bool
	out   string
	aye   bool
	opts  injector.Options
)

func init() {
	flag.StringVar(&img, "img", "", "set input pe image file path")
	flag.StringVar(&sc, "sc", "", "set input shellcode file path")
	flag.BoolVar(&hexSC, "hex", false, "input shellcode with hex format")
	flag.StringVar(&out, "o", "", "set output pe image file path")
	flag.BoolVar(&aye, "a", false, "analyze the pe image for inject")
	flag.Uint64Var(&opts.Address, "addr", 0, "specify the target function address that will be hooked")
	flag.BoolVar(&opts.NotSaveContext, "nsc", false, "not append instruction about save and restore context")
	flag.BoolVar(&opts.NotCreateThread, "nct", false, "not create thread at the shellcode")
	flag.BoolVar(&opts.NotWaitThread, "nwt", false, "not wait created thread at the shellcode")
	flag.BoolVar(&opts.NotEraseShellcode, "nes", false, "not erase shellcode after execute finish")
	flag.BoolVar(&opts.ForceCodeCave, "fcc", false, "force use code cave mode for write shellcode")
	flag.BoolVar(&opts.ForceExtendSection, "fes", false, "force extend the last section for write shellcode")
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for generate loader")
	flag.StringVar(&opts.LoaderX86, "ldr-x86", "", "specify the x86 loader template file path")
	flag.StringVar(&opts.LoaderX64, "ldr-x64", "", "specify the x64 loader template file path")
	flag.Parse()
}

func main() {
	if img == "" {
		flag.Usage()
		return
	}
	if aye {
		analyzeImage()
		return
	}
	if out == "" {
		err := os.Mkdir("output", 0700)
		checkError(err)
		out = filepath.Join("output", filepath.Base(img))
	}
	opts.LoaderX86 = loadSourceTemplate(opts.LoaderX86)
	opts.LoaderX64 = loadSourceTemplate(opts.LoaderX64)

	inj := injector.NewInjector()
	seed := opts.RandSeed
	if seed == 0 {
		seed = inj.Seed()
	}
	fmt.Println("random seed:", seed)

	fmt.Printf("read input PE image from \"%s\"\n", img)
	image, err := os.ReadFile(img) // #nosec
	checkError(err)
	fmt.Println("input PE image size:", len(image))

	fmt.Printf("read input shellcode from \"%s\"\n", sc)
	shellcode, err := os.ReadFile(sc) // #nosec
	checkError(err)
	if hexSC {
		shellcode, err = hex.DecodeString(string(shellcode))
		checkError(err)
	}
	fmt.Println("input shellcode size:", len(shellcode))

	output, err := inj.Inject(image, shellcode, &opts)
	checkError(err)

	fmt.Printf("write output image to \"%s\"\n", out)
	err = os.WriteFile(out, output, 0600)
	checkError(err)

	err = inj.Close()
	checkError(err)
}

func analyzeImage() {
	image, err := os.ReadFile(img) // #nosec
	checkError(err)
	info, err := injector.Analyze(image)
	checkError(err)
	fmt.Println("================PE image================")
	fmt.Println("Architecture:", info.Architecture)
	fmt.Println("ImageSize: ", info.ImageSize)
	fmt.Printf("ImageBase:  0x%X\n", info.ImageBase)
	fmt.Printf("EntryPoint: 0x%X\n", info.EntryPoint)
	fmt.Println("===============Procedures===============")
	fmt.Println("Entirety:      ", info.HasAllProcedures)
	fmt.Println("VirtualAlloc:  ", info.HasVirtualAlloc)
	fmt.Println("VirtualProtect:", info.HasVirtualProtect)
	fmt.Println("CreateThread:  ", info.HasCreateThread)
	fmt.Println("LoadLibraryA:  ", info.HasLoadLibraryA)
	fmt.Println("LoadLibraryW:  ", info.HasLoadLibraryW)
	fmt.Println("GetProcAddress:", info.HasGetProcAddress)
	fmt.Println("================Injector================")
	fmt.Println("NumCodeCaves:    ", info.NumCodeCaves)
	fmt.Println("CanInjectLoader: ", info.CanInjectLoader)
	fmt.Println("InjectLoaderRank:", info.InjectLoaderRank)
	fmt.Println("========================================")
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
