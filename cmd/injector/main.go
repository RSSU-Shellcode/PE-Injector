package main

import (
	"encoding/hex"
	"encoding/json"
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
	raw   bool
	jcx86 string
	jcx64 string
	args  string
	opts  injector.Options
)

func init() {
	flag.StringVar(&img, "img", "", "set input pe image file path")
	flag.StringVar(&sc, "sc", "", "set input shellcode file path")
	flag.BoolVar(&hexSC, "hex", false, "input shellcode with hex format")
	flag.StringVar(&out, "o", "", "set output pe image file path")
	flag.BoolVar(&aye, "a", false, "analyze the pe image for inject")
	flag.BoolVar(&raw, "raw", false, "inject shellcode without loader")
	flag.StringVar(&args, "args", "", "set custom arguments for loader template from a json file")
	flag.Uint64Var(&opts.Address, "addr", 0, "specify the target function address that will be hooked")
	flag.BoolVar(&opts.NotSaveContext, "nsc", false, "not append instruction about save and restore context")
	flag.BoolVar(&opts.NotCreateThread, "nct", false, "not create thread at the shellcode")
	flag.BoolVar(&opts.NotWaitThread, "nwt", false, "not wait created thread at the shellcode")
	flag.BoolVar(&opts.NotEraseShellcode, "nes", false, "not erase shellcode after execute finish")
	flag.BoolVar(&opts.NoShellcodeJumper, "nsj", false, "not add a shellcode jumper to call shellcode")
	flag.BoolVar(&opts.NoGarbage, "ng", false, "not append garbage instruction to loader")
	flag.StringVar(&opts.SectionName, "sn", "", "specify the section name that will be created")
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for generate loader")
	flag.BoolVar(&opts.ForceCodeCave, "fcc", false, "force use code cave mode")
	flag.BoolVar(&opts.ForceExtendSection, "fes", false, "force use extend section mode")
	flag.BoolVar(&opts.ForceCreateSection, "fcs", false, "force use create section mode")
	flag.StringVar(&opts.LoaderX86, "ldr-x86", "", "specify the x86 loader template file path")
	flag.StringVar(&opts.LoaderX64, "ldr-x64", "", "specify the x64 loader template file path")
	flag.StringVar(&jcx86, "junk-x86", "", "specify the x86 junk template directory path")
	flag.StringVar(&jcx64, "junk-x64", "", "specify the x64 junk template directory path")
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

	opts.LoaderX86 = loadLoaderTemplate(opts.LoaderX86)
	opts.LoaderX64 = loadLoaderTemplate(opts.LoaderX64)
	opts.JunkCodeX86 = loadJunkCodeTemplate(jcx86)
	opts.JunkCodeX64 = loadJunkCodeTemplate(jcx64)
	if args != "" {
		data, err := os.ReadFile(args) // #nosec
		checkError(err)
		err = json.Unmarshal(data, &opts.Arguments)
		checkError(err)
	}

	inj := injector.NewInjector()
	var ctx *injector.Context
	if raw {
		ctx, err = inj.InjectRaw(image, shellcode, &opts)
	} else {
		ctx, err = inj.Inject(image, shellcode, &opts)
	}
	checkError(err)
	fmt.Println("==============Context===============")
	fmt.Println("arch:", ctx.Arch)
	fmt.Println("mode:", ctx.Mode)
	fmt.Println("dll: ", ctx.IsDLL)
	fmt.Println("raw: ", ctx.IsRaw)
	fmt.Println("size:", len(ctx.Output))
	fmt.Println("seed:", ctx.Seed)
	fmt.Println()
	fmt.Println("save context:    ", ctx.SaveContext)
	fmt.Println("create thread:   ", ctx.CreateThread)
	fmt.Println("wait thread:     ", ctx.WaitThread)
	fmt.Println("erase shellcode: ", ctx.EraseShellcode)
	fmt.Println("shellcode jumper:", ctx.ShellcodeJumper)
	fmt.Println("has garbage:     ", ctx.HasGarbage)
	fmt.Println("section name:    ", ctx.SectionName)
	fmt.Println()
	fmt.Println("Procedure Complete: ", ctx.HasAllProcedures)
	fmt.Println("VirtualAlloc:       ", ctx.HasVirtualAlloc)
	fmt.Println("VirtualFree:        ", ctx.HasVirtualFree)
	fmt.Println("VirtualProtect:     ", ctx.HasVirtualProtect)
	fmt.Println("CreateThread:       ", ctx.HasCreateThread)
	fmt.Println("WaitForSingleObject:", ctx.HasWaitForSingleObject)
	fmt.Println("LoadLibraryA:       ", ctx.HasLoadLibraryA)
	fmt.Println("LoadLibraryW:       ", ctx.HasLoadLibraryW)
	fmt.Println("GetProcAddress:     ", ctx.HasGetProcAddress)
	fmt.Println()
	fmt.Println("num code caves:  ", ctx.NumCodeCaves)
	fmt.Println("num loader insts:", ctx.NumLoaderInst)
	fmt.Printf("hook address:     0x%X\n", ctx.HookAddress)
	fmt.Println("====================================")

	fmt.Printf("write output image to \"%s\"\n", out)
	err = os.WriteFile(out, ctx.Output, 0600)
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
	fmt.Println("Arch: ", info.Architecture)
	fmt.Println("IsDLL:", info.IsDLL)
	fmt.Println("ImageSize: ", info.ImageSize)
	fmt.Printf("ImageBase:  0x%X\n", info.ImageBase)
	fmt.Printf("EntryPoint: 0x%X\n", info.EntryPoint)
	fmt.Println("===============PE Sections==============")
	for _, s := range info.Sections {
		fmt.Print(s.Name + " ")
	}
	fmt.Println()
	fmt.Println("===============Procedures===============")
	fmt.Println("Procedure Complete: ", info.HasAllProcedures)
	fmt.Println("VirtualAlloc:       ", info.HasVirtualAlloc)
	fmt.Println("VirtualFree:        ", info.HasVirtualFree)
	fmt.Println("VirtualProtect:     ", info.HasVirtualProtect)
	fmt.Println("CreateThread:       ", info.HasCreateThread)
	fmt.Println("WaitForSingleObject:", info.HasWaitForSingleObject)
	fmt.Println("LoadLibraryA:       ", info.HasLoadLibraryA)
	fmt.Println("LoadLibraryW:       ", info.HasLoadLibraryW)
	fmt.Println("GetProcAddress:     ", info.HasGetProcAddress)
	fmt.Println("================Injector================")
	fmt.Println("NumCodeCaves:    ", info.NumCodeCaves)
	fmt.Println("CanCreateSection:", info.CanCreateSection)
	fmt.Println("CanInjectJumper: ", info.CanInjectJumper)
	fmt.Println("CanInjectLoader: ", info.CanInjectLoader)
	fmt.Println("InjectLoaderRank:", info.InjectLoaderRank)
	fmt.Println("========================================")
}

func loadLoaderTemplate(path string) string {
	if path == "" {
		return ""
	}
	fmt.Println("load custom loader template:", path)
	template, err := os.ReadFile(path) // #nosec
	checkError(err)
	return string(template)
}

func loadJunkCodeTemplate(dir string) []string {
	if dir == "" {
		return nil
	}
	fmt.Println("load custom junk code template directory:", dir)
	files, err := os.ReadDir(dir)
	checkError(err)
	templates := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, file.Name())) // #nosec
		checkError(err)
		templates = append(templates, string(data))
	}
	return templates
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
