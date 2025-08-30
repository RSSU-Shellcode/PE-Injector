package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RSSU-Shellcode/PE-Injector"
)

var (
	target      string
	minNumCaves int
	mustNotSign bool
)

func init() {
	flag.StringVar(&target, "path", "", "target directory path for scan")
	flag.IntVar(&minNumCaves, "mnc", 200, "set minimum number of cave nodes")
	flag.BoolVar(&mustNotSign, "mns", false, "ignore PE image with digital signature")
	flag.Parse()
}

func main() {
	if target == "" {
		flag.Usage()
		return
	}
	err := filepath.Walk(target, func(path string, file os.FileInfo, _ error) error {
		if file.IsDir() {
			return nil
		}
		ext := filepath.Ext(file.Name())
		if ext != ".exe" && ext != ".dll" {
			return nil
		}
		image, err := os.ReadFile(path) // #nosec
		if err != nil {
			return nil
		}
		info, err := injector.Analyze(image)
		if err != nil {
			return nil
		}
		if !info.CanCreateSection && !info.CanInjectLoader {
			return nil
		}
		if info.NumCodeCaves < minNumCaves {
			return nil
		}
		if mustNotSign && info.ContainSignature {
			return nil
		}
		fmt.Println(path)
		fmt.Println("num code caves:    ", info.NumCodeCaves)
		fmt.Println("can create section:", info.CanCreateSection)
		fmt.Println("can inject loader: ", info.CanInjectLoader)
		fmt.Println("can inject jumper: ", info.CanInjectJumper)
		if info.CanInjectLoader {
			fmt.Println("inject loader rank:", info.InjectLoaderRank)
		}
		fmt.Println()
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}
}
