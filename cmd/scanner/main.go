package main

import (
	"flag"
	"fmt"

	"github.com/RSSU-Shellcode/PE-Injector"
)

var (
	path string
	opts injector.ScanOptions
)

func init() {
	flag.StringVar(&path, "p", "", "set the target directory path for scan")
	flag.IntVar(&opts.MinNumCaves, "mnc", 350, "set minimum number of cave nodes")
	flag.BoolVar(&opts.NoSignature, "ns", false, "ignore PE image with digital signature")
	flag.BoolVar(&opts.NoLoadConfig, "nlc", false, "ignore PE image with load config")
	flag.BoolVar(&opts.IgnoreRank, "ir", false, "ignore inject loader pre-detection")
	flag.Parse()
}

func main() {
	if path == "" {
		flag.Usage()
		return
	}

	results, err := injector.Scan(path, &opts)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, result := range results {
		fmt.Println(result.Path)
		info := result.Info
		fmt.Println("num code caves:    ", info.NumCodeCaves)
		fmt.Println("can create section:", info.CanCreateSection)
		fmt.Println("can inject loader: ", info.CanInjectLoader)
		if info.CanInjectLoader {
			fmt.Println("inject loader rank:", info.InjectLoaderRank)
		}
		fmt.Println()
	}
}
