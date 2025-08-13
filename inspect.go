package injector

import (
	"fmt"
	"strings"
)

// InspectOptions contains options about inspect loader template.
type InspectOptions struct {
	CodeCaveMode      bool
	ExtendSectionMode bool
	CreateSectionMode bool

	HasVirtualAlloc        bool
	HasVirtualFree         bool
	HasVirtualProtect      bool
	HasCreateThread        bool
	HasWaitForSingleObject bool
	HasLoadLibraryA        bool

	Arguments map[string]interface{}
}

// InspectLoaderTemplate is used to test junk code template.
func InspectLoaderTemplate(arch string, src string, opts *InspectOptions) (string, []byte, error) {
	injector := NewInjector()
	injector.arch = arch
	injector.opts = &Options{
		NoGarbage: true,

		ForceCodeCave:      opts.CodeCaveMode,
		ForceExtendSection: opts.ExtendSectionMode,
		ForceCreateSection: opts.CreateSectionMode,

		Arguments: opts.Arguments,
	}
	injector.ctx = new(Context)
	// build fake IAT from options.
	var list []*iat
	if opts.HasVirtualAlloc {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualAlloc",
			addr: 0x2000,
		})
	}
	if opts.HasVirtualFree {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualFree",
			addr: 0x3000,
		})
	}
	if opts.HasVirtualProtect {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualProtect",
			addr: 0x4000,
		})
	}
	if opts.HasCreateThread {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "CreateThread",
			addr: 0x5000,
		})
	}
	if opts.HasWaitForSingleObject {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "WaitForSingleObject",
			addr: 0x6000,
		})
	}
	if opts.HasLoadLibraryA {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "LoadLibraryA",
			addr: 0x7000,
		})
	} else {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "LoadLibraryW",
			addr: 0x7000,
		})
	}
	list = append(list, &iat{
		dll:  "kernel32.dll",
		proc: "GetProcAddress",
		addr: 0x8000,
	})
	injector.iat = list
	src = strings.ReplaceAll(src, "{{STUB CodeCaveMode STUB}}", "")
	err := injector.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, err := injector.buildLoaderASM(src, nil, true)
	if err != nil {
		return "", nil, err
	}
	inst, err := injector.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble loader: %s", err)
	}
	err = injector.Close()
	if err != nil {
		return "", nil, err
	}
	return asm, inst, nil
}

// InspectJunkCodeTemplate is used to test junk code template.
func InspectJunkCodeTemplate(arch string, src string) (string, []byte, error) {
	injector := NewInjector()
	injector.arch = arch
	injector.opts = new(Options)
	err := injector.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, err := injector.buildJunkCode(src)
	if err != nil {
		return "", nil, err
	}
	inst, err := injector.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble junk code: %s", err)
	}
	err = injector.Close()
	if err != nil {
		return "", nil, err
	}
	return asm, inst, nil
}
