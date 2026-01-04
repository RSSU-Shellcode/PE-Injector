package injector

import (
	"fmt"
	"strings"
)

// InspectConfig contains configuration about inspect loader template.
type InspectConfig struct {
	CodeCaveMode      bool `toml:"code_cave_mode"      json:"code_cave_mode"`
	ExtendSectionMode bool `toml:"extend_section_mode" json:"extend_section_mode"`
	CreateSectionMode bool `toml:"create_section_mode" json:"create_section_mode"`

	HasVirtualAlloc        bool `toml:"has_virtual_alloc"          json:"has_virtual_alloc"`
	HasVirtualFree         bool `toml:"has_virtual_free"           json:"has_virtual_free"`
	HasVirtualProtect      bool `toml:"has_virtual_protect"        json:"has_virtual_protect"`
	HasCreateThread        bool `toml:"has_create_thread"          json:"has_create_thread"`
	HasWaitForSingleObject bool `toml:"has_wait_for_single_object" json:"has_wait_for_single_object"`
	HasLoadLibraryA        bool `toml:"has_load_library_a"         json:"has_load_library_a"`
}

// InspectLoaderTemplate is used to test loader template.
func InspectLoaderTemplate(arch, template string, cfg *InspectConfig) (string, []byte, error) {
	switch arch {
	case "386", "amd64":
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %s", arch)
	}
	injector := NewInjector()
	// build injector internal status
	injector.arch = arch
	err := injector.initAssembler()
	if err != nil {
		return "", nil, err
	}
	injector.opts = &Options{
		NoGarbage: true,

		ForceCodeCave:      cfg.CodeCaveMode,
		ForceExtendSection: cfg.ExtendSectionMode,
		ForceCreateSection: cfg.CreateSectionMode,
	}
	injector.ctx = new(Context)
	injector.dup = make([]byte, 16*1024)
	injector.caves = []*codeCave{
		{
			virtualAddr:  0x10000,
			pointerToRaw: 0x1000,
			size:         32,
		},
	}
	injector.iat = buildFakeIATList(cfg)
	// build loader assembly source
	template = strings.ReplaceAll(template, codeCaveModeStub, "")
	asm, err := injector.buildLoaderASM(template, nil, false)
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

func buildFakeIATList(cfg *InspectConfig) []*iat {
	var list []*iat
	if cfg.HasVirtualAlloc {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualAlloc",
			rva:  0x2000,
		})
	}
	if cfg.HasVirtualFree {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualFree",
			rva:  0x3000,
		})
	}
	if cfg.HasVirtualProtect {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualProtect",
			rva:  0x4000,
		})
	}
	if cfg.HasCreateThread {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "CreateThread",
			rva:  0x5000,
		})
	}
	if cfg.HasWaitForSingleObject {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "WaitForSingleObject",
			rva:  0x6000,
		})
	}
	if cfg.HasLoadLibraryA {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "LoadLibraryA",
			rva:  0x7000,
		})
	} else {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "LoadLibraryW",
			rva:  0x7000,
		})
	}
	list = append(list, &iat{
		dll:  "kernel32.dll",
		proc: "GetProcAddress",
		rva:  0x8000,
	})
	return list
}

// InspectJunkCodeTemplate is used to test junk code template.
func InspectJunkCodeTemplate(arch string, template string) (string, []byte, error) {
	switch arch {
	case "386", "amd64":
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %s", arch)
	}
	injector := NewInjector()
	injector.arch = arch
	injector.opts = new(Options)
	err := injector.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, err := injector.buildJunkCode(template)
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
