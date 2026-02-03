package injector

import (
	"fmt"
)

// InspectConfig contains configuration about inspect loader template.
type InspectConfig struct {
	CodeCaveMode     bool `toml:"code_cave_mode"      json:"code_cave_mode"`
	CodeCaveNSMode   bool `toml:"code_cave_ns_mode"   json:"code_cave_ns_mode"`
	ExtendTextMode   bool `toml:"extend_text_mode"    json:"extend_text_mode"`
	ExtendTextNSMode bool `toml:"extend_text_ns_mode" json:"extend_text_ns_mode"`
	CreateTextMode   bool `toml:"create_text_mode"    json:"create_text_mode"`

	HasVirtualAlloc        bool `toml:"has_virtual_alloc"          json:"has_virtual_alloc"`
	HasVirtualFree         bool `toml:"has_virtual_free"           json:"has_virtual_free"`
	HasVirtualProtect      bool `toml:"has_virtual_protect"        json:"has_virtual_protect"`
	HasCreateThread        bool `toml:"has_create_thread"          json:"has_create_thread"`
	HasWaitForSingleObject bool `toml:"has_wait_for_single_object" json:"has_wait_for_single_object"`
	HasLoadLibraryA        bool `toml:"has_load_library_a"         json:"has_load_library_a"`
	HasLoadLibraryW        bool `toml:"has_load_library_w"         json:"has_load_library_w"`
}

// InspectLoaderTemplate is used to inspect loader template.
func InspectLoaderTemplate(arch, template string, cfg *InspectConfig) (string, []byte, error) {
	arch, err := selectInspectArch(arch)
	if err != nil {
		return "", nil, err
	}
	// build injector internal status
	injector := NewInjector()
	injector.arch = arch
	injector.opts = &Options{
		NoGarbageInst: true,

		ForceCodeCave:     cfg.CodeCaveMode,
		ForceCodeCaveNS:   cfg.CodeCaveNSMode,
		ForceExtendText:   cfg.ExtendTextMode,
		ForceExtendTextNS: cfg.ExtendTextNSMode,
		ForceCreateText:   cfg.CreateTextMode,
	}
	injector.ctx = new(Context)
	injector.dup = make([]byte, 16*1024)
	injector.caves = []*codeCave{
		{
			va:   0x10000,
			off:  0x1000,
			size: 32,
		},
	}
	injector.iat = buildFakeIATList(cfg)
	err = injector.initAssembler()
	if err != nil {
		return "", nil, err
	}
	// build loader assembly source
	template = removeCodeCaveModeStub(template)
	asm, err := injector.generateLoader(template, nil, false)
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

// InspectJunkCodeTemplate is used to inspect junk code template.
func InspectJunkCodeTemplate(arch, template string) (string, []byte, error) {
	arch, err := selectInspectArch(arch)
	if err != nil {
		return "", nil, err
	}
	// build injector internal status
	injector := NewInjector()
	injector.arch = arch
	injector.opts = new(Options)
	err = injector.initAssembler()
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

func selectInspectArch(arch string) (string, error) {
	switch arch {
	case "386", "amd64":
	case "x86":
		arch = "386"
	case "x64":
		arch = "amd64"
	default:
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}
	return arch, nil
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
	}
	if cfg.HasLoadLibraryW {
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
