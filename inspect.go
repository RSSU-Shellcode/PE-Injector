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

// InspectLoaderTemplate is used to test junk code template.
func InspectLoaderTemplate(arch string, src string, cfg *InspectConfig) (string, []byte, error) {
	switch arch {
	case "386", "amd64":
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %s", arch)
	}
	injector := NewInjector()
	injector.arch = arch
	injector.opts = &Options{
		NoGarbage: true,

		ForceCodeCave:      cfg.CodeCaveMode,
		ForceExtendSection: cfg.ExtendSectionMode,
		ForceCreateSection: cfg.CreateSectionMode,
	}
	injector.ctx = new(Context)
	injector.dup = make([]byte, 16*1024)
	injector.caves = []*codeCave{
		{0x10000, 0x1000, 32},
	}
	injector.iat = buildFakeIATList(cfg)
	src = strings.ReplaceAll(src, codeCaveModeStub, "")
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

func buildFakeIATList(cfg *InspectConfig) []*iat {
	var list []*iat
	if cfg.HasVirtualAlloc {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualAlloc",
			addr: 0x2000,
		})
	}
	if cfg.HasVirtualFree {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualFree",
			addr: 0x3000,
		})
	}
	if cfg.HasVirtualProtect {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "VirtualProtect",
			addr: 0x4000,
		})
	}
	if cfg.HasCreateThread {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "CreateThread",
			addr: 0x5000,
		})
	}
	if cfg.HasWaitForSingleObject {
		list = append(list, &iat{
			dll:  "kernel32.dll",
			proc: "WaitForSingleObject",
			addr: 0x6000,
		})
	}
	if cfg.HasLoadLibraryA {
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
	return list
}

// InspectJunkCodeTemplate is used to test junk code template.
func InspectJunkCodeTemplate(arch string, src string) (string, []byte, error) {
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
