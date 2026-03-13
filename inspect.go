package injector

import (
	"context"
	"fmt"
	"runtime"

	"golang.org/x/sync/errgroup"
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

// InspectLoaderTemplate is used to inspect loader template with all possible configurations.
func InspectLoaderTemplate(arch, template string) error {
	configs := buildPossibleConfigs()
	// send configs to channel
	configCh := make(chan *InspectConfig, len(configs))
	for _, config := range configs {
		configCh <- config
	}
	close(configCh)
	// start inspectors
	numWorker := runtime.NumCPU()/2 + 1
	if numWorker > 8 {
		numWorker = 1
	}
	group, ctx := errgroup.WithContext(context.Background())
	for i := 0; i < numWorker; i++ {
		group.Go(func() error {
			for {
				select {
				case config, ok := <-configCh:
					if !ok {
						return nil
					}
					_, _, err := InspectLoaderTemplateWithConfig(arch, template, config)
					if err != nil {
						return err
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
	}
	return group.Wait()
}

// InspectLoaderTemplateWithConfig is used to inspect loader template with config.
func InspectLoaderTemplateWithConfig(arch, template string, cfg *InspectConfig) (string, []byte, error) {
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
			rva:  0x10000,
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

func buildPossibleConfigs() []*InspectConfig {
	var configs []*InspectConfig
	for i := 0; i < 5; i++ {
		config := InspectConfig{}
		config.CodeCaveMode = i == 0
		config.CodeCaveNSMode = i == 1
		config.ExtendTextMode = i == 2
		config.ExtendTextNSMode = i == 3
		config.CreateTextMode = i == 4

		for i1 := 0; i1 < 2; i1++ {
			config.HasVirtualAlloc = i1 == 0
			for i2 := 0; i2 < 2; i2++ {
				config.HasVirtualFree = i2 == 0
				for i3 := 0; i3 < 2; i3++ {
					config.HasVirtualProtect = i3 == 0
					for i4 := 0; i4 < 2; i4++ {
						config.HasCreateThread = i4 == 0
						for i5 := 0; i5 < 2; i5++ {
							config.HasWaitForSingleObject = i5 == 0

							config.HasLoadLibraryA = true
							config.HasLoadLibraryW = false
							cp := config
							configs = append(configs, &cp)

							config.HasLoadLibraryA = false
							config.HasLoadLibraryW = true
							cp = config
							configs = append(configs, &cp)

							config.HasLoadLibraryA = true
							config.HasLoadLibraryW = true
							cp = config
							configs = append(configs, &cp)
						}
					}
				}
			}
		}
	}
	return configs
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
