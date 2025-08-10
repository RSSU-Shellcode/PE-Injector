package injector

import (
	"fmt"
)

// InspectOption contains options about inspect loader template.
type InspectOption struct {
	CodeCaveMode      bool
	ExtendSectionMode bool
	CreateSectionMode bool

	LackVirtualAlloc   bool
	LackVirtualProtect bool
	LackCreateThread   bool
	LackLoadLibraryA   bool

	Arguments map[string]interface{}
}

// InspectLoaderTemplate is used to test junk code template.
func InspectLoaderTemplate(arch string, src string, opts *InspectOption) (string, []byte, error) {
	injector := NewInjector()
	injector.arch = arch
	injector.opts = &Options{
		NoGarbage: true,
	}
	err := injector.initAssembler()
	if err != nil {
		return "", nil, err
	}

	asm, err := injector.buildLoaderASM(src, nil, false)
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
