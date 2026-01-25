package injector

// Info contains the image analyze result.
type Info struct {
	ImageArch string `json:"image_arch"`
	ImageType string `json:"image_type"`
	ImageSize uint32 `json:"image_size"`
	ImageBase uint64 `json:"image_base"`

	EntryPoint uint64     `json:"entry_point"`
	Sections   []*Section `json:"sections"`
	Exports    []*Export  `json:"exports"`

	HasAllProcedures       bool `json:"has_all_procedures"`
	HasVirtualAlloc        bool `json:"has_virtual_alloc"`
	HasVirtualFree         bool `json:"has_virtual_free"`
	HasVirtualProtect      bool `json:"has_virtual_protect"`
	HasCreateThread        bool `json:"has_create_thread"`
	HasWaitForSingleObject bool `json:"has_wait_for_single_object"`
	HasLoadLibraryA        bool `json:"has_load_library_a"`
	HasLoadLibraryW        bool `json:"has_load_library_w"`
	HasGetProcAddress      bool `json:"has_get_proc_address"`

	NumCodeCaves      int  `json:"num_code_caves"`
	ContainSignature  bool `json:"contain_signature"`
	ContainLoadConfig bool `json:"contain_load_config"`
	CanCreateSection  bool `json:"can_create_section"`
	CanInjectLoader   bool `json:"can_inject_loader"`
	CanInjectJumper   bool `json:"can_inject_jumper"`
	InjectLoaderRank  int  `json:"inject_loader_rank"`
}

// Analyze is used to analyze the target pe image file that can be injected.
func Analyze(image []byte) (*Info, error) {
	injector := NewInjector()
	err := injector.preprocess(image, nil)
	if err != nil {
		return nil, err
	}
	// read pe image basic information
	var (
		imageArch  string
		imageSize  uint32
		imageBase  uint64
		entryPoint uint64
	)
	switch injector.arch {
	case "386":
		imageArch = "x86"
		imageSize = injector.hdr32.SizeOfImage
		imageBase = uint64(injector.hdr32.ImageBase)
		entryPoint = imageBase + uint64(injector.hdr32.AddressOfEntryPoint)
	case "amd64":
		imageArch = "x64"
		imageSize = injector.hdr64.SizeOfImage
		imageBase = injector.hdr64.ImageBase
		entryPoint = imageBase + uint64(injector.hdr64.AddressOfEntryPoint)
	}
	var imageType string
	if injector.dll {
		imageType = imageTypeDLL
	} else {
		imageType = imageTypeEXE
	}
	l := len(injector.img.Sections)
	sections := make([]*Section, l)
	for i := 0; i < l; i++ {
		sh := injector.img.Sections[i].SectionHeader
		sections[i] = &Section{
			Name:            sh.Name,
			VirtualSize:     sh.VirtualSize,
			VirtualAddress:  sh.VirtualAddress,
			SizeOfRawData:   sh.Size,
			OffsetToRawData: sh.Offset,
		}
	}
	l = len(injector.eat)
	exports := make([]*Export, l)
	for i := 0; i < l; i++ {
		eat := injector.eat[i]
		exports[i] = &Export{
			Name:    eat.proc,
			Address: injector.rvaToVA(eat.rva),
		}
	}
	// check the procedure in IAT
	hasLoadLibraryA := injector.getProcFromIAT("LoadLibraryA") != nil
	hasLoadLibraryW := injector.getProcFromIAT("LoadLibraryW") != nil
	hasGetProcAddress := injector.getProcFromIAT("GetProcAddress") != nil
	ctx := &loaderCtx{}
	hasCoreProc := injector.findProcFromIAT(ctx) == nil
	// process total rank
	numCaves := len(injector.caves)
	var canCreateSection bool
	_, err = injector.createSection(".test", 1024)
	if err == nil {
		canCreateSection = true
	}
	canInjectLoader := true
	if !hasCoreProc {
		canInjectLoader = false
	}
	var numLoaderInst int
	switch injector.arch {
	case "386":
		numLoaderInst = defaultMaxNumLoaderInstX86
	case "amd64":
		numLoaderInst = defaultMaxNumLoaderInstX64
	}
	if numLoaderInst+8 > numCaves {
		canInjectLoader = false
	}
	var injectLoaderRank int
	if canInjectLoader {
		injectLoaderRank = calcInjectLoaderRank(ctx)
	}
	info := Info{
		ImageArch:              imageArch,
		ImageType:              imageType,
		ImageSize:              imageSize,
		ImageBase:              imageBase,
		EntryPoint:             entryPoint,
		Sections:               sections,
		Exports:                exports,
		HasAllProcedures:       !ctx.LackProcedure,
		HasVirtualAlloc:        !ctx.LackVirtualAlloc,
		HasVirtualFree:         !ctx.LackVirtualFree,
		HasVirtualProtect:      !ctx.LackVirtualProtect,
		HasCreateThread:        !ctx.LackCreateThread,
		HasWaitForSingleObject: !ctx.LackWaitForSingleObject,
		HasLoadLibraryA:        hasLoadLibraryA,
		HasLoadLibraryW:        hasLoadLibraryW,
		HasGetProcAddress:      hasGetProcAddress,
		NumCodeCaves:           numCaves,
		ContainSignature:       injector.containSign,
		ContainLoadConfig:      injector.containCFG,
		CanCreateSection:       canCreateSection,
		CanInjectLoader:        canInjectLoader,
		CanInjectJumper:        numCaves > 0,
		InjectLoaderRank:       injectLoaderRank,
	}
	err = injector.Close()
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func calcInjectLoaderRank(ctx *loaderCtx) int {
	var rank int
	if !ctx.LackProcedure {
		rank = 100
		return rank
	}
	if !ctx.LackVirtualAlloc {
		rank += 18
	}
	if !ctx.LackVirtualFree {
		rank += 18
	}
	if !ctx.LackVirtualProtect {
		rank += 18
	}
	if !ctx.LackCreateThread {
		rank += 18
	}
	if !ctx.LackWaitForSingleObject {
		rank += 18
	}
	if !ctx.LoadLibraryWOnly {
		rank += 10
	}
	return rank
}
