package injector

// Info contains the image analyze result.
type Info struct {
	Architecture string     `toml:"architecture" json:"architecture"`
	IsDLL        bool       `toml:"is_dll"       json:"is_dll"`
	ImageSize    uint32     `toml:"image_size"   json:"image_size"`
	ImageBase    uint64     `toml:"image_base"   json:"image_base"`
	EntryPoint   uint32     `toml:"entry_point"  json:"entry_point"`
	Sections     []*Section `toml:"sections"     json:"sections"`
	Exports      []string   `toml:"exports"      json:"exports"`

	HasAllProcedures       bool `toml:"has_all_procedures"         json:"has_all_procedures"`
	HasVirtualAlloc        bool `toml:"has_virtual_alloc"          json:"has_virtual_alloc"`
	HasVirtualFree         bool `toml:"has_virtual_free"           json:"has_virtual_free"`
	HasVirtualProtect      bool `toml:"has_virtual_protect"        json:"has_virtual_protect"`
	HasCreateThread        bool `toml:"has_create_thread"          json:"has_create_thread"`
	HasWaitForSingleObject bool `toml:"has_wait_for_single_object" json:"has_wait_for_single_object"`
	HasLoadLibraryA        bool `toml:"has_load_library_a"         json:"has_load_library_a"`
	HasLoadLibraryW        bool `toml:"has_load_library_w"         json:"has_load_library_w"`
	HasGetProcAddress      bool `toml:"has_get_proc_address"       json:"has_get_proc_address"`

	NumCodeCaves     int  `toml:"num_code_caves"     json:"num_code_caves"`
	ContainSignature bool `toml:"contain_signature"  json:"contain_signature"`
	ContainCFG       bool `toml:"contain_cfg"        json:"contain_cfg"`
	CanCreateSection bool `toml:"can_create_section" json:"can_create_section"`
	CanInjectLoader  bool `toml:"can_inject_loader"  json:"can_inject_loader"`
	CanInjectJumper  bool `toml:"can_inject_jumper"  json:"can_inject_jumper"`
	InjectLoaderRank int  `toml:"inject_loader_rank" json:"inject_loader_rank"`
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
		arch       string
		imageSize  uint32
		imageBase  uint64
		entryPoint uint32
	)
	switch injector.arch {
	case "386":
		arch = "x86"
		imageSize = injector.hdr32.SizeOfImage
		imageBase = uint64(injector.hdr32.ImageBase)
		entryPoint = injector.hdr32.AddressOfEntryPoint
	case "amd64":
		arch = "x64"
		imageSize = injector.hdr64.SizeOfImage
		imageBase = injector.hdr64.ImageBase
		entryPoint = injector.hdr64.AddressOfEntryPoint
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
	exports := make([]string, l)
	for i := 0; i < l; i++ {
		exports[i] = injector.eat[i].proc
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
		Architecture:           arch,
		IsDLL:                  injector.dll,
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
		ContainCFG:             injector.containCFG,
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
