package injector

// Info contains the image analyze result.
type Info struct {
	Architecture string
	ImageSize    uint32
	ImageBase    uint64
	EntryPoint   uint32
	Sections     []*Section

	HasAllProcedures       bool
	HasVirtualAlloc        bool
	HasVirtualFree         bool
	HasVirtualProtect      bool
	HasCreateThread        bool
	HasWaitForSingleObject bool
	HasLoadLibraryA        bool
	HasLoadLibraryW        bool
	HasGetProcAddress      bool

	NumCodeCaves     int
	HasSignature     bool
	CanCreateSection bool
	CanInjectJumper  bool
	CanInjectLoader  bool
	InjectLoaderRank int
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
		numLoaderInst = maxNumLoaderInstX86
	case "amd64":
		numLoaderInst = maxNumLoaderInstX64
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
		ImageSize:              imageSize,
		ImageBase:              imageBase,
		EntryPoint:             entryPoint,
		Sections:               sections,
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
		HasSignature:           injector.hasSignature,
		CanCreateSection:       canCreateSection,
		CanInjectJumper:        numCaves > 0,
		CanInjectLoader:        canInjectLoader,
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
