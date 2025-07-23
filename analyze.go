package injector

import (
	"debug/pe"
)

// Info contains the image analyze result.
type Info struct {
	Architecture string
	ImageSize    uint32
	ImageBase    uint64
	EntryPoint   uint32
	Sections     []*pe.SectionHeader

	LackProcedure      bool
	LackVirtualAlloc   bool
	LackVirtualProtect bool
	LackCreateThread   bool
	LackLoadLibraryA   bool
	LackLoadLibraryW   bool
	LackGetProcAddress bool

	NumCodeCaves    int
	CanInjectLoader bool
	Rank            int
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
	sections := make([]*pe.SectionHeader, l)
	for i := 0; i < l; i++ {
		sections[i] = &injector.img.Sections[i].SectionHeader
	}
	// check the procedure in IAT
	lackLoadLibraryA := injector.getProcFromIAT("LoadLibraryA") == nil
	lackLoadLibraryW := injector.getProcFromIAT("LoadLibraryW") == nil
	lackGetProcAddress := injector.getProcFromIAT("GetProcAddress") == nil
	ctx := &loaderCtx{}
	hasCoreProc := injector.findProcFromIAT(ctx) == nil
	// process rank
	numCaves := len(injector.caves)
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
	var rank int
	if canInjectLoader {
		rank = calculateRank(ctx)
	}
	info := Info{
		Architecture:       arch,
		ImageSize:          imageSize,
		ImageBase:          imageBase,
		EntryPoint:         entryPoint,
		Sections:           sections,
		LackProcedure:      ctx.LackProcedure,
		LackVirtualAlloc:   ctx.LackVirtualAlloc,
		LackVirtualProtect: ctx.LackVirtualProtect,
		LackCreateThread:   ctx.LackCreateThread,
		LackLoadLibraryA:   lackLoadLibraryA,
		LackLoadLibraryW:   lackLoadLibraryW,
		LackGetProcAddress: lackGetProcAddress,
		NumCodeCaves:       numCaves,
		CanInjectLoader:    canInjectLoader,
		Rank:               rank,
	}
	err = injector.Close()
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func calculateRank(ctx *loaderCtx) int {
	var rank int
	if !ctx.LackProcedure {
		rank = 100
		return rank
	}
	if !ctx.LackVirtualAlloc {
		rank += 25
	}
	if !ctx.LackVirtualProtect {
		rank += 25
	}
	if !ctx.LackCreateThread {
		rank += 25
	}
	if !ctx.LoadLibraryWOnly {
		rank += 25
	}
	return rank
}
