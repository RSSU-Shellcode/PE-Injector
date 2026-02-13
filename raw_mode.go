package injector

import (
	"errors"
	"fmt"
)

const reservedCodeCaves = 16

func (inj *Injector) selectInjectRawMode(shellcode []byte) error {
	if inj.opts.ForceCodeCaveNS {
		return errors.New("code cave with new section mode is not support")
	}
	if inj.opts.ForceExtendTextNS {
		return errors.New("extend text with new section mode is not support")
	}
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
		return errors.New("set too many force mode in options")
	}
	if counter == 1 {
		return inj.useForceRawMode(shellcode)
	}
	// try to use these modes in the following order
	// 1. CodeCave
	// 2. ExtendText
	// 3. CreateText
	err := inj.useCodeCaveRawMode(shellcode)
	if err == nil {
		return nil
	}
	err = inj.useExtendTextRawMode(shellcode)
	if err == nil {
		return nil
	}
	err = inj.useCreateTextRawMode(shellcode)
	if err == nil {
		return nil
	}
	return errors.New("unable to select any mode for inject raw")
}

func (inj *Injector) useForceRawMode(shellcode []byte) error {
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

func (inj *Injector) useCodeCaveRawMode(shellcode []byte) error {
	insts, err := inj.disassemble(shellcode)
	if err != nil {
		return fmt.Errorf("failed to disassemble shellcode: %s", err)
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
		return errors.New("not enough code caves for code cave mode")
	}
	inj.ctx.Mode = ModeCodeCave
	return nil
}

func (inj *Injector) useExtendTextRawMode(shellcode []byte) error {
	if !inj.canTryExtendText {
		return errors.New("the first section without RX")
	}
	scSize := uint32(len(shellcode))
	// calculate the section extend size
	randomBeginSize := uint32(64 + inj.rand.Intn(64)) // #nosec G115
	randomEndSize := uint32(32 + inj.rand.Intn(256))  // #nosec G115
	reservedInstSize := inj.calcReservedCtxInstSize()
	size := uint32(0)
	size += randomBeginSize
	size += reservedInstSize
	size += scSize
	size += reservedInstSize
	size += randomEndSize
	// extend text and update internal status
	output, extended, err := inj.extendTextSection(size)
	if err != nil {
		return err
	}
	err = inj.preprocess(output, inj.opts)
	if err != nil {
		return err
	}
	text := inj.img.Sections[0]
	// padding the extended section
	for i := uint32(0); i < extended; i++ {
		inj.dup[text.Offset+i] = 0xCC
	}
	inj.paddingGarbageInst(text.Offset, randomBeginSize+reservedInstSize)
	off := randomBeginSize + reservedInstSize + scSize
	inj.paddingGarbageInst(text.Offset+off, extended-off)
	// update context
	inj.extendTextSize = extended
	inj.dstRVA = text.VirtualAddress + randomBeginSize
	inj.dstFOA = text.Offset + randomBeginSize
	inj.ctx.Mode = ModeExtendText
	inj.ctx.ExtendedSize = extended
	return nil
}

func (inj *Injector) useCreateTextRawMode(shellcode []byte) error {

	inj.ctx.Mode = ModeCreateText
	return nil
}
