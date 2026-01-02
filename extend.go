package injector

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
)

func (inj *Injector) extendTextSection(size uint32) ([]byte, error) {
	if !inj.canTryExtend {
		return nil, errors.New("the first section without RX")
	}
	err := inj.checkImageAlignment()
	if err != nil {
		return nil, err
	}
	// align the size to section alignment size
	// for adjust other section data easily
	size = inj.alignSection(size)
	// copy all data before the first section data
	output := make([]byte, len(inj.dup)+int(size))
	copy(output, inj.dup[:inj.img.Sections[0].Offset])
	// extend the first section
	for _, step := range []func(output []byte, size uint32){
		inj.adjustOptionalHeader,
		inj.adjustDataDirectory,
		inj.adjustSectionHeader,
		inj.adjustExportDirectory,
		inj.adjustImportDescriptor,
		inj.adjustBaseRelocation,
	} {
		step(output, size)
	}
	return output, nil
}

func (inj *Injector) checkImageAlignment() error {
	if inj.sectionAlign < inj.fileAlign {
		return errors.New("section alignment is less than file alignment")
	}
	if inj.sectionAlign%inj.fileAlign != 0 {
		return errors.New("section alignment is not aligned to file alignment")
	}
	return nil
}

func (inj *Injector) adjustOptionalHeader(output []byte, size uint32) {
	var optHdr []byte
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.AddressOfEntryPoint += size
		hdr.SizeOfCode += size
		hdr.SizeOfImage += size
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// ignore data directory
		optHdr = buffer.Bytes()[:imageOptionHeaderSize32]
	case "amd64":
		hdr := *inj.hdr64
		hdr.AddressOfEntryPoint += size
		hdr.SizeOfCode += size
		hdr.SizeOfImage += size
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// ignore data directory
		optHdr = buffer.Bytes()[:imageOptionHeaderSize64]
	}
	copy(output[inj.offOptHdr:], optHdr)
}

func (inj *Injector) adjustDataDirectory(output []byte, size uint32) {
	for i := uint32(0); i < inj.numDataDir; i++ {
		dd := new(pe.DataDirectory)
		offset := inj.offDataDir + i*imageDataDirectorySize
		readStruct(inj.dup[offset:], dd)
		if dd.VirtualAddress == 0 {
			continue
		}
		dd.VirtualAddress += size
		// rewrite data directory
		writeStruct(output[offset:], dd)
	}
}

func (inj *Injector) adjustSectionHeader(output []byte, size uint32) {
	// adjust the text section header
	shOffset := inj.offOptHdr + uint32(inj.img.SizeOfOptionalHeader)
	text := new(pe.SectionHeader32)
	readStruct(inj.dup[shOffset:], text)
	// copy text section data
	textPtr := text.PointerToRawData
	copy(output[textPtr+size:], inj.dup[textPtr:textPtr+text.SizeOfRawData])
	// adjust section size
	text.VirtualSize += size
	text.SizeOfRawData += size
	// overwrite the text section
	writeStruct(output[shOffset:], text)
	// adjust other sections
	for i := 1; i < len(inj.img.Sections); i++ {
		shOffset += imageSectionHeaderSize
		section := new(pe.SectionHeader32)
		readStruct(inj.dup[shOffset:], section)
		// copy section data
		ptr := section.PointerToRawData
		copy(output[ptr+size:], inj.dup[ptr:ptr+section.SizeOfRawData])
		// adjust section size
		section.VirtualAddress += size
		section.PointerToRawData += size
		// overwrite section header
		writeStruct(output[shOffset:], section)
	}
}

func (inj *Injector) adjustExportDirectory(output []byte, size uint32) {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	foa := inj.rvaToFOA(dd.VirtualAddress)
	src := inj.dup[foa:]
	dst := output[foa+size:]
	// overwrite export directory
	srcDir := &exportDirectory{}
	readStruct(src, srcDir)
	dstDir := &exportDirectory{
		Characteristics:       srcDir.Characteristics,
		TimeDateStamp:         srcDir.TimeDateStamp,
		MajorVersion:          srcDir.MajorVersion,
		MinorVersion:          srcDir.MinorVersion,
		Name:                  srcDir.Name + size,
		Base:                  srcDir.Base,
		NumberOfFunctions:     srcDir.NumberOfFunctions,
		NumberOfNames:         srcDir.NumberOfNames,
		AddressOfFunctions:    srcDir.AddressOfFunctions + size,
		AddressOfNames:        srcDir.AddressOfNames + size,
		AddressOfNameOrdinals: srcDir.AddressOfNameOrdinals + size,
	}
	writeStruct(dst, dstDir)
	// overwrite export function address
	for i := uint32(0); i < srcDir.NumberOfFunctions; i++ {
		off := inj.rvaToFOA(srcDir.AddressOfFunctions + i*4)
		srcD := inj.dup[off:]
		dstD := output[off+size:]
		funcRVA := binary.LittleEndian.Uint32(srcD)
		funcRVA += size
		binary.LittleEndian.PutUint32(dstD, funcRVA)
	}
	// overwrite export function name
	for i := uint32(0); i < srcDir.NumberOfNames; i++ {
		off := inj.rvaToFOA(srcDir.AddressOfNames + i*4)
		srcD := inj.dup[off:]
		dstD := output[off+size:]
		nameRVA := binary.LittleEndian.Uint32(srcD)
		nameRVA += size
		binary.LittleEndian.PutUint32(dstD, nameRVA)
	}
}

func (inj *Injector) adjustImportDescriptor(output []byte, size uint32) {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	foa := inj.rvaToFOA(dd.VirtualAddress)
	src := inj.dup[foa:]
	dst := output[foa+size:]
	for {
		srcDesc := &importDescriptor{}
		readStruct(src, srcDesc)
		if srcDesc.OriginalFirstThunk == 0 {
			break
		}
		dstDesc := &importDescriptor{
			OriginalFirstThunk: srcDesc.OriginalFirstThunk + size,
			TimeDateStamp:      srcDesc.TimeDateStamp,
			ForwarderChain:     srcDesc.ForwarderChain,
			Name:               srcDesc.Name + size,
			FirstThunk:         srcDesc.FirstThunk + size,
		}
		// rewrite import descriptor
		writeStruct(dst, dstDesc)
		// adjust thunk data
		off := inj.rvaToFOA(srcDesc.OriginalFirstThunk)
		srcD := inj.dup[off:]
		dstD := output[off+size:]
		for len(srcD) > 0 {
			var stop bool
			switch inj.arch {
			case "386":
				val := binary.LittleEndian.Uint32(srcD[0:4])
				srcD = srcD[4:]
				if val == 0 {
					stop = true
					break
				}
				if val&0x80000000 == 0 {
					val += size
					binary.LittleEndian.PutUint32(dstD, val)
				}
				dstD = dstD[4:]
			case "amd64":
				val := binary.LittleEndian.Uint64(srcD[0:8])
				srcD = srcD[8:]
				if val == 0 {
					stop = true
					break
				}
				if val&0x8000000000000000 == 0 {
					val += uint64(size)
					binary.LittleEndian.PutUint64(dstD, val)
				}
				dstD = dstD[8:]
			}
			if stop {
				break
			}
		}
		// update src and dst
		src = src[importDescriptorSize:]
		dst = dst[importDescriptorSize:]
	}
}

func (inj *Injector) adjustBaseRelocation(output []byte, size uint32) {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	foa := inj.rvaToFOA(dd.VirtualAddress)
	src := inj.dup[foa:]
	dst := output[foa+size:]
	for {
		srcReloc := &baseRelocation{}
		readStruct(src, srcReloc)
		if srcReloc.VirtualAddress == 0 {
			break
		}
		dstReloc := &baseRelocation{
			VirtualAddress: srcReloc.VirtualAddress + size,
			SizeOfBlock:    srcReloc.SizeOfBlock,
		}
		// rewrite base relocation
		writeStruct(dst, dstReloc)
		// adjust reloc entry
		for i := uint32(0); i < (srcReloc.SizeOfBlock-baseRelocationSize)/2; i++ {
			reloc := binary.LittleEndian.Uint16(src[baseRelocationSize+i*2:])
			typ := reloc >> 12
			off := reloc & 0x0FFF
			switch typ {
			case relBasedAbsolute:
			case relBasedHighlow:
				o := inj.rvaToFOA(srcReloc.VirtualAddress + uint32(off))
				addr := binary.LittleEndian.Uint32(inj.dup[o:])
				addr += size
				binary.LittleEndian.PutUint32(output[o+size:], addr)
			case relBasedDir64:
				o := inj.rvaToFOA(srcReloc.VirtualAddress + uint32(off))
				addr := binary.LittleEndian.Uint64(inj.dup[o:])
				addr += uint64(size)
				binary.LittleEndian.PutUint64(output[o+size:], addr)
			}
		}
		// update src and dst
		src = src[srcReloc.SizeOfBlock:]
		dst = dst[srcReloc.SizeOfBlock:]
	}
}
