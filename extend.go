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
	err := inj.checkAlignment()
	if err != nil {
		return nil, err
	}
	text := inj.img.Sections[0]
	// calculate actual extend file size and virtual address offset
	extSize := alignFileOffset(size)
	vaOffset := alignMemoryRegion(text.VirtualSize+extSize) - alignMemoryRegion(text.VirtualSize)
	// copy all data before the first section data
	output := make([]byte, len(inj.dup)+int(extSize))
	copy(output, inj.dup[:text.Offset])
	// preprocess NT Headers
	for _, step := range []func(output []byte, extSize, vaOffset uint32){
		inj.adjustOptionalHeader,
		inj.adjustSectionHeaders,
		inj.adjustDataDirectory,
		inj.adjustImportDescriptor,
		inj.adjustBaseRelocation,
	} {
		step(output, extSize, vaOffset)
	}
	return output, nil
}

func (inj *Injector) checkAlignment() error {
	var (
		sectionAlignment uint32
		fileAlignment    uint32
	)
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		sectionAlignment = hdr.SectionAlignment
		fileAlignment = hdr.FileAlignment
	case "amd64":
		hdr := *inj.hdr64
		sectionAlignment = hdr.SectionAlignment
		fileAlignment = hdr.FileAlignment
	}
	if sectionAlignment != 4096 {
		return errors.New("invalid section alignment")
	}
	if fileAlignment != 512 {
		return errors.New("invalid file alignment")
	}
	return nil
}

func (inj *Injector) adjustOptionalHeader(output []byte, extSize, vaOffset uint32) {
	var optHdr []byte
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.AddressOfEntryPoint += extSize
		hdr.SizeOfCode += extSize
		hdr.SizeOfImage += vaOffset
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// ignore data directory
		optHdr = buffer.Bytes()[:imageOptionHeaderSize32]
	case "amd64":
		hdr := *inj.hdr64
		hdr.AddressOfEntryPoint += extSize
		hdr.SizeOfCode += extSize
		hdr.SizeOfImage += vaOffset
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// ignore data directory
		optHdr = buffer.Bytes()[:imageOptionHeaderSize64]
	}
	copy(output[inj.offOptHdr:], optHdr)
}

func (inj *Injector) adjustSectionHeaders(output []byte, extSize, vaOffset uint32) {
	// adjust the text section header
	shOffset := inj.offOptHdr + uint32(inj.img.SizeOfOptionalHeader)
	text := new(pe.SectionHeader32)
	_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, text)
	// copy text section data
	textPtr := text.PointerToRawData
	copy(output[textPtr+extSize:], inj.dup[textPtr:textPtr+text.SizeOfRawData])
	// adjust section size
	text.VirtualSize += extSize
	text.SizeOfRawData += extSize
	// overwrite the text section
	buffer := bytes.NewBuffer(nil)
	_ = binary.Write(buffer, binary.LittleEndian, text)
	copy(output[shOffset:], buffer.Bytes())
	// adjust other sections
	for i := 1; i < len(inj.img.Sections); i++ {
		shOffset += imageSectionHeaderSize
		section := new(pe.SectionHeader32)
		_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, section)
		// copy section data
		ptr := section.PointerToRawData
		copy(output[ptr+extSize:], inj.dup[ptr:ptr+section.SizeOfRawData])
		// adjust section size
		section.VirtualAddress += vaOffset
		section.PointerToRawData += extSize
		// overwrite section header
		buffer.Reset()
		_ = binary.Write(buffer, binary.LittleEndian, section)
		copy(output[shOffset:], buffer.Bytes())
	}
}

func (inj *Injector) adjustDataDirectory(output []byte, _, vaOffset uint32) {
	for i := uint32(0); i < inj.numDataDir; i++ {
		dd := new(pe.DataDirectory)
		offset := inj.offDataDir + i*imageDataDirectorySize
		_ = binary.Read(bytes.NewReader(inj.dup[offset:]), binary.LittleEndian, dd)
		if dd.VirtualAddress == 0 {
			continue
		}
		dd.VirtualAddress += vaOffset
		// rewrite data directory
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, dd)
		copy(output[offset:], buffer.Bytes())
	}
}

func (inj *Injector) adjustEAT() {

}

func (inj *Injector) adjustImportDescriptor(output []byte, extSize, vaOffset uint32) {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	offset := inj.rvaToOffset(dd.VirtualAddress)
	srcTable := inj.dup[offset:]
	dstTable := output[offset+extSize:]
	for {
		srcDesc := &importDescriptor{}
		_ = binary.Read(bytes.NewReader(srcTable), binary.LittleEndian, srcDesc)
		if srcDesc.OriginalFirstThunk == 0 {
			break
		}
		dstDesc := &importDescriptor{
			OriginalFirstThunk: srcDesc.OriginalFirstThunk + vaOffset,
			TimeDateStamp:      srcDesc.TimeDateStamp,
			ForwarderChain:     srcDesc.ForwarderChain,
			Name:               srcDesc.Name + vaOffset,
			FirstThunk:         srcDesc.FirstThunk + vaOffset,
		}
		// rewrite import descriptor
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, dstDesc)
		copy(dstTable, buffer.Bytes())
		// adjust thunk data
		off := inj.rvaToOffset(srcDesc.OriginalFirstThunk)
		srcD := inj.dup[off:]
		dstD := output[off+extSize:]
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
					val += vaOffset
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
					val += uint64(vaOffset)
					binary.LittleEndian.PutUint64(dstD, val)
				}
				dstD = dstD[8:]
			}
			if stop {
				break
			}
		}
		// update src and dst table
		srcTable = srcTable[importDescriptorSize:]
		dstTable = dstTable[importDescriptorSize:]
	}
}

func (inj *Injector) adjustBaseRelocation(output []byte, extSize, vaOffset uint32) {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	offset := inj.rvaToOffset(dd.VirtualAddress)
	srcTable := inj.dup[offset:]
	dstTable := output[offset+extSize:]
	for {
		srcReloc := &baseRelocation{}
		_ = binary.Read(bytes.NewReader(srcTable), binary.LittleEndian, srcReloc)
		if srcReloc.VirtualAddress == 0 {
			break
		}

		text := inj.img.Sections[0]

		if srcReloc.VirtualAddress >= text.VirtualAddress && srcReloc.VirtualAddress < text.VirtualAddress+text.VirtualSize {

			dstReloc := &baseRelocation{
				VirtualAddress: srcReloc.VirtualAddress + extSize,
				SizeOfBlock:    srcReloc.SizeOfBlock,
			}
			// rewrite base relocation
			buffer := bytes.NewBuffer(nil)
			_ = binary.Write(buffer, binary.LittleEndian, dstReloc)
			copy(dstTable, buffer.Bytes())
			// adjust reloc entry
			for i := uint32(0); i < (srcReloc.SizeOfBlock-baseRelocationSize)/2; i++ {
				reloc := binary.LittleEndian.Uint16(srcTable[baseRelocationSize+i*2:])
				typ := reloc >> 12
				off := reloc & 0x0FFF
				switch typ {
				case relBasedAbsolute:
				case relBasedHighlow:
					o := inj.rvaToOffset(srcReloc.VirtualAddress + uint32(off))
					addr := binary.LittleEndian.Uint32(inj.dup[o:])
					addr += extSize
					binary.LittleEndian.PutUint32(output[o+extSize:], addr)
				case relBasedDir64:
					o := inj.rvaToOffset(srcReloc.VirtualAddress + uint32(off))
					addr := binary.LittleEndian.Uint64(inj.dup[o:])
					addr += uint64(extSize)
					binary.LittleEndian.PutUint64(output[o+extSize:], addr)
				}
			}

		} else {

			dstReloc := &baseRelocation{
				VirtualAddress: srcReloc.VirtualAddress + vaOffset,
				SizeOfBlock:    srcReloc.SizeOfBlock,
			}
			// rewrite base relocation
			buffer := bytes.NewBuffer(nil)
			_ = binary.Write(buffer, binary.LittleEndian, dstReloc)
			copy(dstTable, buffer.Bytes())
			// adjust reloc entry
			for i := uint32(0); i < (srcReloc.SizeOfBlock-baseRelocationSize)/2; i++ {
				reloc := binary.LittleEndian.Uint16(srcTable[baseRelocationSize+i*2:])
				typ := reloc >> 12
				off := reloc & 0x0FFF
				switch typ {
				case relBasedAbsolute:
				case relBasedHighlow:
					o := inj.rvaToOffset(srcReloc.VirtualAddress + uint32(off))
					addr := binary.LittleEndian.Uint32(inj.dup[o:])
					addr += vaOffset
					binary.LittleEndian.PutUint32(output[o+vaOffset:], addr)
				case relBasedDir64:
					o := inj.rvaToOffset(srcReloc.VirtualAddress + uint32(off))
					addr := binary.LittleEndian.Uint64(inj.dup[o:])
					addr += uint64(vaOffset)
					binary.LittleEndian.PutUint64(output[o+vaOffset:], addr)
				}
			}
		}

		// update src and dst table
		srcTable = srcTable[srcReloc.SizeOfBlock:]
		dstTable = dstTable[srcReloc.SizeOfBlock:]
	}
}
