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
	size = alignFileOffset(size)
	output := make([]byte, len(inj.dup)+int(size))
	// copy all data before the first section data
	copy(output, inj.dup[:inj.img.Sections[0].Offset])
	// preprocess NT Headers
	for _, step := range []func(output []byte, size uint32){
		inj.adjustOptionalHeader,
		inj.adjustSectionHeaders,
		inj.adjustDataDirectory,
		inj.adjustImportDescriptor,
		inj.adjustBaseRelocation,
	} {
		step(output, size)
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

func (inj *Injector) adjustOptionalHeader(output []byte, size uint32) {
	var optHdr []byte
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.AddressOfEntryPoint += size
		hdr.SizeOfCode += size
		hdr.SizeOfImage += alignMemoryRegion(size)
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// ignore data directory
		optHdr = buffer.Bytes()[:imageOptionHeaderSize32]
	case "amd64":
		hdr := *inj.hdr64
		hdr.AddressOfEntryPoint += size
		hdr.SizeOfCode += size
		hdr.SizeOfImage += alignMemoryRegion(size)
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// ignore data directory
		optHdr = buffer.Bytes()[:imageOptionHeaderSize64]
	}
	copy(output[inj.offOptHdr:], optHdr)
}

func (inj *Injector) adjustSectionHeaders(output []byte, size uint32) {
	// adjust the text section header
	shOffset := inj.offOptHdr + uint32(inj.img.SizeOfOptionalHeader)
	text := new(pe.SectionHeader32)
	_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, text)
	text.VirtualSize += size
	text.SizeOfRawData += size
	// overwrite the text section
	buffer := bytes.NewBuffer(nil)
	_ = binary.Write(buffer, binary.LittleEndian, text)
	copy(output[shOffset:], buffer.Bytes())
	// copy text section data
	textPtr := text.PointerToRawData
	copy(output[textPtr+size:], inj.dup[textPtr:])
	// adjust other section headers
	prev := text
	for i := 1; i < len(inj.img.Sections); i++ {
		shOffset += imageSectionHeaderSize
		section := new(pe.SectionHeader32)
		_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, section)
		section.VirtualAddress = prev.VirtualAddress + alignMemoryRegion(prev.VirtualSize)
		section.PointerToRawData += size
		// rewrite section header
		buffer.Reset()
		_ = binary.Write(buffer, binary.LittleEndian, section)
		copy(output[shOffset:], buffer.Bytes())
		// copy section data
		setPtr := section.PointerToRawData
		copy(output[setPtr:], inj.dup[setPtr-size:])
		// update previous section
		prev = section
	}
}

func (inj *Injector) adjustDataDirectory(output []byte, size uint32) {
	for i := uint32(0); i < inj.numDataDir; i++ {
		dd := new(pe.DataDirectory)
		offset := inj.offDataDir + i*imageDataDirectorySize
		_ = binary.Read(bytes.NewReader(inj.dup[offset:]), binary.LittleEndian, dd)
		if dd.VirtualAddress == 0 {
			continue
		}
		dd.VirtualAddress += alignMemoryRegion(size)
		// rewrite data directory
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, dd)
		copy(output[offset:], buffer.Bytes())
	}
}

func (inj *Injector) adjustEAT() {

}

func (inj *Injector) adjustImportDescriptor(output []byte, size uint32) {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	offset := inj.rvaToOffset(dd.VirtualAddress)
	srcTable := inj.dup[offset:]
	dstTable := output[offset+size:]
	for {
		srcDesc := &importDescriptor{}
		_ = binary.Read(bytes.NewReader(srcTable), binary.LittleEndian, srcDesc)
		if srcDesc.OriginalFirstThunk == 0 {
			break
		}
		dstDesc := &importDescriptor{
			OriginalFirstThunk: srcDesc.OriginalFirstThunk + alignMemoryRegion(size),
			TimeDateStamp:      srcDesc.TimeDateStamp,
			ForwarderChain:     srcDesc.ForwarderChain,
			Name:               srcDesc.Name + size,
			FirstThunk:         srcDesc.FirstThunk + alignMemoryRegion(size),
		}
		// rewrite import descriptor
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, dstDesc)
		copy(dstTable, buffer.Bytes())
		// adjust thunk data
		off := inj.rvaToOffset(srcDesc.OriginalFirstThunk)
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
					val += alignMemoryRegion(size)
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
					val += uint64(alignMemoryRegion(size))
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

func (inj *Injector) adjustBaseRelocation(output []byte, size uint32) {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	offset := inj.rvaToOffset(dd.VirtualAddress)
	srcTable := inj.dup[offset:]
	dstTable := output[offset+size:]
	for {
		srcReloc := &baseRelocation{}
		_ = binary.Read(bytes.NewReader(srcTable), binary.LittleEndian, srcReloc)
		if srcReloc.VirtualAddress == 0 {
			break
		}
		dstReloc := &baseRelocation{
			VirtualAddress: srcReloc.VirtualAddress + alignMemoryRegion(size),
			SizeOfBlock:    srcReloc.SizeOfBlock,
		}
		// rewrite import descriptor
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, dstReloc)
		copy(dstTable, buffer.Bytes())

		// update src and dst table
		srcTable = srcTable[baseRelocationSize:]
		dstTable = dstTable[baseRelocationSize:]
	}
}
