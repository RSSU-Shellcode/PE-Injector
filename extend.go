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
	// copy all data before the first section data
	size = alignMemoryRegion(size)
	text := inj.img.Sections[0]
	output := make([]byte, len(inj.dup)+int(size))
	copy(output, inj.dup[:text.Offset])
	// extend the first section
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

func (inj *Injector) checkImageAlignment() error {
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

func (inj *Injector) adjustSectionHeaders(output []byte, size uint32) {
	// adjust the text section header
	shOffset := inj.offOptHdr + uint32(inj.img.SizeOfOptionalHeader)
	text := new(pe.SectionHeader32)
	_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, text)
	// copy text section data
	textPtr := text.PointerToRawData
	copy(output[textPtr+size:], inj.dup[textPtr:textPtr+text.SizeOfRawData])
	// adjust section size
	text.VirtualSize += size
	text.SizeOfRawData += size
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
		copy(output[ptr+size:], inj.dup[ptr:ptr+section.SizeOfRawData])
		// adjust section size
		section.VirtualAddress += size
		section.PointerToRawData += size
		// overwrite section header
		buffer.Reset()
		_ = binary.Write(buffer, binary.LittleEndian, section)
		copy(output[shOffset:], buffer.Bytes())
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
		dd.VirtualAddress += size
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
	foa := inj.rvaToFOA(dd.VirtualAddress)
	src := inj.dup[foa:]
	dst := output[foa+size:]
	for {
		srcDesc := &importDescriptor{}
		_ = binary.Read(bytes.NewReader(src), binary.LittleEndian, srcDesc)
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
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, dstDesc)
		copy(dst, buffer.Bytes())
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
		_ = binary.Read(bytes.NewReader(src), binary.LittleEndian, srcReloc)
		if srcReloc.VirtualAddress == 0 {
			break
		}
		dstReloc := &baseRelocation{
			VirtualAddress: srcReloc.VirtualAddress + size,
			SizeOfBlock:    srcReloc.SizeOfBlock,
		}
		// rewrite base relocation
		buffer := bytes.NewBuffer(nil)
		_ = binary.Write(buffer, binary.LittleEndian, dstReloc)
		copy(dst, buffer.Bytes())
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
