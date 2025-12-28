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
	size = alignFileOffset(size)
	output := make([]byte, len(inj.dup)+int(size))
	// copy all data before the first section data
	copy(output, inj.dup[:inj.img.Sections[0].Offset])
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
	// adjust data directory

	// adjust the size of image in optional header
	buffer.Reset()
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.SizeOfCode += alignFileOffset(size)
		hdr.SizeOfImage += alignMemoryRegion(size)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
	case "amd64":
		hdr := *inj.hdr64
		hdr.SizeOfCode += alignFileOffset(size)
		hdr.SizeOfImage += alignMemoryRegion(size)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
	}
	copy(output[inj.offOptHdr:], buffer.Bytes())
	return output, nil
}
