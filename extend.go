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
	output := make([]byte, len(inj.dup)+int(size))
	// copy DOS stub and FileHeader

	// adjust the text section header
	shOffset := inj.offOptHdr + uint32(inj.img.SizeOfOptionalHeader)
	text := new(pe.SectionHeader32)
	_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, text)
	text.VirtualSize += alignMemoryRegion(size)
	text.SizeOfRawData += alignFileOffset(size)
	// overwrite the text section
	buffer := bytes.NewBuffer(nil)
	_ = binary.Write(buffer, binary.LittleEndian, text)
	copy(inj.dup[shOffset:], buffer.Bytes())
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
	copy(inj.dup[inj.offOptHdr:], buffer.Bytes())

	return output, nil
}
