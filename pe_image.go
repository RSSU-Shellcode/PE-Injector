package injector

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
)

const (
	imageDOSHeader         = 64
	imageFileHeaderSize    = 20
	imageSectionHeaderSize = 40
	importDirectorySize    = 5 * 4
	reserveSectionSize     = 8
)

type iat struct {
	dll  string
	proc string
	addr uint64
}

func (inj *Injector) loadImage(image []byte) {
	var size uint32
	switch inj.arch {
	case "386":
		size = inj.hdr32.SizeOfImage
	case "amd64":
		size = inj.hdr64.SizeOfImage
	}
	vm := make([]byte, size)
	for _, section := range inj.img.Sections {
		dst := vm[section.VirtualAddress:]
		src := image[section.Offset : section.Offset+section.Size]
		copy(dst, src)
	}
	inj.vm = vm
	inj.processIAT()
}

func (inj *Injector) processIAT() {
	var dataDirectory [16]pe.DataDirectory
	switch inj.arch {
	case "386":
		dataDirectory = inj.hdr32.DataDirectory
	case "amd64":
		dataDirectory = inj.hdr64.DataDirectory
	}
	dd := dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	table := inj.vm[dd.VirtualAddress:]
	var list []*iat
	for len(table) >= importDirectorySize {
		originalFirstThunk := binary.LittleEndian.Uint32(table[0:4])
		name := binary.LittleEndian.Uint32(table[12:16])
		firstThunk := binary.LittleEndian.Uint32(table[16:20])
		if originalFirstThunk == 0 {
			break
		}
		dll := extractString(inj.vm, uint64(name))
		d := inj.vm[originalFirstThunk:]
		for len(d) > 0 {
			var (
				proc string
				addr uint64
			)
			switch inj.arch {
			case "386":
				va := binary.LittleEndian.Uint32(d[0:4])
				d = d[4:]
				if va == 0 {
					break
				}
				if va&0x80000000 == 0 {
					proc = extractString(inj.vm, uint64(va+2))
					addr = uint64(firstThunk)
				}
				firstThunk += 4
			case "amd64":
				va := binary.LittleEndian.Uint64(d[0:8])
				d = d[8:]
				if va == 0 {
					break
				}
				if va&0x8000000000000000 == 0 {
					proc = extractString(inj.vm, va+2)
					addr = uint64(firstThunk)
				}
				firstThunk += 8
			}
			if proc == "" {
				break
			}
			list = append(list, &iat{
				dll:  dll,
				proc: proc,
				addr: addr,
			})
		}
		table = table[20:]
	}
	inj.iat = list
}

// extendSection is used to extend the last section for write data.
// It will return the RVA about the start of written data.
func (inj *Injector) extendSection(data []byte) uint32 {
	// calculate the offset of target data
	peOffset := binary.LittleEndian.Uint32(inj.dup[imageDOSHeader-4:])
	hdrOffset := peOffset + 4 + imageFileHeaderSize
	sctOffset := hdrOffset + uint32(inj.img.SizeOfOptionalHeader)
	shOffset := sctOffset + uint32((inj.img.NumberOfSections-1)*imageSectionHeaderSize)
	// adjust the last section header
	last := new(pe.SectionHeader32)
	_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, last)
	oldVirtualSize := last.VirtualSize
	size := uint32(reserveSectionSize + len(data))
	last.VirtualSize += size
	// make sure the SizeOfRawData > VirtualSize
	newSize := (last.VirtualSize/0x200 + 1) * 0x200
	padSize := int64(newSize) - int64(last.SizeOfRawData)
	if padSize > 0 {
		last.SizeOfRawData = newSize
		pad := make([]byte, padSize)
		inj.dup = append(inj.dup, pad...)
	} else {
		padSize = 0
	}
	_ = binary.Write(bytes.NewBuffer(inj.dup[shOffset:]), binary.LittleEndian, last)
	// adjust the size of image in optional header
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.SizeOfImage += uint32(padSize)
		_ = binary.Write(bytes.NewBuffer(inj.dup[hdrOffset:]), binary.LittleEndian, &hdr)
	case "amd64":
		hdr := *inj.hdr64
		hdr.SizeOfImage += uint32(padSize)
		_ = binary.Write(bytes.NewBuffer(inj.dup[hdrOffset:]), binary.LittleEndian, &hdr)
	}
	// copy data to the extended section
	dst := last.PointerToRawData + oldVirtualSize + reserveSectionSize
	copy(inj.dup[dst:], data)
	return last.VirtualAddress + oldVirtualSize + reserveSectionSize
}

// #nosec G115
func (inj *Injector) vaToRVA(va uint64) uint32 {
	var base int64
	switch inj.arch {
	case "386":
		base = int64(inj.hdr32.ImageBase)
	case "amd64":
		base = int64(inj.hdr64.ImageBase)
	}
	return uint32(int64(va) - base)
}

func (inj *Injector) rvaToOffset(section string, rva uint32) uint32 {
	s := inj.img.Section(section)
	return s.Offset + (rva - s.VirtualAddress)
}

func extractString(section []byte, start uint64) string {
	l := uint64(len(section))
	if start >= l {
		return ""
	}
	for end := start; end < l; end++ {
		if section[end] == 0 {
			return string(section[start:end])
		}
	}
	return ""
}
