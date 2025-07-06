package injector

import (
	"debug/pe"
	"encoding/binary"
)

const importDirectorySize = 5 * 4

type iat struct {
	dll  string
	proc string
	addr uint64
}

func (inj *Injector) loadImage(image []byte) {
	var size uint32
	switch inj.arch {
	case "386":
		size = inj.img.OptionalHeader.(*pe.OptionalHeader32).SizeOfImage
	case "amd64":
		size = inj.img.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage
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
		dataDirectory = inj.img.OptionalHeader.(*pe.OptionalHeader32).DataDirectory
	case "amd64":
		dataDirectory = inj.img.OptionalHeader.(*pe.OptionalHeader64).DataDirectory
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
