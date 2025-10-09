package injector

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	imageDOSHeader          = 64
	imageFileHeaderSize     = 20
	imageSectionHeaderSize  = 40
	imageOptionHeaderSize32 = 96
	imageOptionHeaderSize64 = 112
	imageDataDirectorySize  = 4 + 4
	importDirectorySize     = 5 * 4
	exportDirectorySize     = 40
	reserveSectionSize      = 8
)

var defaultSectionNames = []string{
	".patch", ".code", ".test", ".init",
	".dbg", ".debug", ".PAGE", ".CRT",
}

// Section contains the basic info of section.
type Section struct {
	Name            string `toml:"name"               json:"name"`
	VirtualAddress  uint32 `toml:"virtual_address"    json:"virtual_address"`
	VirtualSize     uint32 `toml:"virtual_size"       json:"virtual_size"`
	OffsetToRawData uint32 `toml:"offset_to_raw_data" json:"offset_to_raw_data"`
	SizeOfRawData   uint32 `toml:"size_of_raw_data"   json:"size_of_raw_data"`
}

// Export contains export function address.
type Export struct {
	Name    string `toml:"name"    json:"name"`
	Address uint64 `toml:"address" json:"address"`
}

type eat struct {
	proc string
	addr uint32
}

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
	inj.processEAT()
	inj.processIAT()
}

func (inj *Injector) processEAT() {
	var dataDirectory [16]pe.DataDirectory
	switch inj.arch {
	case "386":
		dataDirectory = inj.hdr32.DataDirectory
	case "amd64":
		dataDirectory = inj.hdr64.DataDirectory
	}
	dd := dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	if int(dd.VirtualAddress)+exportDirectorySize > len(inj.vm) {
		return
	}
	ed := inj.vm[dd.VirtualAddress:]
	numberOfNames := binary.LittleEndian.Uint32(ed[24:28])
	addressOfFunctions := binary.LittleEndian.Uint32(ed[28:32])
	addressOfNames := binary.LittleEndian.Uint32(ed[32:36])
	addressOfNameOrdinals := binary.LittleEndian.Uint32(ed[36:40])
	var list []*eat
	for i := uint32(0); i < numberOfNames; i++ {
		nameRVAOffset := int(addressOfNames + i*4)
		if nameRVAOffset+4 > len(inj.vm) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(inj.vm[nameRVAOffset : nameRVAOffset+4])
		if nameRVA == 0 {
			continue
		}
		funcName := extractString(inj.vm, uint64(nameRVA))
		ordinalOffset := int(addressOfNameOrdinals + i*2)
		if ordinalOffset+2 > len(inj.vm) {
			break
		}
		ordinal := binary.LittleEndian.Uint16(inj.vm[ordinalOffset : ordinalOffset+2])
		funcAddrOffset := int(addressOfFunctions) + int(ordinal)*4
		if funcAddrOffset+4 > len(inj.vm) {
			break
		}
		funcRVA := binary.LittleEndian.Uint32(inj.vm[funcAddrOffset : funcAddrOffset+4])
		if funcRVA >= dd.VirtualAddress && funcRVA <= dd.VirtualAddress+dd.Size {
			continue
		}
		list = append(list, &eat{
			proc: funcName,
			addr: funcRVA,
		})
	}
	inj.eat = list
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
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
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

func (inj *Injector) removeSignature() {
	var dataDirectory *[16]pe.DataDirectory
	switch inj.arch {
	case "386":
		dataDirectory = &inj.hdr32.DataDirectory
	case "amd64":
		dataDirectory = &inj.hdr64.DataDirectory
	}
	dd := &dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	// erase the signature at tail of image
	inj.dup = inj.dup[:dd.VirtualAddress]
	// calculate the offset of the security entry
	peOffset := binary.LittleEndian.Uint32(inj.dup[imageDOSHeader-4:])
	fhOffset := peOffset + 4
	hdrOffset := fhOffset + imageFileHeaderSize
	var optHeaderSize uint32
	switch inj.arch {
	case "386":
		optHeaderSize = imageOptionHeaderSize32
	case "amd64":
		optHeaderSize = imageOptionHeaderSize64
	}
	ddOffset := hdrOffset + optHeaderSize
	secOffset := ddOffset + pe.IMAGE_DIRECTORY_ENTRY_SECURITY*imageDataDirectorySize
	// erase the directory entry
	ndd := bytes.Repeat([]byte{0x00}, imageDataDirectorySize)
	copy(inj.dup[secOffset:], ndd)
	// extendSection or createSection will read optional header
	// so need overwrite these fields in data directory
	dd.VirtualAddress = 0
	dd.Size = 0
	// store state for analyze
	inj.containSign = true
}

func (inj *Injector) removeLoadConfig() {
	if inj.opts.ReserveCFG {
		return
	}
	var dataDirectory *[16]pe.DataDirectory
	switch inj.arch {
	case "386":
		dataDirectory = &inj.hdr32.DataDirectory
	case "amd64":
		dataDirectory = &inj.hdr64.DataDirectory
	}
	dd := &dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	// erase the CFG table data
	tableOffset := inj.rvaToOffset(dd.VirtualAddress)
	etb := bytes.Repeat([]byte{0x00}, int(dd.Size))
	copy(inj.dup[tableOffset:], etb)
	// calculate the offset of the load config entry
	peOffset := binary.LittleEndian.Uint32(inj.dup[imageDOSHeader-4:])
	fhOffset := peOffset + 4
	hdrOffset := fhOffset + imageFileHeaderSize
	var optHeaderSize uint32
	switch inj.arch {
	case "386":
		optHeaderSize = imageOptionHeaderSize32
	case "amd64":
		optHeaderSize = imageOptionHeaderSize64
	}
	ddOffset := hdrOffset + optHeaderSize
	cfgOffset := ddOffset + pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG*imageDataDirectorySize
	// erase the directory entry
	ndd := bytes.Repeat([]byte{0x00}, imageDataDirectorySize)
	copy(inj.dup[cfgOffset:], ndd)
	// extendSection or createSection will read optional header
	// so need overwrite these fields in data directory
	dd.VirtualAddress = 0
	dd.Size = 0
	// store state for analyze
	inj.containCFG = true
}

func (inj *Injector) overwriteChecksum() {
	var checksum uint32
	switch inj.arch {
	case "386":
		checksum = inj.hdr32.CheckSum
	case "amd64":
		checksum = inj.hdr32.CheckSum
	}
	if checksum == 0 {
		return
	}
	checksum = calculateChecksum(inj.dup)
	// calculate the offset of the checksum field
	peOffset := binary.LittleEndian.Uint32(inj.dup[imageDOSHeader-4:])
	fhOffset := peOffset + 4
	hdrOffset := fhOffset + imageFileHeaderSize
	sumOffset := int(hdrOffset + 64)
	// overwrite checksum
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, checksum)
	copy(inj.dup[sumOffset:], buf)
}

func calculateChecksum(image []byte) uint32 {
	// calculate the offset of the checksum field
	peOffset := binary.LittleEndian.Uint32(image[imageDOSHeader-4:])
	fhOffset := peOffset + 4
	hdrOffset := fhOffset + imageFileHeaderSize
	sumOffset := int(hdrOffset + 64)
	// calculate pe image checksum
	var sum uint64
	for i := 0; i < len(image); i += 2 {
		if i >= sumOffset && i < sumOffset+4 {
			continue
		}
		var word uint16
		if i+1 < len(image) {
			word = binary.LittleEndian.Uint16(image[i:])
		} else {
			word = uint16(image[i])
		}
		sum += uint64(word)
		if sum > 0xFFFFFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
	}
	sum = (sum & 0xFFFF) + (sum >> 16)
	sum += sum >> 16
	sum &= 0xFFFF
	sum += uint64(len(image))
	return uint32(sum & 0xFFFFFFFF) // #nosec G115
}

// extendSection is used to extend the last section for write data.
// It will return the RVA about the start of written data.
// #nosec G115
func (inj *Injector) extendSection(data []byte) uint32 {
	// calculate the offset of target data
	peOffset := binary.LittleEndian.Uint32(inj.dup[imageDOSHeader-4:])
	fhOffset := peOffset + 4
	hdrOffset := fhOffset + imageFileHeaderSize
	sctOffset := hdrOffset + uint32(inj.img.SizeOfOptionalHeader)
	shOffset := sctOffset + uint32((inj.img.NumberOfSections-1)*imageSectionHeaderSize)
	// adjust the last section header
	last := new(pe.SectionHeader32)
	_ = binary.Read(bytes.NewReader(inj.dup[shOffset:]), binary.LittleEndian, last)
	oldVirtualSize := last.VirtualSize
	size := uint32(reserveSectionSize + len(data))
	last.VirtualSize += size
	// make sure the SizeOfRawData > VirtualSize
	newSize := alignFileOffset(last.VirtualSize)
	padSize := int64(newSize) - int64(last.SizeOfRawData)
	if padSize > 0 {
		last.SizeOfRawData = newSize
		pad := make([]byte, padSize)
		inj.dup = append(inj.dup, pad...)
	} else {
		padSize = 0
	}
	// overwrite the last section
	buffer := bytes.NewBuffer(nil)
	_ = binary.Write(buffer, binary.LittleEndian, last)
	copy(inj.dup[shOffset:], buffer.Bytes())
	// adjust the size of image in optional header
	buffer.Reset()
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.SizeOfImage += uint32(padSize)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
	case "amd64":
		hdr := *inj.hdr64
		hdr.SizeOfImage += uint32(padSize)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
	}
	copy(inj.dup[hdrOffset:], buffer.Bytes())
	// copy data to the extended section
	dst := last.PointerToRawData + oldVirtualSize + reserveSectionSize
	copy(inj.dup[dst:], data)
	return last.VirtualAddress + oldVirtualSize + reserveSectionSize
}

// createSection is used to create a new section after the last section.
// #nosec G115
func (inj *Injector) createSection(name string, size uint32) (*pe.SectionHeader, error) {
	if len(inj.img.Sections) == 0 {
		return nil, errors.New("no sections in pe image")
	}
	if name == "" {
		idx := inj.rand.Intn(len(defaultSectionNames))
		name = defaultSectionNames[idx]
	}
	fSection := inj.img.Sections[0]
	fhOffset := fSection.Offset
	// calculate the offset about the end of last section header
	peOffset := binary.LittleEndian.Uint32(inj.dup[imageDOSHeader-4:])
	fHdrOffset := peOffset + 4
	hdrOffset := fHdrOffset + imageFileHeaderSize
	sctOffset := hdrOffset + uint32(inj.img.SizeOfOptionalHeader)
	shOffset := sctOffset + uint32((inj.img.NumberOfSections)*imageSectionHeaderSize)
	if fhOffset-shOffset < imageSectionHeaderSize {
		return nil, errors.New("not enough space for add a new section header")
	}
	// write a new section header
	if len(name) > 8 {
		return nil, errors.New("section name size can not be longer than 8 bytes")
	}
	var nameArr [8]byte
	copy(nameArr[:], name)
	lastOffset := shOffset - imageSectionHeaderSize
	last := new(pe.SectionHeader32)
	_ = binary.Read(bytes.NewReader(inj.dup[lastOffset:]), binary.LittleEndian, last)
	sh := &pe.SectionHeader32{
		Name:             nameArr,
		VirtualSize:      size,
		VirtualAddress:   last.VirtualAddress + alignMemoryRegion(last.VirtualSize),
		SizeOfRawData:    alignFileOffset(size),
		PointerToRawData: last.PointerToRawData + last.SizeOfRawData,
		Characteristics:  0x60000020, // RX
	}
	buffer := bytes.NewBuffer(nil)
	_ = binary.Write(buffer, binary.LittleEndian, sh)
	copy(inj.dup[shOffset:], buffer.Bytes())
	// append data to the tail
	newSection := bytes.Repeat([]byte{0}, int(sh.SizeOfRawData))
	inj.dup = append(inj.dup, newSection...)
	// adjust the file header
	fileHeader := inj.img.FileHeader
	fileHeader.NumberOfSections++
	buffer.Reset()
	_ = binary.Write(buffer, binary.LittleEndian, &fileHeader)
	copy(inj.dup[fHdrOffset:], buffer.Bytes())
	// adjust the size of image in optional header
	buffer.Reset()
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.SizeOfImage += uint32(len(newSection))
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
	case "amd64":
		hdr := *inj.hdr64
		hdr.SizeOfImage += uint32(len(newSection))
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
	}
	copy(inj.dup[hdrOffset:], buffer.Bytes())
	// update context
	inj.ctx.SectionName = name
	return &pe.SectionHeader{
		Name:            name,
		VirtualSize:     sh.VirtualSize,
		VirtualAddress:  sh.VirtualAddress,
		Size:            sh.SizeOfRawData,
		Offset:          sh.PointerToRawData,
		Characteristics: sh.Characteristics,
	}, nil
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

// #nosec G115
func (inj *Injector) rvaToVA(rva uint32) uint64 {
	var base int64
	switch inj.arch {
	case "386":
		base = int64(inj.hdr32.ImageBase)
	case "amd64":
		base = int64(inj.hdr64.ImageBase)
	}
	return uint64(base + int64(rva))
}

func (inj *Injector) offsetToRVA(offset uint32) uint32 {
	for _, section := range inj.img.Sections {
		off := section.Offset
		size := section.Size
		if offset >= off && offset <= off+size {
			return section.VirtualAddress + (offset - section.Offset)
		}
	}
	panic(fmt.Sprintf("invalid offset: 0x%X", offset))
}

func (inj *Injector) rvaToOffset(rva uint32) uint32 {
	for _, section := range inj.img.Sections {
		va := section.VirtualAddress
		size := section.Size
		if rva >= va && rva <= va+size {
			return section.Offset + (rva - va)
		}
	}
	panic(fmt.Sprintf("invalid rva: 0x%X", rva))
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

func alignFileOffset(size uint32) uint32 {
	return (size/0x200 + 1) * 0x200
}

func alignMemoryRegion(size uint32) uint32 {
	return (size/0x1000 + 1) * 0x1000
}
