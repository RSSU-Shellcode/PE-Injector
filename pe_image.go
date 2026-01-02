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
	imageNTSignatureSize    = 4
	imageFileHeaderSize     = 20
	imageOptionHeaderSize32 = 96
	imageOptionHeaderSize64 = 112
	imageDataDirectorySize  = 4 + 4
	imageSectionHeaderSize  = 40

	importDescriptorSize = 5 * 4
	baseRelocationSize   = 2 * 4

	relBasedAbsolute = 0
	relBasedHighlow  = 3
	relBasedDir64    = 10

	reserveSectionSize = 16
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
	rva  uint32
}

type iat struct {
	dll  string
	proc string
	rva  uint32
}

type exportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type importDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type baseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

func (inj *Injector) loadImage() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	inj.processEAT()
	inj.processIAT()
	return nil
}

func (inj *Injector) processEAT() {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	directory := &exportDirectory{}
	readStruct(inj.getFileDataByRVA(dd.VirtualAddress), directory)
	var list []*eat
	for i := uint32(0); i < directory.NumberOfNames; i++ {
		nameRVAOffset := directory.AddressOfNames + i*4
		nameRVA := binary.LittleEndian.Uint32(inj.getFileDataByRVA(nameRVAOffset))
		if nameRVA == 0 {
			continue
		}
		funcName := inj.extractString(nameRVA)
		ordinalOffset := directory.AddressOfNameOrdinals + i*2
		ordinal := binary.LittleEndian.Uint16(inj.getFileDataByRVA(ordinalOffset))
		funcAddrOffset := directory.AddressOfFunctions + uint32(ordinal*4)
		funcRVA := binary.LittleEndian.Uint32(inj.getFileDataByRVA(funcAddrOffset))
		if funcRVA >= dd.VirtualAddress && funcRVA <= dd.VirtualAddress+dd.Size {
			continue
		}
		list = append(list, &eat{
			proc: funcName,
			rva:  funcRVA,
		})
	}
	inj.eat = list
}

func (inj *Injector) processIAT() {
	dd := inj.dataDir[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	if dd.VirtualAddress == 0 || dd.Size == 0 {
		return
	}
	descriptors := inj.getFileDataByRVA(dd.VirtualAddress)
	var list []*iat
	for len(descriptors) >= importDescriptorSize {
		desc := &importDescriptor{}
		readStruct(descriptors, desc)
		if desc.OriginalFirstThunk == 0 {
			break
		}
		dll := inj.extractString(desc.Name)
		d := inj.getFileDataByRVA(desc.OriginalFirstThunk)
		for len(d) > 0 {
			var (
				proc string
				rva  uint32
				stop bool
			)
			switch inj.arch {
			case "386":
				val := binary.LittleEndian.Uint32(d[0:4])
				d = d[4:]
				if val == 0 {
					stop = true
					break
				}
				if val&0x80000000 == 0 {
					proc = inj.extractString(val + 2)
					rva = desc.FirstThunk
				}
				desc.FirstThunk += 4
			case "amd64":
				val := binary.LittleEndian.Uint64(d[0:8])
				d = d[8:]
				if val == 0 {
					stop = true
					break
				}
				if val&0x8000000000000000 == 0 {
					proc = inj.extractString(uint32(val + 2)) // #nosec G115
					rva = desc.FirstThunk
				}
				desc.FirstThunk += 8
			}
			if stop {
				break
			}
			list = append(list, &iat{
				dll:  dll,
				proc: proc,
				rva:  rva,
			})
		}
		descriptors = descriptors[importDescriptorSize:]
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
	secOffset := inj.offDataDir + pe.IMAGE_DIRECTORY_ENTRY_SECURITY*imageDataDirectorySize
	// erase the data directory entry
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
	tableFOA := inj.rvaToFOA(dd.VirtualAddress)
	etb := bytes.Repeat([]byte{0x00}, int(dd.Size))
	copy(inj.dup[tableFOA:], etb)
	// calculate the offset of the load config entry
	cfgOffset := inj.offDataDir + pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG*imageDataDirectorySize
	// erase the data directory entry
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
	sumOffset := int(inj.offOptHdr + 64)
	// overwrite checksum
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, checksum)
	copy(inj.dup[sumOffset:], buf)
}

func calculateChecksum(image []byte) uint32 {
	// calculate the offset of the checksum field
	hdrOffset := binary.LittleEndian.Uint32(image[imageDOSHeader-4:])
	fileHeader := hdrOffset + imageNTSignatureSize
	optHeader := fileHeader + imageFileHeaderSize
	sumOffset := int(optHeader + 64)
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
func (inj *Injector) extendSection(data []byte) (uint32, error) {
	// calculate the offset of target data
	sctOffset := inj.offOptHdr + uint32(inj.img.SizeOfOptionalHeader)
	shOffset := sctOffset + uint32((inj.img.NumberOfSections-1)*imageSectionHeaderSize)
	// adjust the last section header
	last := new(pe.SectionHeader32)
	readStruct(inj.dup[shOffset:], last)
	// the section must be read only
	if last.Characteristics&0xF0000000 != 0x40000000 {
		return 0, fmt.Errorf("the last section is not read only")
	}
	// store old section header data
	oldVirtualSize := last.VirtualSize
	oldSizeOfRawData := last.SizeOfRawData
	// adjust VirtualSize and SizeOfRawData
	setSize := uint32(reserveSectionSize + len(data))
	newSize := inj.alignFile(min(last.VirtualSize, last.SizeOfRawData) + setSize)
	last.VirtualSize += setSize
	last.SizeOfRawData = newSize
	// add padding data if last section need extend raw data
	padSize := int64(newSize) - int64(oldSizeOfRawData)
	if padSize > 0 {
		pad := make([]byte, padSize)
		inj.dup = append(inj.dup, pad...)
	} else {
		padSize = 0
	}
	// overwrite the last section
	writeStruct(inj.dup[shOffset:], last)
	// adjust the size of image in optional header
	buffer := bytes.NewBuffer(nil)
	var optHdr []byte
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.SizeOfImage += uint32(padSize)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// process data directory
		optHdr = buffer.Bytes()
		sz := int(inj.numDataDir * imageDataDirectorySize)
		optHdr = optHdr[:imageOptionHeaderSize32+sz]
	case "amd64":
		hdr := *inj.hdr64
		hdr.SizeOfImage += uint32(padSize)
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// process data directory
		optHdr = buffer.Bytes()
		sz := int(inj.numDataDir * imageDataDirectorySize)
		optHdr = optHdr[:imageOptionHeaderSize64+sz]
	}
	copy(inj.dup[inj.offOptHdr:], optHdr)
	// copy data to the extended section
	ptrOff := min(oldVirtualSize, oldSizeOfRawData)
	dst := last.PointerToRawData + ptrOff + reserveSectionSize
	copy(inj.dup[dst:], data)
	rva := last.VirtualAddress + oldVirtualSize + reserveSectionSize
	// update context
	inj.ctx.SectionName = inj.img.Sections[len(inj.img.Sections)-1].Name
	return rva, nil
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
	sctOffset := inj.offOptHdr + uint32(inj.img.SizeOfOptionalHeader)
	shOffset := sctOffset + uint32((inj.img.NumberOfSections)*imageSectionHeaderSize)
	if fhOffset-shOffset < imageSectionHeaderSize {
		return nil, errors.New("not enough space for add a new section header")
	}
	// write a new section header
	if len(name) > 8 {
		return nil, errors.New("section name size can not be longer than 8 bytes")
	}
	lastOffset := shOffset - imageSectionHeaderSize
	last := new(pe.SectionHeader32)
	readStruct(inj.dup[lastOffset:], last)
	sh := &pe.SectionHeader32{
		VirtualSize:      size,
		VirtualAddress:   last.VirtualAddress + inj.alignSection(last.VirtualSize),
		SizeOfRawData:    inj.alignFile(size),
		PointerToRawData: last.PointerToRawData + last.SizeOfRawData,
		Characteristics:  0x60000020, // RX
	}
	copy(sh.Name[:], name)
	writeStruct(inj.dup[shOffset:], sh)
	// append data to the tail
	newSection := bytes.Repeat([]byte{0}, int(sh.SizeOfRawData))
	inj.dup = append(inj.dup, newSection...)
	// adjust the file header
	fileHeader := inj.img.FileHeader
	fileHeader.NumberOfSections++
	writeStruct(inj.dup[inj.offFileHdr:], &fileHeader)
	// adjust the size of image in optional header
	buffer := bytes.NewBuffer(nil)
	var optHdr []byte
	switch inj.arch {
	case "386":
		hdr := *inj.hdr32
		hdr.SizeOfImage += uint32(len(newSection))
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// process data directory
		optHdr = buffer.Bytes()
		sz := int(inj.numDataDir * imageDataDirectorySize)
		optHdr = optHdr[:imageOptionHeaderSize32+sz]
	case "amd64":
		hdr := *inj.hdr64
		hdr.SizeOfImage += uint32(len(newSection))
		_ = binary.Write(buffer, binary.LittleEndian, &hdr)
		// process data directory
		optHdr = buffer.Bytes()
		sz := int(inj.numDataDir * imageDataDirectorySize)
		optHdr = optHdr[:imageOptionHeaderSize64+sz]
	}
	copy(inj.dup[inj.offOptHdr:], optHdr)
	// return new section information
	nsh := pe.SectionHeader{
		Name:            name,
		VirtualSize:     sh.VirtualSize,
		VirtualAddress:  sh.VirtualAddress,
		Size:            sh.SizeOfRawData,
		Offset:          sh.PointerToRawData,
		Characteristics: sh.Characteristics,
	}
	// update context
	inj.ctx.SectionName = name
	return &nsh, nil
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

func (inj *Injector) foaToRVA(offset uint32) uint32 {
	for _, section := range inj.img.Sections {
		off := section.Offset
		size := section.Size
		if offset >= off && offset <= off+size {
			return section.VirtualAddress + (offset - section.Offset)
		}
	}
	panic(fmt.Sprintf("invalid offset: 0x%X", offset))
}

func (inj *Injector) rvaToFOA(rva uint32) uint32 {
	for _, section := range inj.img.Sections {
		va := section.VirtualAddress
		size := section.Size
		if rva >= va && rva <= va+size {
			return section.Offset + (rva - va)
		}
	}
	panic(fmt.Sprintf("invalid rva: 0x%X", rva))
}

func (inj *Injector) getFileDataByRVA(rva uint32) []byte {
	return inj.dup[inj.rvaToFOA(rva):]
}

func (inj *Injector) extractString(rva uint32) string {
	foa := inj.rvaToFOA(rva)
	for end := foa; end < inj.size; end++ {
		if inj.dup[end] == 0 {
			return string(inj.dup[foa:end])
		}
	}
	return ""
}

func (inj *Injector) alignSection(size uint32) uint32 {
	if size%inj.sectionAlign == 0 {
		return size
	}
	return (size/inj.sectionAlign + 1) * inj.sectionAlign
}

func (inj *Injector) alignFile(size uint32) uint32 {
	if size%inj.fileAlign == 0 {
		return size
	}
	return (size/inj.fileAlign + 1) * inj.fileAlign
}

func readStruct(src []byte, val interface{}) {
	_ = binary.Read(bytes.NewBuffer(src), binary.LittleEndian, val)
}

func writeStruct(dst []byte, val interface{}) {
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, val)
	copy(dst, buf.Bytes())
}
