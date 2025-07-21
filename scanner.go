package injector

import (
	"errors"
)

const (
	jmpInstSize    = 5
	expInstSizeX86 = 7
	expInstSizeX64 = 12
	expCaveSizeX86 = expInstSizeX86 + jmpInstSize
	expCaveSizeX64 = expInstSizeX64 + jmpInstSize
)

type codeCave struct {
	virtualAddr  uint32
	pointerToRaw uint32
	size         int
}

func (inj *Injector) scanCodeCave() ([]*codeCave, error) {
	text := inj.img.Section(".text")
	if text == nil {
		return nil, errors.New("cannot find .text section in image")
	}
	// record offset and calculate scan range
	size := text.Size
	if text.VirtualSize < size {
		size = text.VirtualSize
	}
	if size < 32*1024 {
		return nil, errors.New(".text section too small")
	}
	section, err := text.Data()
	if err != nil {
		return nil, err
	}
	section = section[:size-32]
	// scan code caves
	caves := inj.scanSection(section, text.VirtualAddress, text.Offset)
	return caves, nil
}

// #nosec G115
func (inj *Injector) scanSection(section []byte, va, raw uint32) []*codeCave {
	var expCaveSize int
	switch inj.arch {
	case "386":
		expCaveSize = expCaveSizeX86
	case "amd64":
		expCaveSize = expCaveSizeX64
	}
	var (
		address int
		reserve int
		caves   []*codeCave
	)
	for address < len(section) {
		b := section[address]
		switch b {
		case 0x00:
			address++
			continue
		case 0xCC:
			reserve = 2
		default:
			reserve = 5
		}
		expSize := reserve + expCaveSize
		caveSize := 1
		for j := address + 1; j < len(section); j++ {
			if section[j] != b {
				break
			}
			caveSize++
			if caveSize == expSize {
				break
			}
		}
		if caveSize == expSize {
			caves = append(caves, &codeCave{
				virtualAddr:  va + uint32(address+reserve),
				pointerToRaw: raw + uint32(address+reserve),
				size:         caveSize - reserve,
			})
		}
		address += caveSize
	}
	return caves
}
