package injector

import (
	"debug/pe"
	"errors"
)

// 0xCC, 0xCC, [n * 0xCC]

const (
	reserveSize    = 2
	jmpInstSize    = 5
	maxInstSizeX86 = 7
	maxInstSizeX64 = 12
	minCaveSizeX86 = reserveSize + (maxInstSizeX86 + jmpInstSize)
	minCaveSizeX64 = reserveSize + (maxInstSizeX64 + jmpInstSize)
	minNumCaves    = 128
)

type codeCave struct {
	addr int
	size int
}

func (inj *Injector) scanCodeCave() error {
	var text *pe.Section
	for _, section := range inj.img.Sections {
		if section.Name == ".text" {
			text = section
			break
		}
	}
	if text == nil {
		return errors.New("cannot find .text section in image")
	}
	// record offset and calculate scan range
	offset := text.Offset
	size := text.Size
	if text.VirtualSize < size {
		size = text.VirtualSize
	}
	if size < 32*1024 {
		return errors.New(".text section too small")
	}
	section, err := text.Data()
	if err != nil {
		return err
	}
	section = section[:size-32]
	// scan code caves
	caves := inj.scanSection(section, int(offset))
	if len(caves) < minNumCaves {
		return errors.New("too little code caves")
	}
	inj.caves = caves
	return nil
}

func (inj *Injector) scanSection(section []byte, offset int) []*codeCave {
	var caves []*codeCave
	for addr := 0; addr < len(section); addr++ {
		if section[addr] != 0xCC {
			continue
		}
		caveSize := 1
		for j := addr + 1; j < len(section); j++ {
			if section[j] != 0xCC {
				break
			}
			caveSize++
		}
		// check the cave size is enough
		var minCaveSize int
		switch inj.arch {
		case "386":
			minCaveSize = minCaveSizeX86
		case "amd64":
			minCaveSize = minCaveSizeX64
		}
		if caveSize < minCaveSize {
			addr += caveSize
			continue
		}
		caves = append(caves, &codeCave{
			addr: offset + addr + reserveSize,
			size: caveSize - reserveSize,
		})
		addr += caveSize
	}
	return caves
}
