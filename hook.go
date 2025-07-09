package injector

import (
	"encoding/binary"
	"errors"

	"golang.org/x/arch/x86/x86asm"
)

const nearJumperSize = 1 + 4

func (inj *Injector) hook(address uint64, first *codeCave) error {
	var mode int
	switch inj.arch {
	case "386":
		mode = 32
	case "amd64":
		mode = 64
	}
	insts, err := disassemble(inj.dup[address:], mode)
	if err != nil {
		return err
	}
	numInst, totalSize, err := calcInstNumAndSize(insts)
	if err != nil {
		return err
	}
	var offset uint64
	relocated := make([][]byte, numInst)
	for i := 0; i < numInst; i++ {
		relocated[i] = make([]byte, insts[i].Len)
		copy(relocated[i], inj.dup[address+offset:])
		offset += uint64(insts[i].Len)
	}
	return err
}

func disassemble(data []byte, mode int) ([]*x86asm.Inst, error) {
	var insts []*x86asm.Inst
	for len(data) > 0 {
		inst, err := x86asm.Decode(data, mode)
		if err != nil {
			if len(insts) == 0 {
				return nil, err
			}
			return insts, nil
		}
		insts = append(insts, &inst)
		data = data[inst.Len:]
	}
	return insts, nil
}

// calcInstNumAndSize is used to calculate the instruction number
// and the total size that will be overwritten.
func calcInstNumAndSize(insts []*x86asm.Inst) (int, int, error) {
	var (
		num  int
		size int
	)
	for i := 0; i < len(insts); i++ {
		num++
		size += insts[i].Len
		if size >= nearJumperSize {
			return num, size, nil
		}
	}
	return 0, 0, errors.New("unable to insert near jmp to this address")
}

// relocateInstruction is used to relocate instruction like jmp, call...
// [Warning]: it is only partially done.
func relocateInstruction(offset int, inst *x86asm.Inst, data []byte) []byte {
	output := make([]byte, len(data))
	copy(output, data)
	switch inst.Op {
	case x86asm.CALL:
		switch output[0] {
		case 0xFF:
			switch output[1] {
			case 0x15:
				mem := inst.Args[0].(x86asm.Mem)
				binary.LittleEndian.PutUint32(output[2:], uint32(int(mem.Disp)-offset))
			}
		case 0xE8:
			mem := inst.Args[0].(x86asm.Mem)
			binary.LittleEndian.PutUint32(output[1:], uint32(int(mem.Disp)-offset))
		}
	case x86asm.JMP:
		switch output[0] {
		case 0xE9:
			mem := inst.Args[0].(x86asm.Mem)
			binary.LittleEndian.PutUint32(output[1:], uint32(int(mem.Disp)-offset))
		case 0x48:
			switch output[1] {
			case 0xFF:
				switch output[2] {
				case 0x25:
					mem := inst.Args[0].(x86asm.Mem)
					binary.LittleEndian.PutUint32(output[3:], uint32(int(mem.Disp)-offset))
				}
			}
		}
	default:
	}
	return output
}
