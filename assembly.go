package injector

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

const nearJumpSize = 1 + 4

func (inj *Injector) decodeInst(src []byte) (*x86asm.Inst, error) {
	var mode int
	switch inj.arch {
	case "386":
		mode = 32
	case "amd64":
		mode = 64
	}
	inst, err := x86asm.Decode(src, mode)
	if err != nil {
		return nil, err
	}
	return &inst, nil
}

func (inj *Injector) disassemble(src []byte) ([]*x86asm.Inst, error) {
	var insts []*x86asm.Inst
	for len(src) > 0 {
		inst, err := inj.decodeInst(src)
		if err != nil {
			return nil, err
		}
		insts = append(insts, inst)
		src = src[inst.Len:]
	}
	return insts, nil
}

// relocateInstruction is used to relocate instruction like jmp, call...
// [Warning]: it is only partially done.
// #nosec G115
func (inj *Injector) relocateInstruction(src []byte, offset int64) []byte {
	inst, err := inj.decodeInst(src)
	if err != nil {
		panic(err)
	}
	fmt.Println(inst.AddrSize, inst.DataSize, inst.MemBytes, len(src), inst.PCRel, inst.PCRelOff)

	output := make([]byte, len(src))
	copy(output, src)
	switch inst.PCRel {
	case 0:
	case 1:
		rel := int64(inst.Args[0].(x86asm.Rel))
		output[1] = uint8(rel - offset)
	case 2:
		rel := int64(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint16(output[1:], uint16(rel-offset))
	case 4:
		rel := int64(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(output[1:], uint32(rel-offset))
	}
	return output

	switch inst.Op {
	case x86asm.CALL:
		switch output[0] {
		case 0xFF:
			switch output[1] {
			case 0x15:
				mem := inst.Args[0].(x86asm.Mem)
				binary.LittleEndian.PutUint32(output[2:], uint32(mem.Disp-offset))
			}
		case 0xE8:
			mem := inst.Args[0].(x86asm.Mem)
			binary.LittleEndian.PutUint32(output[1:], uint32(mem.Disp-offset))
		}
	case x86asm.JMP:
		switch output[0] {
		case 0xEB:
			rel := int64(inst.Args[0].(x86asm.Rel))
			output[1] = uint8(rel - offset)
		case 0xE9:
			rel := int64(inst.Args[0].(x86asm.Rel))
			binary.LittleEndian.PutUint32(output[1:], uint32(rel-offset))
		case 0x48:
			switch output[1] {
			case 0xFF:
				switch output[2] {
				case 0x25:
					mem := inst.Args[0].(x86asm.Mem)
					binary.LittleEndian.PutUint32(output[3:], uint32(mem.Disp-offset))
				}
			}
		}
	case x86asm.JG:
	case x86asm.JGE:
	case x86asm.JL:
	case x86asm.JLE:
	case x86asm.JE:
	case x86asm.JNE:

	default:
	}
	return output
}
