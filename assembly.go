package injector

import (
	"encoding/binary"

	"golang.org/x/arch/x86/x86asm"
)

const nearJumpSize = 1 + 4

func (inj *Injector) disassemble(src []byte) ([]*x86asm.Inst, error) {
	var mode int
	switch inj.arch {
	case "386":
		mode = 32
	case "amd64":
		mode = 64
	}
	var insts []*x86asm.Inst
	for len(src) > 0 {
		inst, err := x86asm.Decode(src, mode)
		if err != nil {
			return nil, err
		}
		insts = append(insts, &inst)
		src = src[inst.Len:]
	}
	return insts, nil
}

// relocateInstruction is used to relocate instruction like jmp, call...
// [Warning]: it is only partially done.
// #nosec G115
func (inj *Injector) relocateInstruction(src []byte, offset int64) []byte {
	var mode int
	switch inj.arch {
	case "386":
		mode = 32
	case "amd64":
		mode = 64
	}
	inst, err := x86asm.Decode(src, mode)
	if err != nil {
		panic(err)
	}
	output := make([]byte, len(src))
	copy(output, src)
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
	default:
	}
	return output
}
