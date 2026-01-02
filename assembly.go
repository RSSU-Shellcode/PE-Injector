package injector

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

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
	var mode int
	switch inj.arch {
	case "386":
		mode = 32
	case "amd64":
		mode = 64
	}
	return disassemble(src, mode)
}

func disassemble(src []byte, mode int) ([]*x86asm.Inst, error) {
	var insts []*x86asm.Inst
	for len(src) > 0 {
		inst, err := x86asm.Decode(src, mode)
		if err != nil {
			return insts, err
		}
		insts = append(insts, &inst)
		src = src[inst.Len:]
	}
	return insts, nil
}

// extendInstruction is used to extend instruction when rel is 1 byte,
// replace it to 4 bytes version, for instruction like jmp.
// [Warning]: it is only partially done.
// #nosec G115
func (inj *Injector) extendInstruction(inst *x86asm.Inst, src []byte) []byte {
	if inst == nil {
		var err error
		inst, err = inj.decodeInst(src)
		if err != nil {
			panic(err)
		}
	}
	if inst.PCRel >= 4 {
		return src
	}
	switch inst.Op {
	case x86asm.JMP:
		jmp := make([]byte, 5)
		jmp[0] = 0xE9
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(jmp[1:], rel)
		return jmp
	case x86asm.JE:
		je := make([]byte, 6)
		je[0] = 0x0F
		je[1] = 0x84
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(je[2:], rel)
		return je
	case x86asm.JNE:
		jne := make([]byte, 6)
		jne[0] = 0x0F
		jne[1] = 0x85
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(jne[2:], rel)
		return jne
	case x86asm.JG:
		jg := make([]byte, 6)
		jg[0] = 0x0F
		jg[1] = 0x8F
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(jg[2:], rel)
		return jg
	case x86asm.JGE:
		jge := make([]byte, 6)
		jge[0] = 0x0F
		jge[1] = 0x8D
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(jge[2:], rel)
		return jge
	case x86asm.JL:
		jl := make([]byte, 6)
		jl[0] = 0x0F
		jl[1] = 0x8C
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(jl[2:], rel)
		return jl
	case x86asm.JLE:
		jle := make([]byte, 6)
		jle[0] = 0x0F
		jle[1] = 0x8E
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(jle[2:], rel)
		return jle
	case x86asm.JBE:
		jbe := make([]byte, 6)
		jbe[0] = 0x0F
		jbe[1] = 0x86
		rel := uint32(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(jbe[2:], rel)
		return jbe
	default:
		return src
	}
}

// relocateInstruction is used to relocate instruction like jmp, call...
// [Warning]: it is only partially done.
// #nosec G115
func (inj *Injector) relocateInstruction(src []byte, offset int64) []byte {
	inst, err := inj.decodeInst(src)
	if err != nil {
		panic(err)
	}
	output := bytes.Clone(src)
	switch inst.Args[0].(type) {
	case x86asm.Rel:
	default:
		return output
	}
	switch inst.PCRel {
	case 0:
	case 1:
		rel := int64(inst.Args[0].(x86asm.Rel))
		output[inst.PCRelOff] = uint8(rel - offset)
	case 2:
		rel := int64(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint16(output[inst.PCRelOff:], uint16(rel-offset))
	case 4:
		rel := int64(inst.Args[0].(x86asm.Rel))
		binary.LittleEndian.PutUint32(output[inst.PCRelOff:], uint32(rel-offset))
	}
	return output
}

func (inj *Injector) disassembleLoader(loader []byte) (string, string) {
	var mode int
	switch inj.arch {
	case "386":
		mode = 32
	case "amd64":
		mode = 64
	}
	binHex, insts, err := printInstructions(loader, mode)
	if err != nil {
		panic(err)
	}
	return binHex, insts
}

func printInstructions(src []byte, mode int) (string, string, error) {
	binHex := strings.Builder{}
	insts := strings.Builder{}
	for len(src) > 0 {
		inst, err := x86asm.Decode(src, mode)
		if err != nil {
			return "", "", err
		}
		b := src[:inst.Len]
		binHex.WriteString(printAssemblyBinHex(&inst, b))
		binHex.Write([]byte("\r\n"))
		insts.WriteString(printAssemblyInstruction(&inst))
		insts.Write([]byte("\r\n"))
		src = src[inst.Len:]
	}
	return binHex.String(), insts.String(), nil
}

func printAssemblyBinHex(inst *x86asm.Inst, b []byte) string {
	var bin strings.Builder
	switch {
	case inst.PCRelOff != 0:
		s1 := strings.ToUpper(hex.EncodeToString(b[:inst.PCRelOff]))
		s2 := strings.ToUpper(hex.EncodeToString(b[inst.PCRelOff:]))
		bin.WriteString(s1)
		bin.WriteString(" ")
		bin.WriteString(s2)
	default:
		s := strings.ToUpper(hex.EncodeToString(b))
		bin.WriteString(s)
	}
	return bin.String()
}

func printAssemblyInstruction(inst *x86asm.Inst) string {
	var buf bytes.Buffer
	for _, p := range inst.Prefix {
		if p == 0 {
			break
		}
		if p&x86asm.PrefixImplicit != 0 {
			continue
		}
		_, _ = fmt.Fprintf(&buf, "%s ", strings.ToLower(p.String()))
	}
	_, _ = fmt.Fprintf(&buf, "%s", strings.ToLower(inst.Op.String()))
	sep := " "
	for _, v := range inst.Args {
		if v == nil {
			break
		}
		_, _ = fmt.Fprintf(&buf, "%s%s", sep, strings.ToLower(v.String()))
		sep = ", "
	}
	return buf.String()
}
