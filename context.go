package injector

var (
	saveContextX86    = [][]byte{{0x60}, {0x9C}} //      pushad, pushfd
	restoreContextX86 = [][]byte{{0x61}, {0x9D}} //      popad, popfd

	saveContextFPX86 = [][]byte{
		{0x8B, 0xEC},                         //         mov ebp, esp
		{0x81, 0xE4, 0xF0, 0xFF, 0xFF, 0xFF}, //         and esp, 0xFFFFFFF0
		{0x81, 0xEC, 0x00, 0x02, 0x00, 0x00}, //         sub esp, 0x200
		{0x0F, 0xAE, 0x04, 0x24},             //         fxsave [esp]
	}

	restoreContextFPX86 = [][]byte{
		{0x8B, 0xE5},             //                     mov esp, ebp
		{0x0F, 0xAE, 0x0C, 0x24}, //                     fxrstor [esp]
	}

	saveContextX64 = [][]byte{
		{0x50}, {0x53}, {0x51}, {0x52}, //               push rax, rbx, rcx, rdx
		{0x56}, {0x57}, {0x55}, {0x54}, //               push rsi, rdi, rbp, rsp
		{0x41, 0x50}, {0x41, 0x51}, //                   push r8, r9
		{0x41, 0x52}, {0x41, 0x53}, //                   push r10, r11
		{0x41, 0x54}, {0x41, 0x55}, //                   push r12, r13
		{0x41, 0x56}, {0x41, 0x57}, //                   push r14, r15
		{0x9C}, //                                       pushfq
	}

	restoreContextX64 = [][]byte{
		{0x58}, {0x5B}, {0x59}, {0x5A}, //               pop rax, rbx, rcx, rdx
		{0x5E}, {0x5F}, {0x5D}, {0x5C}, //               pop rsi, rdi, rbp, rsp
		{0x41, 0x58}, {0x41, 0x59}, //                   pop r8, r9
		{0x41, 0x5A}, {0x41, 0x5B}, //                   pop r10, r11
		{0x41, 0x5C}, {0x41, 0x5D}, //                   pop r12, r13
		{0x41, 0x5E}, {0x41, 0x5F}, //                   pop r14, r15
		{0x9D}, //                                       popfq
	}

	saveContextFPX64 = [][]byte{
		{0x48, 0x8B, 0xEC},                         //   mov rbp, rsp
		{0x48, 0x83, 0xE4, 0xF0},                   //   and rsp, 0xFFFFFFFFFFFFFFF0
		{0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00}, //   sub rsp, 0x200
		{0x0F, 0xAE, 0x04, 0x24},                   //   fxsave [rsp]
	}

	restoreContextFPX64 = [][]byte{
		{0x48, 0x8B, 0xE5},       //                     mov rsp, rbp
		{0x0F, 0xAE, 0x0C, 0x24}, //                     fxrstor [rsp]
	}
)

func (inj *Injector) saveContext() [][]byte {
	var (
		save [][]byte
		fp   [][]byte
	)
	switch inj.arch {
	case "386":
		save = saveContextX86
		fp = saveContextFPX86
	case "amd64":
		save = saveContextX64
		fp = saveContextFPX64
	}
	inj.contextSeq = inj.rand.Perm(len(save))
	insts := make([][]byte, 0, len(save))
	for i := 0; i < len(save); i++ {
		selected := save[inj.contextSeq[i]]
		inst := make([]byte, len(selected))
		copy(inst, selected)
		insts = append(insts, inst)
	}
	for i := 0; i < len(fp); i++ {
		inst := make([]byte, len(fp[i]))
		copy(inst, fp[i])
		insts = append(insts, inst)
	}
	return insts
}

func (inj *Injector) restoreContext() [][]byte {
	var (
		restore [][]byte
		fp      [][]byte
	)
	switch inj.arch {
	case "386":
		restore = restoreContextX86
		fp = restoreContextFPX86
	case "amd64":
		restore = restoreContextX64
		fp = restoreContextFPX64
	}
	insts := make([][]byte, 0, len(restore))
	for i := len(fp) - 1; i >= 0; i-- {
		inst := make([]byte, len(fp[i]))
		copy(inst, fp[i])
		insts = append(insts, inst)
	}
	for i := len(restore) - 1; i >= 0; i-- {
		selected := restore[inj.contextSeq[i]]
		inst := make([]byte, len(selected))
		copy(inst, selected)
		insts = append(insts, inst)
	}
	return insts
}
