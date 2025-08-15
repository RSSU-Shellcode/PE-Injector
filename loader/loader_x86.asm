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
  mov {{.Reg.r8}},  {{index .Kernel32DLLKey 0}}                {{igi}}
  xor {{.Reg.eax}}, {{.Reg.r8}}                                {{igi}}
  push {{.Reg.eax}}                                            {{igi}}
  mov {{.Reg.ebx}}, {{index .Kernel32DLLDB  1}}                {{igi}}
  mov {{.Reg.r9}},  {{index .Kernel32DLLKey 1}}                {{igi}}
  xor {{.Reg.ebx}}, {{.Reg.r9}}                                {{igi}}
  push {{.Reg.ebx}}                                            {{igi}}

  {{if .LoadLibraryWOnly}}
    mov {{.Reg.ecx}}, {{index .Kernel32DLLDB  2}}              {{igi}}
    mov {{.Reg.r10}}, {{index .Kernel32DLLKey 2}}              {{igi}}
    xor {{.Reg.ecx}}, {{.Reg.r10}}                             {{igi}}
    push {{.Reg.ecx}}                                          {{igi}}
    mov {{.Reg.rdx}}, {{index .Kernel32DLLDB  3}}              {{igi}}
    mov {{.Reg.r11}}, {{index .Kernel32DLLKey 3}}              {{igi}}
    xor {{.Reg.rdx}}, {{.Reg.r11}}                             {{igi}}
    push {{.Reg.rdx}}                                          {{igi}}
  {{end}}

  // get pointer to the PEB
  xor {{.Reg.eax}}, {{.Reg.eax}}                               {{igi}}
  mov {{.Reg.eax}}, 0x60                                       {{igi}}
  mov {{.Reg.ebx}}, gs:[{{.Reg.eax}}]                          {{igi}}
  // store image base address
  mov {{.RegN.edi}}, [{{.Reg.ebx}} + 0x10]                     {{igi}}

  // read the LoadLibraryA/W form IAT
  mov {{.RegN.ebx}}, {{.RegN.edi}}                             {{igi}}
  add {{.RegN.ebx}}, {{hex .LoadLibrary}}                      {{igi}}
  mov {{.RegN.ebx}}, [{{.RegN.ebx}}]                           {{igi}}

  // load kernel32.dll
  mov ecx, esp         {{igi}} // lpLibFileName
  sub esp, 0x20        {{igi}} // reserve stack for call convention
  call {{.RegN.ebx}}   {{igi}} // call LoadLibraryA/W
  add esp, 0x20        {{igi}} // restore stack for call convention

  // store the handle of kernel32.dll
  mov {{.RegN.esi}}, eax                                       {{igi}}

  // restore stack for kernel32 module name
  {{if .LoadLibraryWOnly}}
    add esp, 8*4                                               {{igi}}
  {{else}}
    add esp, 4*4                                               {{igi}}
  {{end}}

{{else}}
  // get pointer to the PEB
  xor {{.Reg.eax}}, {{.Reg.eax}}                               {{igi}}
  mov {{.Reg.eax}}, 0x60                                       {{igi}}
  mov {{.Reg.ebx}}, gs:[{{.Reg.eax}}]                          {{igi}}
  // store image base address
  mov {{.RegN.edi}}, [{{.Reg.ebx}} + 0x10]                     {{igi}}
  // get procedure address of VirtualAlloc
  mov {{.RegV.ecx}}, {{.RegN.edi}}                             {{igi}}
  add {{.RegV.ecx}}, {{hex .VirtualAlloc}}                     {{igi}}
  mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                           {{igi}}
  mov [esp+0x10], {{.RegV.ecx}}                                {{igi}}
  // get procedure address of VirtualFree
  {{if .NeedEraseShellcode}}
    mov {{.RegV.ecx}}, {{.RegN.edi}}                           {{igi}}
    add {{.RegV.ecx}}, {{hex .VirtualFree}}                    {{igi}}
    mov {{.RegV.ecx}}, [{{.RegV.ecx}}]                         {{igi}}
    mov [esp+0x18], {{.RegV.ecx}}                              {{igi}}
  {{end}}
  // get procedure address of VirtualProtect
  mov {{.RegV.rdx}}, {{.RegN.edi}}                             {{igi}}
  add {{.RegV.rdx}}, {{hex .VirtualProtect}}                   {{igi}}
  mov {{.RegV.rdx}}, [{{.RegV.rdx}}]                           {{igi}}
  mov [esp+0x20], {{.RegV.rdx}}                                {{igi}}
  // get procedure address of CreateThread
  {{if .NeedCreateThread}}
    mov {{.RegV.r8}}, {{.RegN.edi}}                            {{igi}}
    add {{.RegV.r8}}, {{hex .CreateThread}}                    {{igi}}
    mov {{.RegV.r8}}, [{{.RegV.r8}}]                           {{igi}}
    mov [esp+0x28], {{.RegV.r8}}                               {{igi}}
  {{end}}
  // get procedure address of WaitFoesingleObject
  {{if .NeedWaitThread}}
    mov {{.RegV.r9}}, {{.RegN.edi}}                            {{igi}}
    add {{.RegV.r9}}, {{hex .WaitFoesingleObject}}             {{igi}}
    mov {{.RegV.r9}}, [{{.RegV.r9}}]                           {{igi}}
    mov [esp+0x30], {{.RegV.r9}}                               {{igi}}
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
