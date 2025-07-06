.code64

// r10 store address of CreateThread
// r11 store address of VirtualAlloc
// r12 store address of VirtualProtect

// find CreateThread, VirtualAlloc and VirtualProtect
{{if .LackProcedure}}

  // push kernel32.dll\0 to stack
  mov {{.Reg.rax}}, {{index .Kernel32DLL 0}}      {{is}}
  mov {{.Reg.r8}},  {{index .Kernel32DLLKey 0}}   {{is}}
  xor {{.Reg.rax}}, {{.Reg.r8}}                   {{is}}
  push {{.Reg.rax}}                               {{is}}
  mov {{.Reg.rbx}}, {{index .Kernel32DLL 1}}      {{is}}
  mov {{.Reg.r9}},  {{index .Kernel32DLLKey 1}}   {{is}}
  xor {{.Reg.rbx}}, {{.Reg.r9}}                   {{is}}
  push {{.Reg.rbx}}                               {{is}}

  {{if .LoadLibraryWOnly}}
  mov {{.Reg.rcx}}, {{index .Kernel32DLL 2}}      {{is}}
  mov {{.Reg.r10}}, {{index .Kernel32DLLKey 2}}   {{is}}
  xor {{.Reg.rcx}}, {{.Reg.r10}}                  {{is}}
  push {{.Reg.rcx}}                               {{is}}
  mov {{.Reg.rdx}}, {{index .Kernel32DLL 3}}      {{is}}
  mov {{.Reg.r11}}, {{index .Kernel32DLLKey 3}}   {{is}}
  xor {{.Reg.rdx}}, {{.Reg.r11}}                  {{is}}
  push {{.Reg.rdx}}                               {{is}}
  {{end}}

  // read the LoadLibraryA/W form IAT
  mov {{.RegS.rbx}}, [rip + 0xFF112200]
  // load kernel32.dll
  mov rcx, rsp
  sub rsp, 0x20
  call {{.RegS.rbx}}
  add rsp, 0x20

  // store DLL handle in stable register
  mov {{.RegS.rbx}}, rax

  // restore stack
  {{if .LoadLibraryWOnly}}
  add rsp, 4*8
  {{else}}
  add rsp, 2*8
  {{end}}

  // read the GetProcAddress form IAT
  mov {{.Reg.rax}}, [rip + 0xFF112201]

  {{if .LackCreateThread}}

  {{else}}
  mov {{.RegS.r10}}, [rip + 0xFF112210]
  {{end}}

  {{if .LackVirtualAlloc}}

  {{else}}
  mov {{.RegS.r11}}, [rip + 0xFF112211]
  {{end}}

  {{if .LackVirtualProtect}}

  {{else}}
  mov {{.RegS.r12}}, [rip + 0xFF112212]
  {{end}}

{{else}}
  mov {{.RegS.r10}}, [rip + 0xFF112210]
  mov {{.RegS.r11}}, [rip + 0xFF112211]
  mov {{.RegS.r12}}, [rip + 0xFF112212]
{{end}}

