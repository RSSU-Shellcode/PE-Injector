.code64

entry:
  // check Integer
  mov {{.Reg.rcx}}, {{hex .CIEnc.Const_1}}
  xor {{.Reg.rcx}}, {{hex .CIKey.Const_1}}
  cmp {{.Reg.rcx}}, 123
  jne panic

  mov {{.Reg.rcx}}, {{hex .CIEnc.Const_2}}
  xor {{.Reg.rcx}}, {{hex .CIKey.Const_2}}
  cmp {{.Reg.rcx}}, 456
  jne panic

  // check ANSI
  mov {{.Reg.rax}}, {{index .CAEnc.ANSI_1 0}}
  mov {{.Reg.rcx}}, {{index .CAKey.ANSI_1 0}}
  xor {{.Reg.rax}}, {{.Reg.rcx}}
  push {{.Reg.rax}}

  // "ansi"
  xor {{.Reg.rax}}, {{.Reg.rax}}
  mov {{.Reg.rax}}, 0x69736E61
  push {{.Reg.rax}}

  // compare string
  mov rsi, rsp
  lea rdi, [rsp+8]
  mov rcx, 8
  cld
  repe cmpsb
  jnz panic

  // check UTF-16
  mov {{.Reg.rax}}, {{index .CWEnc.UTF16_1 0}}
  mov {{.Reg.rcx}}, {{index .CWKey.UTF16_1 0}}
  xor {{.Reg.rax}}, {{.Reg.rcx}}
  push {{.Reg.rax}}
  mov {{.Reg.rax}}, {{index .CWEnc.UTF16_1 1}}
  mov {{.Reg.rcx}}, {{index .CWKey.UTF16_1 1}}
  xor {{.Reg.rax}}, {{.Reg.rcx}}
  push {{.Reg.rax}}

  // "utf16"
  push 0x00000036
  push 0x00310066
  push 0x00740075

  // compare string
  mov rsi, rsp
  lea rdi, [rsp+3*4]
  mov rcx, 10
  cld
  repe cmpsb
  jnz panic

  // check Arguments
  mov {{.Reg.rcx}}, {{.Args.Arg_1}}
  cmp {{.Reg.rcx}}, 123
  jne panic
  mov {{.Reg.rcx}}, {{.Args.Arg_2}}
  cmp {{.Reg.rcx}}, 456
  jne panic

  // check Switches
  {{if .Switches.Switch_1}}
    jmp panic
  {{end}}

  {{if not .Switches.Switch_2}}
    jmp panic
  {{end}}

  add rsp, 9*8

  // mark the end of loader
  {{db .EndOfLoader}}

panic:
  int3
