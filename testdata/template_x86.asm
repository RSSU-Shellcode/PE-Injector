.code32

entry:
  // check Integer
  mov {{.Reg.ecx}}, {{hex .CIEnc.Const_1}}
  xor {{.Reg.ecx}}, {{hex .CIKey.Const_1}}
  cmp {{.Reg.ecx}}, 123
  jne panic

  mov {{.Reg.ecx}}, {{hex .CIEnc.Const_2}}
  xor {{.Reg.ecx}}, {{hex .CIKey.Const_2}}
  cmp {{.Reg.ecx}}, 456
  jne panic

  // check ANSI
  mov {{.Reg.eax}}, {{index .CAEnc.ANSI_1 0}}
  mov {{.Reg.ecx}}, {{index .CAKey.ANSI_1 0}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}
  mov {{.Reg.eax}}, {{index .CAEnc.ANSI_1 1}}
  mov {{.Reg.ecx}}, {{index .CAKey.ANSI_1 1}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}

  // "ansi"
  push 0x69736E61

  // compare string
  mov esi, esp
  lea edi, [esp+4]
  mov ecx, 4
  cld
  repe cmpsb
  jnz panic

  // check UTF-16
  mov {{.Reg.eax}}, {{index .CWEnc.UTF16_1 0}}
  mov {{.Reg.ecx}}, {{index .CWKey.UTF16_1 0}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}
  mov {{.Reg.eax}}, {{index .CWEnc.UTF16_1 1}}
  mov {{.Reg.ecx}}, {{index .CWKey.UTF16_1 1}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}
  mov {{.Reg.eax}}, {{index .CWEnc.UTF16_1 2}}
  mov {{.Reg.ecx}}, {{index .CWKey.UTF16_1 2}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}

  // "utf16"
  push 0x00000036
  push 0x00310066
  push 0x00740075

  // compare string
  mov esi, esp
  lea edi, [esp+3*4]
  mov ecx, 10
  cld
  repe cmpsb
  jnz panic

  // check Arguments
  mov {{.Reg.ecx}}, {{.Args.Arg_1}}
  cmp {{.Reg.ecx}}, 123
  jne panic
  mov {{.Reg.ecx}}, {{.Args.Arg_2}}
  cmp {{.Reg.ecx}}, 456
  jne panic

  // check Switches
  {{if .Switches.Switch_1}}
    jmp panic
  {{end}}

  {{if not .Switches.Switch_2}}
    jmp panic
  {{end}}

  add esp, 9*4

  // mark the end of loader
  {{db .EndOfLoader}}

panic:
  int3
