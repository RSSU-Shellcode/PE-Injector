.code64

entry:
  pushfq
  push {{.Reg.rax}}

  {{if .Switch.A}}
  mov {{.Reg.rax}}, {{.Reg.rbx}}
  test {{.Reg.rax}}, {{.Reg.rax}}
  jnz next_1
  {{iji}}
 next_1:
  call func_1
  {{end}}

  {{if .Switch.B}}
  xor {{.Reg.rax}}, {{.Reg.rcx}}
  {{iji}}
  {{end}}

  {{if .Switch.C}}
  xor {{.Reg.rax}}, {{.DWORD.D}}
  call func_2
  {{end}}

  {{if .Switch.D}}
  mov {{.Reg.rax}}, {{.WORD.E}}
  test {{.Reg.rax}}, {{.Reg.rax}}
  jnz next_3
  {{iji}}
 next_3:
  {{iji}}
  {{end}}

  {{if .Switch.E}}
  ror {{.Reg.rax}}, {{.Less32.A}}
  xor {{.Reg.rax}}, {{.Reg.rdi}}
  rol {{.Reg.rax}}, {{.Less32.B}}
  call func_3
  {{end}}

  pop {{.Reg.rax}}
  popfq
  jmp exit

func_1:
  {{iji}}
  ret

func_2:
  push {{.Reg.rbx}}
  mov {{.Reg.rbx}}, {{.Reg.rcx}}
  {{if .Switch.F}}
  test {{.Reg.rbx}}, {{.Reg.rbx}}
  jnz next_2
  {{iji}}
 next_2:
  call func_1
  {{end}}
  pop {{.Reg.rbx}}
  ret

func_3:
  rol {{.Reg.rax}}, {{.Less32.C}}
  ret

exit:
