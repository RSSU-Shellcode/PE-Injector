.code32

pushfd
push {{.Reg.eax}}
entry:
  pushfd
  push {{.Reg.eax}}

{{if .Switch.A}}
mov {{.Reg.eax}}, {{.Reg.ebx}}
{{end}}
  {{if .Switch.A}}
  mov {{.Reg.eax}}, {{.Reg.ebx}}
  test {{.Reg.eax}}, {{.Reg.eax}}
  jnz next_1
  {{iji}}
 next_1:
  call func_1
  {{end}}

{{if .Switch.B}}
xor {{.Reg.eax}}, {{.Reg.ecx}}
{{end}}
  {{if .Switch.B}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  {{iji}}
  jmp leave
  {{end}}

{{if .Switch.C}}
xor {{.Reg.eax}}, {{.DWORD.D}}
{{end}}
  {{if .Switch.C}}
  xor {{.Reg.eax}}, {{.DWORD.D}}
  call func_2
  {{end}}

{{if .Switch.D}}
mov {{.Reg.eax}}, {{.WORD.E}}
{{end}}
  {{if .Switch.D}}
  mov {{.Reg.eax}}, {{.WORD.E}}
  test {{.Reg.eax}}, {{.Reg.eax}}
  jnz next_3
  {{iji}}
 next_3:
  {{iji}}
  jmp leave
  {{end}}

{{if .Switch.E}}
ror {{.Reg.eax}}, {{.Less32.A}}
xor {{.Reg.eax}}, {{.Reg.edi}}
rol {{.Reg.eax}}, {{.Less32.B}}
{{end}}
  {{if .Switch.E}}
  ror {{.Reg.eax}}, {{.Less32.A}}
  xor {{.Reg.eax}}, {{.Reg.edi}}
  rol {{.Reg.eax}}, {{.Less32.B}}
  call func_3
  {{end}}

pop {{.Reg.eax}}
popfd
 leave:
  pop {{.Reg.eax}}
  popfd
  jmp exit

func_1:
  {{iji}}
  ret

func_2:
  push {{.Reg.ebx}}
  mov {{.Reg.ebx}}, {{.Reg.ecx}}
  {{if .Switch.F}}
    test {{.Reg.ebx}}, {{.Reg.ebx}}
    jnz next_2
    {{iji}}
   next_2:
    call func_1
  {{end}}
  pop {{.Reg.ebx}}
  ret

func_3:
  rol {{.Reg.eax}}, {{.Less32.C}}
  {{if .Switch.E}}
  {{iji}}
  {{end}}
  ret

exit:
