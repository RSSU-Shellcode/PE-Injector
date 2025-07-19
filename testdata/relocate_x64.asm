.code64

entry:
  mov rax, 0x1123
  mov rcx, 0x2313
  jmp next

fn2:
  mov r8, 0x3545
  ret

je2:
  call fn2
  nop
  int3

next:
  xor rax, rax
  test rax, rax
  je je1
  nop
  nop
  nop
je1:
  call fn1
  call fn2
  xor rax, rax
  test rax, rax
  je je2
  nop

fn1:
  mov r9, 0x456F
  ret
