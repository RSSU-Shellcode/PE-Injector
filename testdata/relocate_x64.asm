.code64

entry:
  mov rax, 0x1123
  mov rcx, 0x2313

  jmp next
fn2:
  mov r8, 0x3545
  ret

next:
  xor rax, rax
  call fn2
  call fn1
  nop
  int3

fn1:
  mov r9, 0x456F
  ret
