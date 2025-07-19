.code32

entry:
  push esi
  mov eax, 0x1123
  mov ecx, 0x2313
  jmp next

fn2:
  mov edx, 0x3545
  ret

je2:
  call fn2
  nop
  pop esi
  int3

next:
  xor eax, eax
  test eax, eax
  je je1
  nop
  nop
  nop
je1:
  call fn1
  call fn2
  xor eax, eax
  test eax, eax
  je je2
  nop

fn1:
  mov edx, 0x456F
  ret
