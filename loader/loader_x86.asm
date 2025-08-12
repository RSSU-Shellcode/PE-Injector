.code32

// edi store address of ImageBaseAddress
// esi store address of kernel32.dll
// ebx store address of LoadLibrary
// ebp store address of GetProcAddress
// [esp+0x04] store address of allocated memory page
// [esp+0x08] store address of VirtualAlloc
// [esp+0x0C] store address of VirtualFree
// [esp+0x10] store address of VirtualProtect
// [esp+0x14] store address of CreateThread
// [esp+0x18] store address of WaitForSingleObject

entry:
  // ensure stack is 16 bytes aligned
  push ebp
  mov ebp, esp
  and esp, 0xFFFFFFF0
  push ebp

  // reserve stack for store variables
  sub esp, 0x2C


  // restore stack for store variables
  add esp, 0x2C

  // restore stack and ebp
  pop ebp                                                      {{igi}}
  mov esp, ebp                                                 {{igi}}
  pop ebp                                                      {{igi}}

  // mark the end of loader
  {{db .EndOfLoader}}
