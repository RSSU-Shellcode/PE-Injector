#include <windows.h>

BOOL DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    return TRUE;
}

INT32 Add(INT32 a, INT32 b)
{
    return a + b;
}
