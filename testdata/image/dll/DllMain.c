#include <windows.h>

typedef void (*Sleep_t)
(
    DWORD dwMilliseconds
);

BOOL DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    return TRUE;
}

INT32 Add(INT32 a, INT32 b)
{
    return a + b;
}

// only let procedure LoadLibraryW and GetProcAddress in IAT
BOOL Load()
{
    HMODULE hKernel32 = LoadLibrary(L"kernel32.dll");
    if (hKernel32 == NULL)
    {
        return FALSE;
    }
    Sleep_t Sleep = (Sleep_t)GetProcAddress(hKernel32, "Sleep");
    if (Sleep == NULL)
    {
        return FALSE;
    }
    Sleep(100);
    return TRUE;
}
