#include "dlltest.h"

VOID WorkFunc(LPVOID fdwReason)
{
    wchar_t tmpStr[1024] = {0};
    swprintf(tmpStr, 1024, L"进程ID: %u，线程ID：%u，事件：%s", GetCurrentProcessId(), GetCurrentThreadId(), utf8toutf16(reason2text((DWORD)fdwReason), utf16_buffer, M_BUF_SIZ));
    MessageBoxW(NULL, tmpStr, L"注入成功", MB_OK);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved)
{
    debugLog("%s", reason2text(fdwReason));
    if (fdwReason == DLL_PROCESS_ATTACH || fdwReason == DLL_PROCESS_DETACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkFunc, (LPVOID)(fdwReason), 0, NULL);
        // Sleep(2000);
    }
    return TRUE;
}