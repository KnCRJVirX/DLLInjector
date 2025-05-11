#include "dlltest.h"

__declspec(dllexport) _stdcall long long sumReal(long long a, long long b)
{
    return a + b;
}

__declspec(dllexport) _stdcall ImgNumber sumImg(ImgNumber a, ImgNumber b)
{
    ImgNumber res;
    res.r = a.r + b.r;
    res.i = a.i + b.i;
    return res;
}

__declspec(dllexport) _stdcall void MyTestFunction()
{
    debugLog("Start");
    HANDLE hFile = CreateFileA("testfile.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        int size = GetFileSize(hFile, NULL);
        debugLog("testfile.txt %d bytes", size);
        CloseHandle(hFile);
    }
}

VOID WINAPI tls_callback(
    PVOID DllHandle,
    DWORD Reason,
    PVOID Reserved)
{
    debugLog("%s", reason2text(Reason));
}
// 注入TLS段
#pragma section(".CRT$XLB")
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;

VOID WorkFunc(LPVOID fdwReason)
{
    wchar_t tmpStr[1024] = {0};
    swprintf(tmpStr, 1024, L"进程ID: %u，线程ID：%u，事件：%s", GetCurrentProcessId(), GetCurrentThreadId(), reason2text((DWORD)fdwReason));
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
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkFunc, (LPVOID)fdwReason, 0, NULL);
    }
    return TRUE;
}