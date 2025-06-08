#ifndef DLLTEST
#define DLLTEST

#include <stdio.h>
#include <windows.h>

#include "Utils.h"

static inline char* reason2text(DWORD reason)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        return "DLL_PROCESS_ATTACH";
        break;
    case DLL_THREAD_ATTACH:
        return "DLL_THREAD_ATTACH";
        break;
    case DLL_THREAD_DETACH:
        return "DLL_THREAD_DETACH";
        break;
    case DLL_PROCESS_DETACH:
        return "DLL_PROCESS_DETACH";
        break;
    default:
        return "Unknown reason";
        break;
    }
}

#define __FILENAME__ ((strrchr(__FILE__, '\\')) ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define debugLog(fmt, ...) (printf("[%5u, %5u] [%s:%s]:" fmt "\n", GetCurrentProcessId(), GetCurrentThreadId(), __FILENAME__, __func__, ##__VA_ARGS__))

#endif