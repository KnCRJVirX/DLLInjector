#define UNICODE
#define _UNICODE

#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#include "Utils.h"
#include "Injector.hpp"

typedef enum InjectMethod
{
    RemoteThread = 0,
    ContextHijack = 1,
    InjectQueueUserAPC = 2,
    SelfLoad = 3
}InjectMethod;

static inline const char* InjectMethod2String(InjectMethod iMethod)
{
    switch (iMethod)
    {
    case RemoteThread:
        return "RemoteThread";
        break;
    case ContextHijack:
        return "ThreadHijacking";
        break;
    case InjectQueueUserAPC:
        return "InjectQueueUserAPC";
        break;
    case SelfLoad:
        return "SelfLoad";
        break;
    default:
        return "UnknownMethod";
        break;
    }
    return NULL;
}

int main(int argc, char const *argv[])
{
    UNICODE_INIT();

    char processName[MAX_PATH] = {0};
    char dllpath[MAX_PATH] = {0};
    WCHAR dllpathW[MAX_PATH] = {0};
    DWORD processId = 0, threadId = 0;
    bool hideModule = false;
    InjectMethod iMethod = RemoteThread;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-im")) {
            gbktoutf8(argv[++i], processName, MAX_PATH);
        }
        else if (!strcmp(argv[i], "-pid")) {
            sscanf(argv[++i], "%d", &processId);
        }
        else if (!strcmp(argv[i], "-thid")) {
            sscanf(argv[++i], "%d", &threadId);
        }
        else if (!strcmp(argv[i], "-dll")) {
            gbktoutf8(argv[++i], dllpath, MAX_PATH);
        }
        else if (!strcmp(argv[i], "-rt")) {
            iMethod = RemoteThread;
        }
        else if (!strcmp(argv[i], "-hijcxt")) {
            iMethod = ContextHijack;
        }
        else if (!strcmp(argv[i], "-apc")) {
            iMethod = InjectQueueUserAPC;
        }
        else if (!strcmp(argv[i], "-sl")) {
            iMethod = SelfLoad;
        }
        else if (!strcmp(argv[i], "-hide")) {
            hideModule = true; 
        }
    }

    if (processName[0] == '\0' && processId == 0) {
        printf("Process name: ");
        scanf("%s", processName);
    }

    if (dllpath[0] == '\0') {
        printf("DLL path: ");
        scanf("%s", dllpath);
    }
    utf8toutf16(dllpath, utf16_buffer, M_BUF_SIZ);
    GetFullPathNameW(utf16_buffer, MAX_PATH, dllpathW, NULL);
    
    if (processId == 0) {
        processId = GetProcessIdByName(utf8toutf16(processName, utf16_buffer, M_BUF_SIZ));
    }
    
    printf("Process ID: %d\n", processId);
    printf("Inject method: %s\n", InjectMethod2String(iMethod));

    HMODULE hRemoteKernel32 = GetRemoteModuleHandle(processId, TEXT("Kernel32.dll"));
    printf("[%s]:[Kernel32.dll] address: %p\n", processName, hRemoteKernel32);

    HMODULE (*pLoadLibraryW)(LPCWSTR) = (HMODULE(*)(LPCWSTR))GetRemoteProcAddress(hRemoteKernel32, TEXT("Kernel32.dll"), "LoadLibraryW");
    printf("[%s]:[Kernel32.dll]:[LoadLibraryW] address: %p\n", processName, pLoadLibraryW);

    // HMODULE hKernel32 = GetModuleHandleW(TEXT("Kernel32.dll"));
    // LPVOID pLLW = GetProcAddress(hKernel32, "LoadLibraryW");
    // printf("[%d]:[Kernel32.dll] address: %p\n", GetCurrentProcessId(), hKernel32);
    // printf("[%d]:[Kernel32.dll]:[LoadLibraryW] address: %p\n", GetCurrentProcessId(), pLLW);

    DWORD retval = 0;
    std::unique_ptr<Injector> injector;
    switch (iMethod) {
    case RemoteThread:{
        injector = std::make_unique<RemoteThreadInjector>(processId, dllpathW);
        break;
    }
    case ContextHijack:{
        if (threadId == 0) {
            std::cout << "Need: -thid <ThreadId>" << std::endl;
            return 1;
        }
        injector = std::make_unique<HijackContextInjector>(processId, dllpathW, threadId);
        break;
    }
    case InjectQueueUserAPC:{
        injector = std::make_unique<APCInjector>(processId, dllpathW);
        break;
    }
    default:
        break;
    }
    
    retval = injector->inject();
    if (retval)
    { std::cout << "Inject success!" << std::endl; }
    else
    { std::cout << "Inject fail!\n" << std::endl; }

    if (hideModule)
    {
        Hidder hidder{processId, dllpathW};
        retval = hidder.hide();
    }

    return 0;
}
