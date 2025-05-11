#define UNICODE
#define _UNICODE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#define M_BUF_SIZ 65536
char gbk_buffer[M_BUF_SIZ];
char utf8_buffer[M_BUF_SIZ];
wchar_t utf16_buffer[M_BUF_SIZ];
wchar_t* utf8toutf16(const char* utf8text, wchar_t* utf16text, size_t utf16text_size)
{
    MultiByteToWideChar(CP_UTF8, 0, utf8text, -1, utf16text, utf16text_size);
    return utf16text;
}
char* utf16toutf8(const wchar_t* utf16text, char* utf8text, size_t utf8text_size)
{
    WideCharToMultiByte(CP_UTF8, 0, utf16text, -1, utf8text, utf8text_size, NULL, NULL);
    return utf8text;
}
char* utf8togbk(const char* utf8text, char* gbktext, size_t gbktext_size)
{
    wchar_t* utf16text = (wchar_t*)calloc((strlen(utf8text) + 1) * 2, sizeof(char));
    MultiByteToWideChar(CP_UTF8, 0, utf8text, -1, utf16text, (strlen(utf8text) + 1) * 2);
    WideCharToMultiByte(936, 0, utf16text, -1, gbktext, gbktext_size, NULL, NULL);
    free(utf16text);
    return gbktext;
}

// 使用进程名获取PID
DWORD GetProcessIdByName(const LPTSTR processName)
{
    // 对所有进程快照
    HANDLE hAllProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hAllProcess == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    TCHAR processNameUpr[MAX_PATH] = {0};
    TCHAR tmpProcessName[MAX_PATH] = {0};
    wcscpy(processNameUpr, processName);
    wcsupr(processNameUpr);
    
    // 遍历快照，找到进程名匹配的
    DWORD resultPID = 0;
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    if (!Process32First(hAllProcess, &pe))
    {
        return 0;
    }
    do
    {
        wcscpy(tmpProcessName, pe.szExeFile);
        wcsupr(tmpProcessName);
        if (!wcscmp(tmpProcessName, processNameUpr))
        {
            resultPID = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hAllProcess, &pe));
    
    CloseHandle(hAllProcess);
    return resultPID;
}

// 获取远程模块句柄
HMODULE GetRemoteModuleHandle(DWORD processId, const LPTSTR moduleName)
{
    // 对进程中所有模块快照
    HANDLE hAllModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hAllModule == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    TCHAR moduleNameUpr[MAX_PATH] = {0};
    TCHAR tmpModuleName[MAX_PATH] = {0};
    wcscpy(moduleNameUpr, moduleName);
    wcsupr(moduleNameUpr);
    
    // 遍历快照，找到模块名匹配的
    HMODULE resulthModule = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me = {0};
    me.dwSize = sizeof(me);
    if (!Module32First(hAllModule, &me))
    {
        CloseHandle(hAllModule);
        return NULL;
    }
    do
    {
        printf("From Process:%d Found module: %s\n", processId, utf16toutf8(me.szModule, utf8_buffer, M_BUF_SIZ));
        wcscpy(tmpModuleName, me.szModule);
        wcsupr(tmpModuleName);
        if (!wcscmp(tmpModuleName, moduleNameUpr))
        {
            resulthModule = me.hModule;
            break;
        }
    } while (Module32Next(hAllModule, &me));
    CloseHandle(hAllModule);
    
    return resulthModule;
}

// 获取远程模块函数地址
DWORD_PTR GetRemoteProcAddress(HMODULE hRemoteModuleHandle, LPCWSTR moduleName, LPCSTR procName)
{
    // 加载模块，获取函数地址
    HMODULE hModule = LoadLibraryW(moduleName);
    if (hModule == NULL)
    {
        return (DWORD_PTR)NULL;
    }
    FARPROC procAddr = GetProcAddress(hModule, procName);
    FreeLibrary(hModule);
    if (procAddr == NULL)
    {
        return (DWORD_PTR)NULL;
    }
    
    // 计算偏移量
    DWORD_PTR offset = (DWORD_PTR)procAddr - (DWORD_PTR)hModule;

    // 将偏移量加在基址（模块句柄）上返回
    return (DWORD_PTR)hRemoteModuleHandle + (DWORD_PTR)offset;
}

BOOL InjectModuleToProcessByRemoteThread(DWORD processID, PVOID pLoadLibraryW, LPCWSTR moduleName)
{
    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) goto err;

    // 分配空间用于写入dll路径
    size_t moduleNameSize = (wcslen(moduleName) + 2) * 2;
    LPVOID hRemoteMem = VirtualAllocEx(hProcess, NULL, moduleNameSize, MEM_COMMIT, PAGE_READWRITE);
    if (hRemoteMem == NULL) goto err;

    // 写入dll路径
    if (!WriteProcessMemory(hProcess, hRemoteMem, moduleName, moduleNameSize, NULL)) goto err;

    // 创建远程线程
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, hRemoteMem, 0, NULL);
    if (hRemoteThread == NULL) goto err;

    // 等待远程线程
    WaitForSingleObject(hRemoteThread, INFINITE);

    // 释放内存，关闭句柄
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;

    err:
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
}

BOOL InjectModuleToProcessByThreadHijack(DWORD processID, PVOID pLoadLibraryW, LPCWSTR moduleName)
{
    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) goto err;

    // 分配空间用于写入dll路径
    size_t moduleNameSize = (wcslen(moduleName) + 2) * 2;
    LPVOID hRemoteMem = VirtualAllocEx(hProcess, NULL, moduleNameSize, MEM_COMMIT, PAGE_READWRITE);
    if (hRemoteMem == NULL) goto err;

    // 写入dll路径
    if (!WriteProcessMemory(hProcess, hRemoteMem, moduleName, moduleNameSize, NULL)) goto err;

    // 对所有线程快照
    HANDLE hAllThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processID);
    if (hAllThread == NULL) goto err;
    
    // 遍历快照，找到PID匹配的，逐个劫持
    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    HANDLE hThread = NULL;
    if (!Thread32First(hAllThread, &te)) goto err;
    do
    {
        if (te.th32OwnerProcessID == processID)
        {
            // 打开线程
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (hThread == NULL) goto err;

            printf("Hijack thread: [%d]:[%d]\n", processID, te.th32ThreadID);

            // 暂停线程
            if (SuspendThread(hThread) == -1) goto err;
            CONTEXT cxt = {0};
            cxt.ContextFlags = CONTEXT_FULL;

            // 获取线程上下文
            GetThreadContext(hThread, &cxt);

            // 修改上下文
            cxt.Rcx = (DWORD64)hRemoteMem;
            cxt.Rip = (DWORD64)pLoadLibraryW;

            // 设置线程上下文
            SetThreadContext(hThread, &cxt);

            // 继续线程
            ResumeThread(hThread);

            // 关闭句柄
            CloseHandle(hThread);
        }
    } while (Thread32Next(hAllThread, &te));

    CloseHandle(hAllThread);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
    
    err:
    CloseHandle(hAllThread);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
}

BOOL InjectModuleToProcessByQueueUserAPC(DWORD processID, PVOID pLoadLibraryW, LPCWSTR moduleName)
{
    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) goto err;

    // 分配空间用于写入dll路径
    size_t moduleNameSize = (wcslen(moduleName) + 2) * 2;
    LPVOID hRemoteMem = VirtualAllocEx(hProcess, NULL, moduleNameSize, MEM_COMMIT, PAGE_READWRITE);
    if (hRemoteMem == NULL) goto err;

    // 写入dll路径
    if (!WriteProcessMemory(hProcess, hRemoteMem, moduleName, moduleNameSize, NULL)) goto err;

    // 对所有线程快照
    HANDLE hAllThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processID);
    if (hAllThread == NULL) goto err;
    
    // 遍历快照，找到PID匹配的，逐个劫持
    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    HANDLE hThread = NULL;
    if (!Thread32First(hAllThread, &te)) goto err;
    do
    {
        if (te.th32OwnerProcessID == processID)
        {
            // 打开线程
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (hThread == NULL) goto err;

            // 注入APC
            printf("Inject APC to thread: [%d]:[%d]\n", processID, te.th32ThreadID);
            QueueUserAPC((PAPCFUNC)pLoadLibraryW, hThread, (ULONG_PTR)hRemoteMem);

            // 关闭句柄
            CloseHandle(hThread);
        }
    } while (Thread32Next(hAllThread, &te));

    CloseHandle(hAllThread);
    CloseHandle(hThread);
    // VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
    
    err:
    CloseHandle(hAllThread);
    CloseHandle(hThread);
    // VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
}

typedef enum InjectMethod
{
    RemoteThread = 0,
    ThreadHijack = 1,
    InjectQueueUserAPC = 2
}InjectMethod;

static inline const char* InjectMethod2String(InjectMethod iMethod)
{
    switch (iMethod)
    {
    case RemoteThread:
        return "RemoteThread";
        break;
    case ThreadHijack:
        return "ThreadHijacking";
        break;
    case InjectQueueUserAPC:
        return "InjectQueueUserAPC";
        break;
    default:
        return "UnknownMethod";
        break;
    }
    return NULL;
}

int main(int argc, char const *argv[])
{
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    char processName[MAX_PATH] = {0};
    char dllpath[MAX_PATH] = {0};
    DWORD pid = 0;
    InjectMethod iMethod = RemoteThread;

    for (int i = 0; i < argc; i++)
    {
        if (!strcmp(argv[i], "-im"))
        { strcpy(processName, argv[++i]); }
        else if (!strcmp(argv[i], "-pid"))
        { sscanf(argv[++i], "%d", &pid); }
        else if (!strcmp(argv[i], "-dll"))
        { strcpy(dllpath, argv[++i]); }
        else if (!strcmp(argv[i], "-rt"))
        { iMethod = RemoteThread; }
        else if (!strcmp(argv[i], "-th"))
        { iMethod = ThreadHijack; }
        else if (!strcmp(argv[i], "-quapc"))
        { iMethod = InjectQueueUserAPC; }
    }

    if (processName[0] == '\0' && pid == 0)
    {
        printf("Process name: ");
        scanf("%s", processName);
    }

    if (dllpath[0] == '\0')
    {
        printf("DLL path: ");
        scanf("%s", dllpath);
    }
    
    if (pid == 0)
    {
        pid = GetProcessIdByName(utf8toutf16(processName, utf16_buffer, M_BUF_SIZ));
    }
    
    printf("Process ID: %d\n", pid);
    printf("Inject method: %s\n", InjectMethod2String(iMethod));

    HMODULE hRemoteKernel32 = GetRemoteModuleHandle(pid, TEXT("Kernel32.dll"));
    printf("[%s]:[Kernel32.dll] address: %p\n", processName, hRemoteKernel32);

    HMODULE (*pLoadLibraryW)(LPCWSTR) = (HMODULE(*)(LPCWSTR))GetRemoteProcAddress(hRemoteKernel32, TEXT("Kernel32.dll"), "LoadLibraryW");
    printf("[%s]:[Kernel32]:[LoadLibraryW] address: %p\n", processName, pLoadLibraryW);

    // HMODULE hKernel32 = GetModuleHandleW(TEXT("Kernel32.dll"));
    // LPVOID pLLW = GetProcAddress(hKernel32, "LoadLibraryW");
    // printf("[%d]:[Kernel32] address: %p\n", GetCurrentProcessId(), hKernel32);
    // printf("[%d]:[Kernel32]:[LoadLibraryW] address: %p\n", GetCurrentProcessId(), pLLW);

    BOOL retval = 0; 
    switch (iMethod)
    {
    case RemoteThread:
        retval = InjectModuleToProcessByRemoteThread(pid, pLoadLibraryW, utf8toutf16(dllpath, utf16_buffer, M_BUF_SIZ));
        break;
    case ThreadHijack:
        retval = InjectModuleToProcessByThreadHijack(pid, pLoadLibraryW, utf8toutf16(dllpath, utf16_buffer, M_BUF_SIZ));
        break;
    case InjectQueueUserAPC:
        retval = InjectModuleToProcessByQueueUserAPC(pid, pLoadLibraryW, utf8toutf16(dllpath, utf16_buffer, M_BUF_SIZ));
        break;
    default:
        break;
    }
    
    if (retval)
    {
        printf("Inject success!\n");
    }
    else
    {
        printf("Inject fail!\n");
    }
    
    return 0;
}
