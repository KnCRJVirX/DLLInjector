# Windows DLL注入常用方法

## 远程线程法（最常见、最成熟）

给目标进程创建一个线程，利用LoadLibraryW只有一个参数的特点，将dll路径字符串作为创建线程参数传入，将线程开始执行的入口点设为LoadLibraryW的地址，即可加载dll

- 打开进程
    
    ```cpp
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    ```

- 给目标进程分配空间用于写入dll路径
    
    ```cpp
    size_t moduleNameSize = (wcslen(moduleName) + 2) * 2;
    LPVOID hRemoteMem = VirtualAllocEx(hProcess, NULL, moduleNameSize, MEM_COMMIT, PAGE_READWRITE);
    ```

- 写入dll路径字符串
    
    ```cpp
    WriteProcessMemory(hProcess, hRemoteMem, moduleName, moduleNameSize, NULL)
    ```

- 启动远程线程并等待完成
    
    ```cpp
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, hRemoteMem, 0, NULL);
    WaitForSingleObject(hRemoteThread, INFINITE);
    ```

- 释放内存，关闭句柄
    ```cpp
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, hRemoteMem, moduleNameSize, MEM_RELEASE);
    CloseHandle(hProcess);
    ```

## APC注入法

一种 **相对温和** 且 **不依赖远程线程创建** 的 DLL 注入技术。通过向目标线程的 **APC（Asynchronous Procedure Call）队列** 中插入一个函数指针（如 LoadLibraryW），当线程进入 **可警醒（alertable）** 状态 时，这个 APC 会被执行。

**可警醒（alertable）** 状态：调用 ```SleepEx``` , ```WaitForSingleObjectEx``` , ```MsgWaitForMultipleObjectsEx``` 等函数后的等待状态。

- 打开进程
    
    ```cpp
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    ```

- 给目标进程分配空间用于写入dll路径
    
    ```cpp
    size_t moduleNameSize = (wcslen(moduleName) + 2) * 2;
    LPVOID hRemoteMem = VirtualAllocEx(hProcess, NULL, moduleNameSize, MEM_COMMIT, PAGE_READWRITE);
    ```

- 写入dll路径字符串
    
    ```cpp
    WriteProcessMemory(hProcess, hRemoteMem, moduleName, moduleNameSize, NULL)
    ```

- 创建线程快照

    ```cpp
    HANDLE hAllThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processID);
    ```

- 枚举所有线程，当该线程属于目标进程时，注入APC

    ```cpp
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
    ```

- 关闭句柄

    ```cpp
    CloseHandle(hAllThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    ```