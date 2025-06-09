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

## 线程上下文劫持+Shellcode

- 打开进程    
    ```cpp
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    ```

- 给目标进程分配空间用于写入dll路径
    
    ```cpp
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, (dllPath.length() + 2) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
    ```

- 写入dll路径字符串
    
    ```cpp
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.data(), (dllPath.length() + 1) * sizeof(WCHAR), NULL)) {
            VirtualFreeEx(hProcess, remoteMem, (dllPath.length() + 2) * sizeof(WCHAR), MEM_RELEASE);
            return false;
        }
    ```

- 创建线程快照

    ```cpp
    HANDLE hAllThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processID);
    ```

- 打开目标线程
    ```cpp
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
    ```

- 暂停线程
    ```cpp
    SuspendThread(hThread);
    ```

- 读取线程上下文
    ```cpp
    CONTEXT cxt = {0};
    cxt.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &cxt);
    ```

- 判断是否需要对齐
    ```cpp
    bool needAlign = false;
    if (cxt.Rip % 16 == 0) {
        needAlign = true;
    }
    ```

    根据Windows x64调用约定：
    - ```rsp```要16字节对齐
    - 整数参数在寄存器 RCX、RDX、R8 和 R9 中传递。 浮点数参数在 XMM0L、XMM1L、XMM2L 和 XMM3L 中传递。 16 字节参数按引用传递。
    - 这些寄存器以及 RAX、R10、R11、XMM4 和 XMM5 被视为易变，可能在返回时由被调用方修改。

    由于后面要向栈中压入RCX, RDX, R8, R9, R10, R11 6个寄存器，call时还要压入一个RBP，故如果原来已经对齐，则要压下6个寄存器后手动进行```sub rsp, 8```


- 构造Shellcode

    | 汇编 | 机器码 |
    |------|-------|
    | ```push rcx``` | ```0x51``` |
    | ```push rdx``` | ```0x52``` |
    | ```push r8```  | ```0x41 0x50``` |
    | ```push r9```  | ```0x41 0x51``` |
    | ```push r10```  | ```0x41 0x52``` |
    | ```push r11```  | ```0x41 0x53``` |
    | ```mov rcx, remoteMem``` | ```0x48 0xB9 remoteMem``` |
    | ```mov rax, pLoadLibraryW``` | ```0x48 0xB8 pLoadLibraryW``` |
    | ```sub rsp, 8``` | ```0x48 0x83 0xEC 0x08``` |
    | ```call rax``` | ```0xFF 0xD0``` |
    | ```add rsp, 8``` | ```0x48 0x83 0xC4 0x08``` |
    | ```pop r11```  | ```0x41 0x5B``` |
    | ```pop r10```  | ```0x41 0x5A``` |
    | ```pop r9```  | ```0x41 0x59``` |
    | ```pop r8```  | ```0x41 0x58``` |
    | ```pop rdx``` | ```0x5A``` |
    | ```pop rcx``` | ```0x59``` |
    | ```mov rax, oldRip``` | ```0x48 0xB8 oldRip``` |
    | ```jmp rax``` | ```0xFF 0xE0``` |

    ```cpp
    std::vector<unsigned char> shellcode;
    // push rcx, rdx, r8 ~ r11
    unsigned char pushes[] = {0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53};
    for (int i = 0; i < sizeof(pushes) / pushes[0]; ++i) {
        shellcode.push_back(pushes[i]);
    }
    // mov rcx, remoteMem
    shellcode.push_back(0x48);
    shellcode.push_back(0xB9);
    for (int i = 0; i < sizeof(void*); ++i) {
        shellcode.push_back(*((unsigned char*)&remoteMem + i));
    }
    // mov rax, pLoadLibraryW
    shellcode.push_back(0x48);
    shellcode.push_back(0xB8);
    for (int i = 0; i < sizeof(void*); ++i) {
        shellcode.push_back(*((unsigned char*)&pLoadLibraryW + i));
    }
    // sub rsp, 8 栈对齐
    if (needAlign) {
        shellcode.push_back(0x48);
        shellcode.push_back(0x83);
        shellcode.push_back(0xEC);
        shellcode.push_back(0x08);
    }
    // call rax
    shellcode.push_back(0xFF);
    shellcode.push_back(0xD0);
    // add rsp, 8
    if (needAlign) {
        shellcode.push_back(0x48);
        shellcode.push_back(0x83);
        shellcode.push_back(0xC4);
        shellcode.push_back(0x08);
    }
    // pop r11 ~ r8, rdx, rcx
    unsigned char pops[] = {0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59};
    for (int i = 0; i < sizeof(pops) / pops[0]; ++i) {
        shellcode.push_back(pops[i]);
    }
    // mov rax, oldRip
    shellcode.push_back(0x48);
    shellcode.push_back(0xB8);
    for (int i = 0; i < sizeof(void*); ++i) {
        shellcode.push_back(*((unsigned char*)&cxt.Rip + i));
    }
    // jmp rax
    shellcode.push_back(0xFF);
    shellcode.push_back(0xE0);
    ```

- 分配可执行内存空间，写入shellcode

    ```cpp
    LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteShellcode, shellcode.data(), shellcode.size(), NULL);
    ```

- 修改线程Rip为shellcode的地址并写回
    ```cpp
    cxt.Rip = (DWORD64)remoteShellcode;
    SetThreadContext(hThread, &cxt);
    ```

- 恢复线程执行
    ```cpp
    ResumeThread(hThread);
    ```

- 关闭句柄
    ```cpp
    CloseHandle(hThread);
    CloseHandle(hAllThread);
    ```