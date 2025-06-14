
# DLL Injector

简易DLL注入器，个人学习DLL注入原理用

## 编译（mingw-w64）
- 编译注入器
  ```
  gcc DLLInjector.c -lntdll -lkernel32 -luser32 -o DLLInjector.exe
  ```
- 编译DLL
  ```
  gcc -mwindows --shared -fPIE dlltest.c -o dlltest.dll
  ```

## 用法
### DLLInjector
```
DLLInjector.exe -im <ProcessName> -dll <DllFileFullPath>
```
或
```
DLLInjector.exe -pid <ProcessID> -dll <DllFileFullPath>
```

### CheckHide
```
CheckHide.exe <ProcessName> <DllName>
```

## 可选选项

### 注入方法

-  ```-rt``` RemoteThread 远程线程注入法，默认使用的方法，也是最成熟稳定的方法。

-  ```-apc``` QueueUserAPC APC队列注入法，**相对温和** 且 **不依赖远程线程创建**，向目标线程的 APC队列中插入函数指针```LoadLibraryW```，当线程进入可警醒状态（调用 ```SleepEx```, ```WaitForSingleObjectEx```, ```MsgWaitForMultipleObjectsEx``` 等）时，该APC会被执行。常用于GUI程序。

-  ```-hijcxt``` ThreadContextHijack 线程上下文劫持法，暂停目标线程，分配可执行空间写入shellcode，修改上下文运行shellcode加载模块，需要用```-thid <ThreadId>```指定线程ID

### 隐藏
- ```-hide``` 注入后遍历```InLoadOrderModuleList``` ```InMemoryOrderModuleList``` ```InInitializationOrderModuleList``` 三个链表，采用断链的方法隐藏注入的模块

## 文件夹中的其他文件

```winternals.h``` Windows内部常见结构体的完整定义，来自于**Duncan Ogilvie**的**Windows Internals Crash Course**的视频简介

```dlltest.c``` ```dlltest.h``` 注入后弹窗

```HideWindow.c``` 执行```SetWindowDisplayAffinity```函数，将目标进程的所有窗口在截屏/录屏时隐藏

```ShowWindow.c``` 执行```SetWindowDisplayAffinity```函数，将目标进程的所有窗口在截屏/录屏时显示
