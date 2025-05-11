
# DLL Injector

简易DLL注入器，个人学习DLL注入原理用

## 编译（mingw-w64）
编译注入器：
```
gcc DLLInjector.c -lkernel32 -luser32 -o DLLInjector.exe
```
编译DLL：
```
gcc -mwindows --shared -fPIE dlltest.c -o dlltest.dll
```

## 使用

用法：
```
DLLInjector.exe -im <ProcessName> -dll <DllFileFullPath>
```
或
```
DLLInjector.exe -pid <ProcessID> -dll <DllFileFullPath>
```

## 可选选项

-  ```-rt``` RemoteThread 远程线程注入法，默认使用的方法，也是最成熟稳定的方法。
-  ```-th``` ThreadHijack 线程劫持法，暂停进程下的所有线程并修改上下文以加载模块，最不稳定的方法，容易注入即崩溃。
-  ```-quapc``` QueueUserAPC APC队列注入法，**相对温和** 且 **不依赖远程线程创建**，向目标线程的 APC队列中插入函数指针```LoadLibraryW```，当线程进入可警醒状态（调用 ```SleepEx```, ```WaitForSingleObjectEx```, ```MsgWaitForMultipleObjectsEx``` 等）时，该APC会被执行。常用于GUI程序。

## 文件夹中的其他文件（用于测试）

```dlltest.c dlltest.h dlltest.dll``` 注入后弹窗

```HideWindow.c HideWindow.dll``` 执行```SetWindowDisplayAffinity```函数，将目标进程的所有窗口在截屏/录屏时隐藏

```ShowWindow.c ShowWindow.dll``` 执行```SetWindowDisplayAffinity```函数，将目标进程的所有窗口在截屏/录屏时显示
