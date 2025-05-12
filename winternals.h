#include <stdint.h>

typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uint32_t DWORD;
typedef uint16_t USHORT;
typedef uint8_t UCHAR;

//0x10 bytes (sizeof)
struct _M128A
{
    ULONGLONG Low;                                                          //0x0
    LONGLONG High;                                                          //0x8
};

//0x200 bytes (sizeof)
struct _XSAVE_FORMAT
{
    USHORT ControlWord;                                                     //0x0
    USHORT StatusWord;                                                      //0x2
    UCHAR TagWord;                                                          //0x4
    UCHAR Reserved1;                                                        //0x5
    USHORT ErrorOpcode;                                                     //0x6
    ULONG ErrorOffset;                                                      //0x8
    USHORT ErrorSelector;                                                   //0xc
    USHORT Reserved2;                                                       //0xe
    ULONG DataOffset;                                                       //0x10
    USHORT DataSelector;                                                    //0x14
    USHORT Reserved3;                                                       //0x16
    ULONG MxCsr;                                                            //0x18
    ULONG MxCsr_Mask;                                                       //0x1c
    _M128A FloatRegisters[8];                                        //0x20
    _M128A XmmRegisters[16];                                         //0xa0
    UCHAR Reserved4[96];                                                    //0x1a0
};

struct XMMSTRUCT
{
    _M128A Header[2];                                        //0x100
    _M128A Legacy[8];                                        //0x120
    _M128A Xmm0;                                             //0x1a0
    _M128A Xmm1;                                             //0x1b0
    _M128A Xmm2;                                             //0x1c0
    _M128A Xmm3;                                             //0x1d0
    _M128A Xmm4;                                             //0x1e0
    _M128A Xmm5;                                             //0x1f0
    _M128A Xmm6;                                             //0x200
    _M128A Xmm7;                                             //0x210
    _M128A Xmm8;                                             //0x220
    _M128A Xmm9;                                             //0x230
    _M128A Xmm10;                                            //0x240
    _M128A Xmm11;                                            //0x250
    _M128A Xmm12;                                            //0x260
    _M128A Xmm13;                                            //0x270
    _M128A Xmm14;                                            //0x280
    _M128A Xmm15;                                            //0x290
};

union XMMUNION
{
    _XSAVE_FORMAT FltSave;                                       //0x100
    XMMSTRUCT Xmm;
};

//0x4d0 bytes (sizeof)
struct _CONTEXT
{
    ULONGLONG P1Home;                                                       //0x0
    ULONGLONG P2Home;                                                       //0x8
    ULONGLONG P3Home;                                                       //0x10
    ULONGLONG P4Home;                                                       //0x18
    ULONGLONG P5Home;                                                       //0x20
    ULONGLONG P6Home;                                                       //0x28
    ULONG ContextFlags;                                                     //0x30
    ULONG MxCsr;                                                            //0x34
    USHORT SegCs;                                                           //0x38
    USHORT SegDs;                                                           //0x3a
    USHORT SegEs;                                                           //0x3c
    USHORT SegFs;                                                           //0x3e
    USHORT SegGs;                                                           //0x40
    USHORT SegSs;                                                           //0x42
    ULONG EFlags;                                                           //0x44
    ULONGLONG Dr0;                                                          //0x48
    ULONGLONG Dr1;                                                          //0x50
    ULONGLONG Dr2;                                                          //0x58
    ULONGLONG Dr3;                                                          //0x60
    ULONGLONG Dr6;                                                          //0x68
    ULONGLONG Dr7;                                                          //0x70
    ULONGLONG Rax;                                                          //0x78
    ULONGLONG Rcx;                                                          //0x80
    ULONGLONG Rdx;                                                          //0x88
    ULONGLONG Rbx;                                                          //0x90
    ULONGLONG Rsp;                                                          //0x98
    ULONGLONG Rbp;                                                          //0xa0
    ULONGLONG Rsi;                                                          //0xa8
    ULONGLONG Rdi;                                                          //0xb0
    ULONGLONG R8;                                                           //0xb8
    ULONGLONG R9;                                                           //0xc0
    ULONGLONG R10;                                                          //0xc8
    ULONGLONG R11;                                                          //0xd0
    ULONGLONG R12;                                                          //0xd8
    ULONGLONG R13;                                                          //0xe0
    ULONGLONG R14;                                                          //0xe8
    ULONGLONG R15;                                                          //0xf0
    ULONGLONG Rip;                                                          //0xf8
    XMMUNION XmmUnion;
    _M128A VectorRegister[26];                                       //0x300
    ULONGLONG VectorControl;                                                //0x4a0
    ULONGLONG DebugControl;                                                 //0x4a8
    ULONGLONG LastBranchToRip;                                              //0x4b0
    ULONGLONG LastBranchFromRip;                                            //0x4b8
    ULONGLONG LastExceptionToRip;                                           //0x4c0
    ULONGLONG LastExceptionFromRip;                                         //0x4c8
};

struct _LIST_ENTRY   /* Size=0x10 */
{
    /* 0x0000 */ _LIST_ENTRY* Flink;
    /* 0x0008 */ _LIST_ENTRY* Blink;
};

struct _UNICODE_STRING   /* Size=0x10 */
{
    /* 0x0000 */ uint16_t Length;
    /* 0x0002 */ uint16_t MaximumLength;
    uint32_t Padding;
    /* 0x0008 */ wchar_t* Buffer;
};

struct _CURDIR   /* Size=0x18 */
{
    /* 0x0000 */ _UNICODE_STRING DosPath;
    /* 0x0010 */ void* Handle;
};

struct _STRING   /* Size=0x10 */
{
    /* 0x0000 */ uint16_t Length;
    /* 0x0002 */ uint16_t MaximumLength;
    uint32_t Padding;
    /* 0x0008 */ char* Buffer;
};

struct _RTL_DRIVE_LETTER_CURDIR   /* Size=0x18 */
{
    /* 0x0000 */ uint16_t Flags;
    /* 0x0002 */ uint16_t Length;
    /* 0x0004 */ uint32_t TimeStamp;
    /* 0x0008 */ _STRING DosPath;
};

struct _RTL_USER_PROCESS_PARAMETERS   /* Size=0x440 */
{
    /* 0x0000 */ uint32_t MaximumLength;
    /* 0x0004 */ uint32_t Length;
    /* 0x0008 */ uint32_t Flags;
    /* 0x000c */ uint32_t DebugFlags;
    /* 0x0010 */ void* ConsoleHandle;
    /* 0x0018 */ uint32_t ConsoleFlags;
    uint32_t Padding;
    /* 0x0020 */ void* StandardInput;
    /* 0x0028 */ void* StandardOutput;
    /* 0x0030 */ void* StandardError;
    /* 0x0038 */ _CURDIR CurrentDirectory;
    /* 0x0050 */ _UNICODE_STRING DllPath;
    /* 0x0060 */ _UNICODE_STRING ImagePathName;
    /* 0x0070 */ _UNICODE_STRING CommandLine;
    /* 0x0080 */ void* Environment;
    /* 0x0088 */ uint32_t StartingX;
    /* 0x008c */ uint32_t StartingY;
    /* 0x0090 */ uint32_t CountX;
    /* 0x0094 */ uint32_t CountY;
    /* 0x0098 */ uint32_t CountCharsX;
    /* 0x009c */ uint32_t CountCharsY;
    /* 0x00a0 */ uint32_t FillAttribute;
    /* 0x00a4 */ uint32_t WindowFlags;
    /* 0x00a8 */ uint32_t ShowWindowFlags;
    uint32_t Padding2;
    /* 0x00b0 */ _UNICODE_STRING WindowTitle;
    /* 0x00c0 */ _UNICODE_STRING DesktopInfo;
    /* 0x00d0 */ _UNICODE_STRING ShellInfo;
    /* 0x00e0 */ _UNICODE_STRING RuntimeData;
    /* 0x00f0 */ _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    /* 0x03f0 */ uint64_t EnvironmentSize;
    /* 0x03f8 */ uint64_t EnvironmentVersion;
    /* 0x0400 */ void* PackageDependencyData;
    /* 0x0408 */ uint32_t ProcessGroupId;
    /* 0x040c */ uint32_t LoaderThreads;
    /* 0x0410 */ _UNICODE_STRING RedirectionDllName;
    /* 0x0420 */ _UNICODE_STRING HeapPartitionName;
    /* 0x0430 */ uint64_t* DefaultThreadpoolCpuSetMasks;
    /* 0x0438 */ uint32_t DefaultThreadpoolCpuSetMaskCount;
    /* 0x043c */ uint32_t DefaultThreadpoolThreadMaximum;
};

struct _RTL_CRITICAL_SECTION_DEBUG   /* Size=0x30 */
{
    /* 0x0000 */ uint16_t Type;
    /* 0x0002 */ uint16_t CreatorBackTraceIndex;
    uint32_t Padding;
    /* 0x0008 */ _RTL_CRITICAL_SECTION* CriticalSection;
    /* 0x0010 */ _LIST_ENTRY ProcessLocksList;
    /* 0x0020 */ uint32_t EntryCount;
    /* 0x0024 */ uint32_t ContentionCount;
    /* 0x0028 */ uint32_t Flags;
    /* 0x002c */ uint16_t CreatorBackTraceIndexHigh;
    /* 0x002e */ uint16_t SpareUSHORT;
};

struct _LEAP_SECOND_DATA   /* Size=0x10 */
{
    /* 0x0000 */ unsigned char Enabled;
    /* 0x0004 */ uint32_t Count;
    /* 0x0008 */ _LARGE_INTEGER Data[1];
};

struct _PEB_LDR_DATA   /* Size=0x58 */
{
    /* 0x0000 */ uint32_t Length;
    /* 0x0004 */ unsigned char Initialized;
    unsigned char Padding[3];
    /* 0x0008 */ void* SsHandle;
    /* 0x0010 */ _LIST_ENTRY InLoadOrderModuleList;
    /* 0x0020 */ _LIST_ENTRY InMemoryOrderModuleList;
    /* 0x0030 */ _LIST_ENTRY InInitializationOrderModuleList;
    /* 0x0040 */ void* EntryInProgress;
    /* 0x0048 */ unsigned char ShutdownInProgress;
    unsigned char Padding2[3];
    /* 0x0050 */ void* ShutdownThreadId;
};

struct _RTL_CRITICAL_SECTION   /* Size=0x28 */
{
    /* 0x0000 */ _RTL_CRITICAL_SECTION_DEBUG* DebugInfo;
    /* 0x0008 */ int32_t LockCount;
    /* 0x000c */ int32_t RecursionCount;
    /* 0x0010 */ void* OwningThread;
    /* 0x0018 */ void* LockSemaphore;
    /* 0x0020 */ uint64_t SpinCount;
};

struct _unnamed_0x10db   /* Size=0x10 */
{
    uint64_t DepthDequence;
    uint64_t ReservedNextEntry;
};

struct _unnamed_0x1093   /* Size=0x8 */
{
    /* 0x0000 */ uint32_t LowPart;
    /* 0x0004 */ uint32_t HighPart;
};

struct _unnamed_0x108e   /* Size=0x8 */
{
    /* 0x0000 */ uint32_t LowPart;
    /* 0x0004 */ int32_t HighPart;
};

struct _unnamed_0x2000   /* Size=0x10 */
{
    /* 0x0000 */ uint64_t Alignment;
    /* 0x0008 */ uint64_t Region;
};

union _SLIST_HEADER   /* Size=0x10 */
{
    _unnamed_0x2000 AR;
    /* 0x0000 */ _unnamed_0x10db HeaderX64;
};

union _ULARGE_INTEGER   /* Size=0x8 */
{
    /* 0x0000 */ _unnamed_0x1093 u;
    /* 0x0000 */ uint64_t QuadPart;
};

union _LARGE_INTEGER   /* Size=0x8 */
{
    /* 0x0000 */ _unnamed_0x108e u;
    /* 0x0000 */ int64_t QuadPart;
};

struct _PEB   /* Size=0x7c8 */
{
    /* 0x0000 */ unsigned char InheritedAddressSpace;
    /* 0x0001 */ unsigned char ReadImageFileExecOptions;
    /* 0x0002 */ unsigned char BeingDebugged;
    /* 0x0003 */ unsigned char BitFieldFlags;
    /* 0x0004 */ unsigned char Padding0[4];
    /* 0x0008 */ void* Mutant;
    /* 0x0010 */ void* ImageBaseAddress;
    /* 0x0018 */ _PEB_LDR_DATA* Ldr;
    /* 0x0020 */ _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    /* 0x0028 */ void* SubSystemData;
    /* 0x0030 */ void* ProcessHeap;
    /* 0x0038 */ _RTL_CRITICAL_SECTION* FastPebLock;
    /* 0x0040 */ _SLIST_HEADER* AtlThunkSListPtr;
    /* 0x0048 */ void* IFEOKey;
    /* 0x0050 */ uint32_t CrossProcessFlags;
    /* 0x0054 */ unsigned char Padding1[4];
    /* 0x0058 */ void* KernelCallbackTable;
    /* 0x0060 */ uint32_t SystemReserved;
    /* 0x0064 */ uint32_t AtlThunkSListPtr32;
    /* 0x0068 */ void* ApiSetMap;
    /* 0x0070 */ uint32_t TlsExpansionCounter;
    /* 0x0074 */ unsigned char Padding2[4];
    /* 0x0078 */ void* TlsBitmap;
    /* 0x0080 */ uint32_t TlsBitmapBits[2];
    /* 0x0088 */ void* ReadOnlySharedMemoryBase;
    /* 0x0090 */ void* SharedData;
    /* 0x0098 */ void** ReadOnlyStaticServerData;
    /* 0x00a0 */ void* AnsiCodePageData;
    /* 0x00a8 */ void* OemCodePageData;
    /* 0x00b0 */ void* UnicodeCaseTableData;
    /* 0x00b8 */ uint32_t NumberOfProcessors;
    /* 0x00bc */ uint32_t NtGlobalFlag;
    /* 0x00c0 */ _LARGE_INTEGER CriticalSectionTimeout;
    /* 0x00c8 */ uint64_t HeapSegmentReserve;
    /* 0x00d0 */ uint64_t HeapSegmentCommit;
    /* 0x00d8 */ uint64_t HeapDeCommitTotalFreeThreshold;
    /* 0x00e0 */ uint64_t HeapDeCommitFreeBlockThreshold;
    /* 0x00e8 */ uint32_t NumberOfHeaps;
    /* 0x00ec */ uint32_t MaximumNumberOfHeaps;
    /* 0x00f0 */ void** ProcessHeaps;
    /* 0x00f8 */ void* GdiSharedHandleTable;
    /* 0x0100 */ void* ProcessStarterHelper;
    /* 0x0108 */ uint32_t GdiDCAttributeList;
    /* 0x010c */ unsigned char Padding3[4];
    /* 0x0110 */ _RTL_CRITICAL_SECTION* LoaderLock;
    /* 0x0118 */ uint32_t OSMajorVersion;
    /* 0x011c */ uint32_t OSMinorVersion;
    /* 0x0120 */ uint16_t OSBuildNumber;
    /* 0x0122 */ uint16_t OSCSDVersion;
    /* 0x0124 */ uint32_t OSPlatformId;
    /* 0x0128 */ uint32_t ImageSubsystem;
    /* 0x012c */ uint32_t ImageSubsystemMajorVersion;
    /* 0x0130 */ uint32_t ImageSubsystemMinorVersion;
    /* 0x0134 */ unsigned char Padding4[4];
    /* 0x0138 */ uint64_t ActiveProcessAffinityMask;
    /* 0x0140 */ uint32_t GdiHandleBuffer[60];
    /* 0x0230 */ void* PostProcessInitRoutine;
    /* 0x0238 */ void* TlsExpansionBitmap;
    /* 0x0240 */ uint32_t TlsExpansionBitmapBits[32];
    /* 0x02c0 */ uint32_t SessionId;
    /* 0x02c4 */ unsigned char Padding5[4];
    /* 0x02c8 */ _ULARGE_INTEGER AppCompatFlags;
    /* 0x02d0 */ _ULARGE_INTEGER AppCompatFlagsUser;
    /* 0x02d8 */ void* pShimData;
    /* 0x02e0 */ void* AppCompatInfo;
    /* 0x02e8 */ _UNICODE_STRING CSDVersion;
    /* 0x02f8 */ void* ActivationContextData;
    /* 0x0300 */ void* ProcessAssemblyStorageMap;
    /* 0x0308 */ void* SystemDefaultActivationContextData;
    /* 0x0310 */ void* SystemAssemblyStorageMap;
    /* 0x0318 */ uint64_t MinimumStackCommit;
    /* 0x0320 */ void* SparePointers[4];
    /* 0x0340 */ uint32_t SpareUlongs[5];
    uint32_t PaddingSpareUlongs;
    /* 0x0358 */ void* WerRegistrationData;
    /* 0x0360 */ void* WerShipAssertPtr;
    /* 0x0368 */ void* pUnused;
    /* 0x0370 */ void* pImageHeaderHash;
    /* 0x0378 */ uint32_t TracingFlags;
    /* 0x037c */ unsigned char Padding6[4];
    /* 0x0380 */ uint64_t CsrServerReadOnlySharedMemoryBase;
    /* 0x0388 */ uint64_t TppWorkerpListLock;
    /* 0x0390 */ _LIST_ENTRY TppWorkerpList;
    /* 0x03a0 */ void* WaitOnAddressHashTable[128];
    /* 0x07a0 */ void* TelemetryCoverageHeader;
    /* 0x07a8 */ uint32_t CloudFileFlags;
    /* 0x07ac */ uint32_t CloudFileDiagFlags;
    /* 0x07b0 */ char PlaceholderCompatibilityMode;
    /* 0x07b1 */ char PlaceholderCompatibilityModeReserved[7];
    /* 0x07b8 */ _LEAP_SECOND_DATA* LeapSecondData;
    /* 0x07c0 */ uint32_t LeapSecondFlags;
    /* 0x07c4 */ uint32_t NtGlobalFlag2;
};

struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME   /* Size=0x18 */
{
    /* 0x0000 */ _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    /* 0x0008 */ void* ActivationContext;
    /* 0x0010 */ uint32_t Flags;
};

struct _TEB_ACTIVE_FRAME_CONTEXT   /* Size=0x10 */
{
    /* 0x0000 */ uint32_t Flags;
    /* 0x0008 */ char* FrameName;
};

struct _GDI_TEB_BATCH   /* Size=0x4e8 */
{
    /* 0x0000 */ uint32_t Offset;
    uint32_t Padding;
    /* 0x0008 */ uint64_t HDC;
    /* 0x0010 */ uint32_t Buffer[310];
};

struct _ACTIVATION_CONTEXT_STACK   /* Size=0x28 */
{
    /* 0x0000 */ _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    /* 0x0008 */ _LIST_ENTRY FrameListCache;
    /* 0x0018 */ uint32_t Flags;
    /* 0x001c */ uint32_t NextCookieSequenceNumber;
    /* 0x0020 */ uint32_t StackId;
    uint32_t Padding;
};

struct _PROCESSOR_NUMBER   /* Size=0x4 */
{
    /* 0x0000 */ uint16_t Group;
    /* 0x0002 */ unsigned char Number;
    /* 0x0003 */ unsigned char Reserved;
};

struct _TEB_ACTIVE_FRAME   /* Size=0x18 */
{
    /* 0x0000 */ uint32_t Flags;
    uint32_t Padding;
    /* 0x0008 */ _TEB_ACTIVE_FRAME* Previous;
    /* 0x0010 */ _TEB_ACTIVE_FRAME_CONTEXT* Context;
};

struct _CLIENT_ID   /* Size=0x10 */
{
    /* 0x0000 */ void* UniqueProcess;
    /* 0x0008 */ void* UniqueThread;
};

struct _EXCEPTION_RECORD   /* Size=0x98 */
{
    /* 0x0000 */ int32_t ExceptionCode;
    /* 0x0004 */ uint32_t ExceptionFlags;
    /* 0x0008 */ _EXCEPTION_RECORD* ExceptionRecord;
    /* 0x0010 */ void* ExceptionAddress;
    /* 0x0018 */ uint32_t NumberParameters;
    uint32_t Padding;
    /* 0x0020 */ uint64_t ExceptionInformation[15];
};

struct _EXCEPTION_REGISTRATION_RECORD   /* Size=0x10 */
{
    /* 0x0000 */ _EXCEPTION_REGISTRATION_RECORD* Next;
    void* Handler;
};

struct CONTEXT_CHUNK
{
    LONG Offset;
    DWORD Length;
};

struct CONTEXT_EX
{
    //
    // The total length of the structure starting from the chunk with
    // the smallest offset. N.B. that the offset may be negative.
    //
    CONTEXT_CHUNK All;

    //
    // Wrapper for the traditional CONTEXT structure. N.B. the size of
    // the chunk may be less than sizeof(CONTEXT) is some cases (when
    // CONTEXT_EXTENDED_REGISTERS is not set on x86 for instance).
    CONTEXT_CHUNK Legacy;
    //

    // CONTEXT_XSTATE: Extended processor state chunk. The state is
    // stored in the same format XSAVE operation strores it with
    // exception of the first 512 bytes, i.e. staring from
    // XSAVE_AREA_HEADER. The lower two bits corresponding FP and
    // SSE state must be zero.
    CONTEXT_CHUNK XState;
};

struct _NT_TIB   /* Size=0x38 */
{
    /* 0x0000 */ _EXCEPTION_REGISTRATION_RECORD* ExceptionList;
    /* 0x0008 */ void* StackBase;
    /* 0x0010 */ void* StackLimit;
    /* 0x0018 */ void* SubSystemTib;
    /* 0x0020 */ void* FiberData;
    /* 0x0028 */ void* ArbitraryUserPointer;
    /* 0x0030 */ _NT_TIB* Self;
};

struct _GUID   /* Size=0x10 */
{
    /* 0x0000 */ uint32_t Data1;
    /* 0x0004 */ uint16_t Data2;
    /* 0x0006 */ uint16_t Data3;
    /* 0x0008 */ unsigned char Data4[8];
};

struct _TEB   /* Size=0x1838 */
{
    /* 0x0000 */ _NT_TIB NtTib;
    /* 0x0038 */ void* EnvironmentPointer;
    /* 0x0040 */ _CLIENT_ID ClientId;
    /* 0x0050 */ void* ActiveRpcHandle;
    /* 0x0058 */ void* ThreadLocalStoragePointer;
    /* 0x0060 */ _PEB* ProcessEnvironmentBlock;
    /* 0x0068 */ uint32_t LastErrorValue;
    /* 0x006c */ uint32_t CountOfOwnedCriticalSections;
    /* 0x0070 */ void* CsrClientThread;
    /* 0x0078 */ void* Win32ThreadInfo;
    /* 0x0080 */ uint32_t User32Reserved[26];
    /* 0x00e8 */ uint32_t UserReserved[5];
    uint32_t Padding;
    /* 0x0100 */ void* WOW32Reserved;
    /* 0x0108 */ uint32_t CurrentLocale;
    /* 0x010c */ uint32_t FpSoftwareStatusRegister;
    /* 0x0110 */ void* ReservedForDebuggerInstrumentation[16];
    /* 0x0190 */ void* SystemReserved1[30];
    /* 0x0280 */ char PlaceholderCompatibilityMode;
    /* 0x0281 */ unsigned char PlaceholderHydrationAlwaysExplicit;
    /* 0x0282 */ char PlaceholderReserved[10];
    /* 0x028c */ uint32_t ProxiedProcessId;
    /* 0x0290 */ _ACTIVATION_CONTEXT_STACK _ActivationStack;
    /* 0x02b8 */ unsigned char WorkingOnBehalfTicket[8];
    /* 0x02c0 */ int32_t ExceptionCode;
    /* 0x02c4 */ unsigned char Padding0[4];
    /* 0x02c8 */ _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    /* 0x02d0 */ uint64_t InstrumentationCallbackSp;
    /* 0x02d8 */ uint64_t InstrumentationCallbackPreviousPc;
    /* 0x02e0 */ uint64_t InstrumentationCallbackPreviousSp;
    /* 0x02e8 */ uint32_t TxFsContext;
    /* 0x02ec */ unsigned char InstrumentationCallbackDisabled;
    /* 0x02ed */ unsigned char UnalignedLoadStoreExceptions;
    /* 0x02ee */ unsigned char Padding1[2];
    /* 0x02f0 */ _GDI_TEB_BATCH GdiTebBatch;
    /* 0x07d8 */ _CLIENT_ID RealClientId;
    /* 0x07e8 */ void* GdiCachedProcessHandle;
    /* 0x07f0 */ uint32_t GdiClientPID;
    /* 0x07f4 */ uint32_t GdiClientTID;
    /* 0x07f8 */ void* GdiThreadLocalInfo;
    /* 0x0800 */ uint64_t Win32ClientInfo[62];
    /* 0x09f0 */ void* glDispatchTable[233];
    /* 0x1138 */ uint64_t glReserved1[29];
    /* 0x1220 */ void* glReserved2;
    /* 0x1228 */ void* glSectionInfo;
    /* 0x1230 */ void* glSection;
    /* 0x1238 */ void* glTable;
    /* 0x1240 */ void* glCurrentRC;
    /* 0x1248 */ void* glContext;
    /* 0x1250 */ uint32_t LastStatusValue;
    /* 0x1254 */ unsigned char Padding2[4];
    /* 0x1258 */ _UNICODE_STRING StaticUnicodeString;
    /* 0x1268 */ wchar_t StaticUnicodeBuffer[261];
    /* 0x1472 */ unsigned char Padding3[6];
    /* 0x1478 */ void* DeallocationStack;
    /* 0x1480 */ void* TlsSlots[64];
    /* 0x1680 */ _LIST_ENTRY TlsLinks;
    /* 0x1690 */ void* Vdm;
    /* 0x1698 */ void* ReservedForNtRpc;
    /* 0x16a0 */ void* DbgSsReserved[2];
    /* 0x16b0 */ uint32_t HardErrorMode;
    /* 0x16b4 */ unsigned char Padding4[4];
    /* 0x16b8 */ void* Instrumentation[11];
    /* 0x1710 */ _GUID ActivityId;
    /* 0x1720 */ void* SubProcessTag;
    /* 0x1728 */ void* PerflibData;
    /* 0x1730 */ void* EtwTraceData;
    /* 0x1738 */ void* WinSockData;
    /* 0x1740 */ uint32_t GdiBatchCount;
    /* 0x1744 */ _PROCESSOR_NUMBER CurrentIdealProcessor;
    /* 0x1748 */ uint32_t GuaranteedStackBytes;
    /* 0x174c */ unsigned char Padding5[4];
    /* 0x1750 */ void* ReservedForPerf;
    /* 0x1758 */ void* ReservedForOle;
    /* 0x1760 */ uint32_t WaitingOnLoaderLock;
    /* 0x1764 */ unsigned char Padding6[4];
    /* 0x1768 */ void* SavedPriorityState;
    /* 0x1770 */ uint64_t ReservedForCodeCoverage;
    /* 0x1778 */ void* ThreadPoolData;
    /* 0x1780 */ void** TlsExpansionSlots;
    /* 0x1788 */ void* DeallocationBStore;
    /* 0x1790 */ void* BStoreLimit;
    /* 0x1798 */ uint32_t MuiGeneration;
    /* 0x179c */ uint32_t IsImpersonating;
    /* 0x17a0 */ void* NlsCache;
    /* 0x17a8 */ void* pShimData;
    /* 0x17b0 */ uint32_t HeapData;
    /* 0x17b4 */ unsigned char Padding7[4];
    /* 0x17b8 */ void* CurrentTransactionHandle;
    /* 0x17c0 */ _TEB_ACTIVE_FRAME* ActiveFrame;
    /* 0x17c8 */ void* FlsData;
    /* 0x17d0 */ void* PreferredLanguages;
    /* 0x17d8 */ void* UserPrefLanguages;
    /* 0x17e0 */ void* MergedPrefLanguages;
    /* 0x17e8 */ uint32_t MuiImpersonation;
    /* 0x17ec */ uint16_t CrossTebFlags;
    /* 0x17ee */ uint16_t SameTebFlags;
    /* 0x17f0 */ void* TxnScopeEnterCallback;
    /* 0x17f8 */ void* TxnScopeExitCallback;
    /* 0x1800 */ void* TxnScopeContext;
    /* 0x1808 */ uint32_t LockCount;
    /* 0x180c */ int32_t WowTebOffset;
    /* 0x1810 */ void* ResourceRetValue;
    /* 0x1818 */ void* ReservedForWdf;
    /* 0x1820 */ uint64_t ReservedForCrt;
    /* 0x1828 */ _GUID EffectiveContainerId;
};

struct _XSTATE_FEATURE   /* Size=0x8 */
{
    /* 0x0000 */ uint32_t Offset;
    /* 0x0004 */ uint32_t Size;
};

struct _XSTATE_CONFIGURATION   /* Size=0x338 */
{
    /* 0x0000 */ uint64_t EnabledFeatures;
    /* 0x0008 */ uint64_t EnabledVolatileFeatures;
    /* 0x0010 */ uint32_t Size;
    /* 0x0014 */ uint32_t ControlFlags;
    /* 0x0018 */ _XSTATE_FEATURE Features[64];
    /* 0x0218 */ uint64_t EnabledSupervisorFeatures;
    /* 0x0220 */ uint64_t AlignedFeatures;
    /* 0x0228 */ uint32_t AllFeatureSize;
    /* 0x022c */ uint32_t AllFeatures[64];
    uint32_t Padding;
    /* 0x0330 */ uint64_t EnabledUserVisibleSupervisorFeatures;
};

struct _KSYSTEM_TIME   /* Size=0xc */
{
    /* 0x0000 */ uint32_t LowPart;
    /* 0x0004 */ int32_t High1Time;
    /* 0x0008 */ int32_t High2Time;
};

struct _KUSER_SHARED_DATA   /* Size=0x720 */
{
    /* 0x0000 */ uint32_t TickCountLowDeprecated;
    /* 0x0004 */ uint32_t TickCountMultiplier;
    /* 0x0008 */ _KSYSTEM_TIME InterruptTime;
    /* 0x0014 */ _KSYSTEM_TIME SystemTime;
    /* 0x0020 */ _KSYSTEM_TIME TimeZoneBias;
    /* 0x002c */ uint16_t ImageNumberLow;
    /* 0x002e */ uint16_t ImageNumberHigh;
    /* 0x0030 */ wchar_t NtSystemRoot[260];
    /* 0x0238 */ uint32_t MaxStackTraceDepth;
    /* 0x023c */ uint32_t CryptoExponent;
    /* 0x0240 */ uint32_t TimeZoneId;
    /* 0x0244 */ uint32_t LargePageMinimum;
    /* 0x0248 */ uint32_t AitSamplingValue;
    /* 0x024c */ uint32_t AppCompatFlag;
    /* 0x0250 */ uint64_t RNGSeedVersion;
    /* 0x0258 */ uint32_t GlobalValidationRunlevel;
    /* 0x025c */ int32_t TimeZoneBiasStamp;
    /* 0x0260 */ uint32_t NtBuildNumber;
    /* 0x0264 */ int32_t NtProductType;
    /* 0x0268 */ unsigned char ProductTypeIsValid;
    /* 0x0269 */ unsigned char Reserved0[1];
    /* 0x026a */ uint16_t NativeProcessorArchitecture;
    /* 0x026c */ uint32_t NtMajorVersion;
    /* 0x0270 */ uint32_t NtMinorVersion;
    /* 0x0274 */ unsigned char ProcessorFeatures[64];
    /* 0x02b4 */ uint32_t Reserved1;
    /* 0x02b8 */ uint32_t Reserved3;
    /* 0x02bc */ uint32_t TimeSlip;
    /* 0x02c0 */ int32_t AlternativeArchitecture;
    /* 0x02c4 */ uint32_t BootId;
    /* 0x02c8 */ _LARGE_INTEGER SystemExpirationDate;
    /* 0x02d0 */ uint32_t SuiteMask;
    /* 0x02d4 */ unsigned char KdDebuggerEnabled;
    /* 0x02d5 */ unsigned char MitigationPolicies;
    /* 0x02d6 */ uint16_t CyclesPerYield;
    /* 0x02d8 */ uint32_t ActiveConsoleId;
    /* 0x02dc */ uint32_t DismountCount;
    /* 0x02e0 */ uint32_t ComPlusPackage;
    /* 0x02e4 */ uint32_t LastSystemRITEventTickCount;
    /* 0x02e8 */ uint32_t NumberOfPhysicalPages;
    /* 0x02ec */ unsigned char SafeBootMode;
    /* 0x02ed */ unsigned char VirtualizationFlags;
    /* 0x02ee */ unsigned char Reserved12[2];
    /* 0x02f0 */ uint32_t SharedDataFlags;
    /* 0x02f4 */ uint32_t DataFlagsPad[1];
    /* 0x02f8 */ uint64_t TestRetInstruction;
    /* 0x0300 */ int64_t QpcFrequency;
    /* 0x0308 */ uint32_t SystemCall;
    /* 0x030c */ uint32_t Reserved2;
    /* 0x0310 */ uint64_t SystemCallPad[2];
    /* 0x0320 */ _KSYSTEM_TIME TickCount;
    /* 0x032c */ uint32_t TickCountPad[1];
    /* 0x0330 */ uint32_t Cookie;
    /* 0x0334 */ uint32_t CookiePad[1];
    /* 0x0338 */ int64_t ConsoleSessionForegroundProcessId;
    /* 0x0340 */ uint64_t TimeUpdateLock;
    /* 0x0348 */ uint64_t BaselineSystemTimeQpc;
    /* 0x0350 */ uint64_t BaselineInterruptTimeQpc;
    /* 0x0358 */ uint64_t QpcSystemTimeIncrement;
    /* 0x0360 */ uint64_t QpcInterruptTimeIncrement;
    /* 0x0368 */ unsigned char QpcSystemTimeIncrementShift;
    /* 0x0369 */ unsigned char QpcInterruptTimeIncrementShift;
    /* 0x036a */ uint16_t UnparkedProcessorCount;
    /* 0x036c */ uint32_t EnclaveFeatureMask[4];
    /* 0x037c */ uint32_t TelemetryCoverageRound;
    /* 0x0380 */ uint16_t UserModeGlobalLogger[16];
    /* 0x03a0 */ uint32_t ImageFileExecutionOptions;
    /* 0x03a4 */ uint32_t LangGenerationCount;
    /* 0x03a8 */ uint64_t Reserved4;
    /* 0x03b0 */ uint64_t InterruptTimeBias;
    /* 0x03b8 */ uint64_t QpcBias;
    /* 0x03c0 */ uint32_t ActiveProcessorCount;
    /* 0x03c4 */ unsigned char ActiveGroupCount;
    /* 0x03c5 */ unsigned char Reserved9;
    /* 0x03c6 */ uint16_t QpcData;
    /* 0x03c8 */ _LARGE_INTEGER TimeZoneBiasEffectiveStart;
    /* 0x03d0 */ _LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    /* 0x03d8 */ _XSTATE_CONFIGURATION XState;
    /* 0x0710 */ _KSYSTEM_TIME FeatureConfigurationChangeStamp;
    /* 0x071c */ uint32_t Spare;
};