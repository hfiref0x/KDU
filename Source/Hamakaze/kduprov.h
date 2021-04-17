/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       KDUPROV.H
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
*
*  Provider support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define KDU_PROVIDER_INTEL_NAL          0
#define KDU_PROVIDER_UNWINDER_RTCORE    1
#define KDU_PROVIDER_GIGABYTE_GDRV      2
#define KDU_PROVIDER_ASUSTEK_ATSZIO     3
#define KDU_PROVIDER_PATRIOT_MSIO64     4
#define KDU_PROVIDER_GLCKIO2            5
#define KDU_PROVIDER_ENEIO64            6
#define KDU_PROVIDER_WINRING0           7
#define KDU_PROVIDER_ENETECHIO64        8
#define KDU_PROVIDER_PHYMEM64           9
#define KDU_PROVIDER_RTKIO64            10
#define KDU_PROVIDER_ENETECHIO64B       11

#define KDU_PROVIDER_DEFAULT            KDU_PROVIDER_INTEL_NAL

#define KDU_MIN_NTBUILDNUMBER       0x1DB1      //Windows 7 SP1
#define KDU_MAX_NTBUILDNUMBER       0xFFFFFFFF  //Undefined

//
// Providers abstraction interface.
//

//
// Prototype for read kernel virtual memory function.
//
typedef BOOL(WINAPI* provReadKernelVM)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// Prototype for write kernel virtual memory function.
//
typedef BOOL(WINAPI* provWriteKernelVM)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// Prototype for allocating kernel memory function.
//
typedef BOOL(WINAPI* provAllocateKernelVM)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG NumberOfBytes,
    _Out_ PVOID* Address);

//
// Prototype for freeing kernel memory function.
//
typedef BOOL(WINAPI* provFreeKernelVM)(
    _In_ HANDLE DeviceHandle,
    _Out_ PVOID Address);

//
// Prototype for virtual to physical address translation function.
//
typedef BOOL(WINAPI* provVirtualToPhysical)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

//
// Prototype for read physical memory function.
//
typedef BOOL(WINAPI* provReadPhysicalMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// Prototype for write physical memory function.
//
typedef BOOL(WINAPI* provWritePhysicalMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// Prototype for read CR registers function.
//
typedef BOOL(WINAPI* provReadControlRegister)(
    _In_ HANDLE DeviceHandle,
    _In_ UCHAR ControlRegister,
    _Out_ ULONG_PTR* Value);

//
// Prototype for query PML4 value function.
//
typedef BOOL(WINAPI* provQueryPML4)(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

//
// Prototype for driver registering/unlocking function.
//
typedef BOOL(WINAPI* provRegisterDriver)(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

//
// Prototype for driver unregistering function.
//
typedef BOOL(WINAPI* provUnregisterDriver)(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

//
// Prototype for driver specific pre-open actions.
//
typedef BOOL(WINAPI* provPreOpenDriver)(
    _In_opt_ PVOID Param
    );

//
// Prototype for driver specific post-open actions.
//
typedef BOOL(WINAPI* provPostOpenDriver)(
    _In_opt_ PVOID Param
    );

typedef enum _KDU_ACTION_TYPE {
    ActionTypeMapDriver = 0,
    ActionTypeDKOM = 1,
    ActionTypeDSECorruption = 2,
    ActionTypeUnspecified = 3,
    ActionTypeMax
} KDU_ACTION_TYPE;

//
// No optional provider flags specified, this is default value.
//
#define KDUPROV_FLAGS_NONE               0x00000000

//
// Provider does support HVCI security measures.
//
#define KDUPROV_FLAGS_SUPPORT_HVCI       0x00000001

//
// Provider is WHQL signed.
//
#define KDUPROV_FLAGS_SIGNATURE_WHQL     0x00000002 

//
// Provider has invalid checksum, so do not forceble check it.
// 
// Several valid signed Realtek drivers has invalid checksum set in their PE header.
// This flag will tell KDU to skip it checksum verification at loading stage.
// Note: Windows 7 does check driver checksum to be valid thus such drivers will fail to load here.
//
#define KDUPROV_FLAGS_IGNORE_CHECKSUM    0x00000004

//
// Do not set System/Admin-only security descriptor to the provider driver device.
//
#define KDUPROV_FLAGS_NO_FORCED_SD       0x00000008

typedef enum _KDU_SOURCEBASE {
    SourceBaseNone = 0,
    SourceBaseWinIo,
    SourceBaseWinRing0,
    SourceBasePhyMem,
    SourceBaseMapMem,
    SourceBaseMax
} KDU_SOURCEBASE;

typedef struct _KDU_PROVIDER {
    ULONG MinNtBuildNumberSupport;
    ULONG MaxNtBuildNumberSupport;
    ULONG ResourceId;
    KDU_SOURCEBASE DrvSourceBase;
    union {
        ULONG Flags;
        struct {
            ULONG SupportHVCI : 1;
            ULONG SignatureWHQL : 1;
            ULONG IgnoreChecksum : 1;
            ULONG NoForcedSD : 1;
            ULONG Reserved : 28;
        };
    };
    LPWSTR Desciption;
    LPWSTR DriverName; //only file name, e.g. PROCEXP152
    LPWSTR DeviceName; //device name, e.g. PROCEXP152
    LPWSTR SignerName;
    struct {
        provRegisterDriver RegisterDriver; //optional
        provUnregisterDriver UnregisterDriver; //optional
        provPreOpenDriver PreOpenDriver; //optional;
        provPostOpenDriver PostOpenDriver; //optional;

        provAllocateKernelVM AllocateKernelVM; //optional
        provFreeKernelVM FreeKernelVM; //optional

        provReadKernelVM ReadKernelVM;
        provWriteKernelVM WriteKernelVM;

        provVirtualToPhysical VirtualToPhysical; //optional
        provReadControlRegister ReadControlRegister; //optional

        provQueryPML4 QueryPML4Value; //optional
        provReadPhysicalMemory ReadPhysicalMemory; //optional
        provWritePhysicalMemory WritePhysicalMemory; //optional
    } Callbacks;
} KDU_PROVIDER, * PKDU_PROVIDER;

typedef struct _KDU_CONTEXT {
    ULONG HvciEnabled;
    ULONG NtBuildNumber;
    ULONG ShellVersion;
    union {
        ULONG EncryptKey;
        ULONG MemoryTag;
    };
    HINSTANCE ModuleBase;
    ULONG_PTR NtOsBase;
    HANDLE DeviceHandle;
    PWSTR DriverFileName; //full file name to the vulnerable driver
    ULONG_PTR MaximumUserModeAddress;
    PKDU_PROVIDER Provider;
    FIXED_UNICODE_STRING DriverObjectName;
    FIXED_UNICODE_STRING DriverRegistryPath;
} KDU_CONTEXT, * PKDU_CONTEXT;

ULONG KDUProvGetCount();
PKDU_PROVIDER KDUProvGetReference();
VOID KDUProvList();

BOOL WINAPI KDUProviderStub(
    VOID);

BOOL WINAPI KDUProviderPostOpen(
    _In_ PVOID Param);

BOOL WINAPI KDUVirtualToPhysical(
    _In_ KDU_CONTEXT* Context,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

_Success_(return != FALSE)
BOOL WINAPI KDUReadKernelVM(
    _In_ KDU_CONTEXT * Context,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI KDUWriteKernelVM(
    _In_ KDU_CONTEXT * Context,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KDUProviderStub(
    VOID);

HINSTANCE KDUProviderLoadDB(
    VOID);

PKDU_CONTEXT WINAPI KDUProviderCreate(
    _In_ ULONG ProviderId,
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ ULONG ShellCodeVersion,
    _In_ KDU_ACTION_TYPE ActionType);

VOID WINAPI KDUProviderRelease(
    _In_ KDU_CONTEXT * Context);
