/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020 gruf0x
*
*  TITLE:       KDUPROV.H
*
*  VERSION:     1.00
*
*  DATE:        07 Feb 2020
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

#define KDU_PROVIDERS_MAX               5

#define KDU_PROVIDER_INTEL_NAL          0
#define KDU_PROVIDER_UNWINDER_RTCORE    1
#define KDU_PROVIDER_GIGABYTE_GDRV      2
#define KDU_PROVIDER_ASUSTEK_ATSZIO     3
#define KDU_PROVIDER_PATRIOT_MSIO64     4

#define KDU_PROVIDER_DEFAULT        KDU_PROVIDER_INTEL_NAL

#define KDU_MAX_NTBUILDNUMBER       0xFFFFFFFF

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
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
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
    _In_ HANDLE DeviceHandle);

//
// Prototype for driver unregistering function.
//
typedef BOOL(WINAPI* provUnregisterDriver)(
    _In_ HANDLE DeviceHandle);

typedef enum _KDU_ACTION_TYPE {
    ActionTypeMapDriver = 0,
    ActionTypeDKOM = 1,
    ActionTypeUnspecified = 2,
    ActionTypeMax
} KDU_ACTION_TYPE;

typedef struct _KDU_PROVIDER {
    ULONG MaxNtBuildNumberSupport;
    ULONG ResourceId;
    union {
        ULONG Flags;
        struct {
            ULONG SupportHVCI : 1;
            ULONG SignatureWHQL : 1;
            ULONG Reserved : 30;
        };
    };
    LPWSTR Desciption;
    LPWSTR DriverName; //only file name, e.g. PROCEXP152
    LPWSTR DeviceName; //device name, e.g. PROCEXP152
    struct {
        provReadKernelVM ReadKernelVM;
        provWriteKernelVM WriteKernelVM;
        provVirtualToPhysical VirtualToPhysical; //optional
        provReadControlRegister ReadControlRegister; //optional
        provQueryPML4 QueryPML4Value; //optional
        provReadPhysicalMemory ReadPhysicalMemory; //optional
        provWritePhysicalMemory WritePhysicalMemory; //optional
        provRegisterDriver RegisterDriver; //optional
        provUnregisterDriver UnregisterDriver; //optional
    } Callbacks;
} KDU_PROVIDER, * PKDU_PROVIDER;

typedef struct _KDU_CONTEXT {
    ULONG HvciEnabled;
    ULONG NtBuildNumber;
    HINSTANCE ModuleBase;
    ULONG_PTR NtOsBase;
    HANDLE DeviceHandle;
    PWSTR DriverFileName; //full file name to the vulnerable driver
    ULONG_PTR MaximumUserModeAddress;
    PKDU_PROVIDER Provider;
} KDU_CONTEXT, * PKDU_CONTEXT;

VOID KDUProvList();

BOOL WINAPI KDUProviderStub(
    VOID);

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

PKDU_CONTEXT WINAPI KDUProviderCreate(
    _In_ ULONG ProviderId,
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ HINSTANCE ModuleBase,
    _In_ KDU_ACTION_TYPE ActionType);

VOID WINAPI KDUProviderRelease(
    _In_ KDU_CONTEXT * Context);
