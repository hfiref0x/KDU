/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2025
*
*  TITLE:       KDUPROV.H
*
*  VERSION:     1.44
*
*  DATE:        18 Aug 2025
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
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

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

//
// Start/Stop prototypes.
//
typedef BOOL(WINAPI* provStartVulnerableDriver)(
    _In_ struct _KDU_CONTEXT* Context
    );
typedef void(WINAPI* provStopVulnerableDriver)(
    _In_ struct _KDU_CONTEXT* Context
    );

//
// Control DSE callback prototype
//
typedef BOOL(WINAPI* provControlDSE)(
    _In_ struct _KDU_CONTEXT* Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address
    );

//
// Prototype for driver mapping action.
//
typedef BOOL(WINAPI* provMapDriver)(
    _In_ struct _KDU_CONTEXT *Context,
    _In_ PVOID ImageBase
    );

//
// Prototype for driver prerequisites validator.
//
typedef BOOL(WINAPI* provValidatePrerequisites)(
    _In_ struct _KDU_CONTEXT* Context
    );

//
// Prototype for process handle acquisition.
//
typedef BOOL(WINAPI* provOpenProcess)(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
    );

typedef enum _KDU_ACTION_TYPE {
    ActionTypeMapDriver = 0,
    ActionTypeDKOM,
    ActionTypeDSECorruption,
    ActionTypeDumpProcess,
    ActionTypeUnspecified,
    ActionTypeMax
} KDU_ACTION_TYPE;

typedef enum _KDU_PROVIDER_STATE {
    StateUnloaded = 0,
    StateLoaded,
    StateMax
} KDU_PROVIDER_STATE;

typedef struct _KDU_PROVIDER {
    PKDU_DB_ENTRY LoadData;
    struct {
        provStartVulnerableDriver StartVulnerableDriver;
        provStopVulnerableDriver StopVulnerableDriver;

        provRegisterDriver RegisterDriver; //optional
        provUnregisterDriver UnregisterDriver; //optional
        provPreOpenDriver PreOpenDriver; //optional;
        provPostOpenDriver PostOpenDriver; //optional;
        provMapDriver MapDriver;
        provControlDSE ControlDSE;

        provReadKernelVM ReadKernelVM; //optional
        provWriteKernelVM WriteKernelVM; //optional

        provVirtualToPhysical VirtualToPhysical; //optional
        provQueryPML4 QueryPML4Value; //optional
        provReadPhysicalMemory ReadPhysicalMemory; //optional
        provWritePhysicalMemory WritePhysicalMemory; //optional

        provValidatePrerequisites ValidatePrerequisites; //optional

        provOpenProcess OpenProcess; //optional

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
    
    // DB image base
    HINSTANCE ModuleBase;

    ULONG_PTR NtOsBase;
    ULONG_PTR NtOsMappedBase;
    union {
        HANDLE DeviceHandle;
        HANDLE PortHandle;
    };

    //full file name to the vulnerable driver
    PWSTR DriverFileName; 

    ULONG_PTR MaximumUserModeAddress;
    PKDU_PROVIDER Provider;
    PKDU_VICTIM_PROVIDER Victim;
    KDU_PROVIDER_STATE ProviderState;

    //fields used by shellcode v3 only
    FIXED_UNICODE_STRING DriverObjectName;
    FIXED_UNICODE_STRING DriverRegistryPath;

    //other
    ULONG64 ArbitraryData;

} KDU_CONTEXT, * PKDU_CONTEXT;

typedef struct _KDU_PHYSMEM_ENUM_PARAMS {
    _In_ BOOL bWrite;

    _In_ HANDLE DeviceHandle;
    _In_ provReadPhysicalMemory ReadPhysicalMemory;
    _In_ provWritePhysicalMemory WritePhysicalMemory;

    _In_opt_ PVOID pvPayload;
    _In_opt_ ULONG cbPayload;

    _Out_ SIZE_T ccPagesFound;
    _Out_ SIZE_T ccPagesModified;

    _In_ ULONG DispatchHandlerOffset;
    _In_ ULONG DispatchHandlerPageOffset;
    _In_ PVOID DispatchSignature;
    _In_ ULONG DispatchSignatureLength;
    _In_ ULONG JmpAddress;

} KDU_PHYSMEM_ENUM_PARAMS, * PKDU_PHYSMEM_ENUM_PARAMS;

ULONG KDUProvGetCount();
PKDU_DB KDUReferenceLoadDB();
VOID KDUProvList();

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

_Success_(return != FALSE)
BOOL WINAPI KDUOpenProcess(
    _In_ struct _KDU_CONTEXT* Context,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);

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

void KDUProvOpenVulnerableDriverAndRunCallbacks(
    _In_ KDU_CONTEXT* Context);

BOOL KDUProvLoadVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

BOOL KDUProvExtractVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

BOOL KDUProvStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

void KDUProvStopVulnerableDriver(
    _In_ KDU_CONTEXT* Context);
