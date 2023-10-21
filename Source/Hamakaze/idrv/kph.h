/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       KPH.H
*
*  VERSION:     1.40
*
*  DATE:        20 Oct 2023
*
*  KProcessHacker2 driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define KPH_DEVICE_TYPE (DWORD)0x9999

#define KPH_FUNCID_OPENPROCESS (DWORD)0x832
#define KPH_FUNCID_DUPLICATEOBJECT (DWORD)0x899

#define IOCTL_KPH_OPENPROCESS    \
    CTL_CODE(KPH_DEVICE_TYPE, KPH_FUNCID_OPENPROCESS, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_KPH_DUPOBJECT      \
    CTL_CODE(KPH_DEVICE_TYPE, KPH_FUNCID_DUPLICATEOBJECT, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _KPH_OPEN_PROCESS_REQUEST {
    PHANDLE ProcessHandle;
    ACCESS_MASK DesiredAccess;
    PCLIENT_ID ClientId;
} KPH_OPEN_PROCESS_REQUEST, * PKPH_OPEN_PROCESS_REQUEST;

typedef struct _KPH_DUPLICATE_OBJECT_REQUEST {
    HANDLE SourceProcessHandle;
    HANDLE SourceHandle;
    HANDLE TargetProcessHandle;
    PHANDLE TargetHandle;
    ACCESS_MASK DesiredAccess;
    ULONG HandleAttributes;
    ULONG Options;
} KPH_DUPLICATE_OBJECT_REQUEST, * PKPH_DUPLICATE_OBJECT_REQUEST;

BOOL WINAPI KphRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI KphUnregisterDriver(
    _In_ HANDLE DeviceHandle);

BOOL WINAPI KphQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI KphVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI KphReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KphWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KphReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KphWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KphOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);
