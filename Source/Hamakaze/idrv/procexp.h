/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       PROCEXP.H
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  Process Explorer driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Process Explorer interface.
//

#define PROCEXP_DEVICE_TYPE (DWORD)0x8335

#define PROCEXP_FUNC_OPEN_PROCESS (DWORD)0xF
#define PROCEXP_FUNC_DUP_HANDLE (DWORD)0x5

#define IOCTL_PROCEXP_OPEN_PROCESS               \
    CTL_CODE(PROCEXP_DEVICE_TYPE, PROCEXP_FUNC_OPEN_PROCESS, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PROCEXP_DUPLICATE_HANDLE           \
    CTL_CODE(PROCEXP_DEVICE_TYPE, PROCEXP_FUNC_DUP_HANDLE, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PEXP_DUPLICATE_HANDLE_REQUEST {
    HANDLE UniqueProcessId;
    ULONG_PTR Unused0;
    ULONG_PTR Unused1;
    HANDLE SourceHandle;
} PEXP_DUPLICATE_HANDLE_REQUEST, * PPEXP_DUPLICATE_HANDLE_REQUEST;

BOOL WINAPI PexRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI PexpUnregisterDriver(
    _In_ HANDLE DeviceHandle);

BOOL WINAPI PexQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI PexVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI PexReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PexWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PexReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PexWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
