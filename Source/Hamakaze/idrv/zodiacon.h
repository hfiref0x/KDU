/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ZODIACON.H
*
*  VERSION:     1.32
*
*  DATE:        10 Jun 2023
*
*  Zodiacon drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define ZODIACON_DEVICE (DWORD)0x8000

#define ZODIACON_DUP_HANDLE (DWORD)0x801

#define IOCTL_KANYEXP_DUPLICATE_OBJECT \
    CTL_CODE(ZODIACON_DEVICE, ZODIACON_DUP_HANDLE, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_KOBEXP_READ_VMEM        \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_OUT_DIRECT, FILE_READ_ACCESS)

#define IOCTL_KOBEXP_WRITE_VMEM       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)

typedef struct _KZODIACON_DUP_DATA {
    ULONG Handle;
    ULONG SourcePid;
    ULONG AccessMask;
    ULONG Flags;
} KZODIACON_DUP_DATA, *PKZODIACON_DUP_DATA;

//
// Yep, screwed up with previously compiled drivers.
//

typedef struct _KZODIACON_DUP_DATA_V2 {
    HANDLE Handle;
    ULONG SourcePid;
    ULONG AccessMask;
    ULONG Flags;
} KZODIACON_DUP_DATA_V2, *PKZODIACON_DUP_DATA_V2;


BOOL WINAPI KObExpReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KObExpWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI ZdcWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI ZdcReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI ZdcVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI ZdcQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI ZdcWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI ZdcReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI ZdcRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI ZdcUnregisterDriver(
    _In_ HANDLE DeviceHandle);

BOOL ZdcStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context);
