/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       LHA.H
*
*  VERSION:     1.10
*
*  DATE:        03 Apr 2021
*
*  LG LHA driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// LG LHA driver interface.
//

#define LHA_DEVICE_TYPE          (DWORD)0x9C40

#define LHA_READ_PHYSMEM_FUNCID  (DWORD)0xBF6
#define LHA_WRITE_PHYSMEM_FUNCID (DWORD)0xBF7


#define IOCTL_LHA_READ_PHYSICAL_MEMORY      \
    CTL_CODE(LHA_DEVICE_TYPE, LHA_READ_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9C402FD8

#define IOCTL_LHA_WRITE_PHYSICAL_MEMORY    \
    CTL_CODE(LHA_DEVICE_TYPE, LHA_WRITE_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9C402FDC

#pragma pack(push,4)

typedef struct _LHA_READ_PHYSICAL_MEMORY {
    ULONG_PTR Address;
    ULONG Size;
} LHA_READ_PHYSICAL_MEMORY, * PLHA_READ_PHYSICAL_MEMORY;

#pragma pack(pop)

typedef struct _LHA_WRITE_PHYSICAL_MEMORY {
    ULONG_PTR Address;
    ULONG Size;
    UCHAR Data[ANYSIZE_ARRAY];
} LHA_WRITE_PHYSICAL_MEMORY, * PLHA_WRITE_PHYSICAL_MEMORY;

BOOL WINAPI LHAReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LHAWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LHAQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI LHAVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI LHAReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LHAWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
