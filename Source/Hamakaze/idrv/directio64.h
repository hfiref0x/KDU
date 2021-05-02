/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       DIRECTIO64.H
*
*  VERSION:     1.11
*
*  DATE:        18 Apr 2021
*
*  PassMark DIRECTIO driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define DIRECTIO_DEVICE_TYPE            (DWORD)0x8011
#define DIRECTIO_OPEN_PHYSMEM_FUNCID    (DWORD)0x81F
#define DIRECTIO_MAP_PHYSMEM_FUNCID     (DWORD)0x811
#define DIRECTIO_UNMAP_PHYSMEM_FUNCID   (DWORD)0x812

#define IOCTL_DIRECTIO_OPEN_PHYSICAL_MEMORY      \
    CTL_CODE(DIRECTIO_DEVICE_TYPE, DIRECTIO_OPEN_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS) //0x8011607C

#define IOCTL_DIRECTIO_MAP_PHYSICAL_MEMORY       \
    CTL_CODE(DIRECTIO_DEVICE_TYPE, DIRECTIO_MAP_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x8011E044

#define IOCTL_DIRECTIO_UNMAP_PHYSICAL_MEMORY     \
    CTL_CODE(DIRECTIO_DEVICE_TYPE, DIRECTIO_UNMAP_PHYSMEM_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x8011E048

#pragma pack(push, 1)
typedef struct _DIRECTIO_PHYSICAL_MEMORY_INFO {
    HANDLE SectionHandle;
    PVOID BaseAddressIoSpace;
    PVOID AllocatedMdl;
    DWORD ViewSize;
    PHYSICAL_ADDRESS Offset;
    PVOID BaseAddress;
    BOOLEAN Writeable;
} DIRECTIO_PHYSICAL_MEMORY_INFO, * PDIRECTIO_PHYSICAL_MEMORY_INFO; //sizeof 45 bytes
#pragma pack(pop)

BOOL WINAPI DI64VirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI DI64QueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI DI64ReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI DI64WriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI DI64ReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI DI64WritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
