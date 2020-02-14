/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       ATSZIO.H
*
*  VERSION:     1.01
*
*  DATE:        12 Feb 2020
*
*  ASUSTeK ATSZIO WinFlash driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// ASUSTeK ATSZIO WinFlash driver interface.
//

#define ATSZIO_DEVICE_TYPE          (DWORD)0x8807

#define ATSZIO_MAP_SECTION_FUNCID   (DWORD)0x803
#define ATSZIO_UNMAP_SECTION_FUNCID (DWORD)0x804

#define IOCTL_ATSZIO_MAP_USER_PHYSICAL_MEMORY      \
    CTL_CODE(ATSZIO_DEVICE_TYPE, ATSZIO_MAP_SECTION_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x8807200C

#define IOCTL_ATSZIO_UNMAP_USER_PHYSICAL_MEMORY    \
    CTL_CODE(ATSZIO_DEVICE_TYPE, ATSZIO_UNMAP_SECTION_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x88072010


#pragma warning(push)
#pragma warning(disable:4324) // structure padded due to __declspec(align())
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)_ATSZIO_PHYSICAL_MEMORY_INFO {
    ULONG_PTR Unused0;
    HANDLE SectionHandle;
    ULONG ViewSize;
    ULONG Padding0;
    ULARGE_INTEGER Offset;
    PVOID MappedBaseAddress;
} ATSZIO_PHYSICAL_MEMORY_INFO, * PATSZIO_PHYSICAL_MEMORY_INFO;
#pragma warning(pop)

BOOL WINAPI AtszioQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI AtszioVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI AtszioReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AtszioWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AtszioWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AtszioReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
