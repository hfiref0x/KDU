/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       MSIO.H
*
*  VERSION:     1.00
*
*  DATE:        07 Feb 2020
*
*  MICSYS MSIO driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// MICSYS driver interface for CVE-2019-18845.
//

#define MICSYS_DEVICE_TYPE  (DWORD)0x8010

#define MSIO_MAP_FUNCID     (DWORD)0x810
#define MSIO_UNMAP_FUNCID   (DWORD)0x811

#define IOCTL_MSIO_MAP_USER_PHYSICAL_MEMORY     \
    CTL_CODE(MICSYS_DEVICE_TYPE, MSIO_MAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102040

#define IOCTL_MSIO_UNMAP_USER_PHYSICAL_MEMORY   \
    CTL_CODE(MICSYS_DEVICE_TYPE, MSIO_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102044

/*

Structure definition note

Field BusAddress downcasted to ULONG in driver

HalTranslateBusAddress(1i64, 0i64, (PVOID)(ULONG)RegionStart, &AddressSpace, &TranslatedAddress);

*/
#pragma warning(push)
#pragma warning(disable:4324) // structure padded due to __declspec(align())
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)_MSIO_PHYSICAL_MEMORY_INFO {
    ULONG_PTR ViewSize;
    ULONG BusAddress;
    HANDLE SectionHandle;
    PVOID BaseAddress;
    PVOID ReferencedObject;
} MSIO_PHYSICAL_MEMORY_INFO, * PMSIO_PHYSICAL_MEMORY_INFO;
#pragma warning(pop)

BOOL WINAPI MsioQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI MsioReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MsioWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MsioVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI MsioReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MsioWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
