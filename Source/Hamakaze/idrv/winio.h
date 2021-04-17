/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       WINIO.H
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
*
*  WINIO based drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Generic WINIO interface for all supported drivers based on WINIO code.
//
// MICSYS RGB driver interface for CVE-2019-18845.
// Ptolemy Tech Co., Ltd ENE driver interface
// G.Skill EneIo64 driver interface
// ... and multiple others
//

#define FILE_DEVICE_WINIO       (DWORD)0x00008010

#define WINIO_IOCTL_INDEX       (DWORD)0x810

#define WINIO_MAP_FUNCID        (DWORD)0x810
#define WINIO_UNMAP_FUNCID      (DWORD)0x811
#define WINIO_READMSR           (DWORD)0x816

#define GLCKIO2_REGISTER_FUNCID (DWORD)0x818

#define IOCTL_WINIO_MAP_USER_PHYSICAL_MEMORY     \
    CTL_CODE(FILE_DEVICE_WINIO, WINIO_MAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102040

#define IOCTL_WINIO_UNMAP_USER_PHYSICAL_MEMORY   \
    CTL_CODE(FILE_DEVICE_WINIO, WINIO_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102044

#define IOCTL_WINIO_READMSR     \
    CTL_CODE(WINIO_DEVICE_TYPE, WINIO_READMSR, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GKCKIO2_REGISTER     \
    CTL_CODE(FILE_DEVICE_WINIO, GLCKIO2_REGISTER_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))


/*

MsIo64 Structure definition note

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

/*

This is original WinIo structure layout.

*/
typedef struct _WINIO_PHYSICAL_MEMORY_INFO {
    ULONG_PTR ViewSize;
    ULONG_PTR BusAddress; //physical address
    HANDLE SectionHandle;
    PVOID BaseAddress;
    PVOID ReferencedObject;
} WINIO_PHYSICAL_MEMORY_INFO, * PWINIO_PHYSICAL_MEMORYINFO;

/*

EneTechIo enhanced variant with requestor check.

*/
typedef struct _WINIO_PHYSICAL_MEMORY_INFO_EX {
    ULONG_PTR CommitSize;
    ULONG_PTR BusAddress;
    HANDLE SectionHandle;
    PVOID BaseAddress;
    PVOID ReferencedObject;
    UCHAR EncryptedKey[16];
} WINIO_PHYSICAL_MEMORY_INFO_EX, * PWINIO_PHYSICAL_MEMORY_INFO_EX;

BOOL WINAPI WinIoQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI WinIoReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI WinIoWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI WinIoVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI WinIoReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI WinIoWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI WinIoPreOpen(
    _In_ PVOID Param);

BOOL WINAPI WinIoRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI WinIoUnregisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);
