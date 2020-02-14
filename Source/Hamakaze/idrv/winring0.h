/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       WINRING0.H
*
*  VERSION:     1.01
*
*  DATE:        13 Feb 2020
*
*  WinRing0 based drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// WinRing0 driver interface definitions. Recognizable CVE-2017-14311.
//
// Taken from WinRing0 source.
//

#define OLS_TYPE            (DWORD)40000

#define OLS_READ_MEMORY     (DWORD)0x841
#define OLS_WRITE_MEMORY    (DWORD)0x842

#define IOCTL_OLS_READ_MEMORY \
	CTL_CODE(OLS_TYPE, OLS_READ_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_OLS_WRITE_MEMORY \
	CTL_CODE(OLS_TYPE, OLS_WRITE_MEMORY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#pragma pack(push,4)

typedef struct _OLS_READ_MEMORY_INPUT {
    PHYSICAL_ADDRESS Address;
    ULONG UnitSize;
    ULONG Count;
} OLS_READ_MEMORY_INPUT;

typedef struct _OLS_WRITE_MEMORY_INPUT {
    PHYSICAL_ADDRESS Address;
    ULONG UnitSize;
    ULONG Count;
    UCHAR Data[1];
} OLS_WRITE_MEMORY_INPUT;

#pragma pack(pop)

BOOL WRZeroReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI WRZeroWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI WRZeroQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI WRZeroVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI WRZeroReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI WRZeroKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
