/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2026
*
*  TITLE:       MARVINHW.H
*
*  VERSION:     1.50
*
*  DATE:        19 Jul 2026
*
*  Marvin HW driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Marvin HW driver interface.
//

#define	FILE_DEVICE_MARVIN_HW   (DWORD)0x9C40

#define HWMEM_MAP               (DWORD)0x940
#define HWMEM_UNMAP             (DWORD)0x941

#define IOCTL_HWMEM_MAP     \
    CTL_CODE(FILE_DEVICE_MARVIN_HW, HWMEM_MAP,\
             METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_HWMEM_UNMAP   \
    CTL_CODE(FILE_DEVICE_MARVIN_HW, HWMEM_UNMAP,\
             METHOD_BUFFERED, FILE_READ_ACCESS)

typedef struct tagHWMEMORYDESC {
    PHYSICAL_ADDRESS PhysicalAddress;
    ULONG_PTR Length;
    PVOID VirtualAddress;
} HWMEMORYDESC, * PHWMEMORYDESC;

BOOL WINAPI HwVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI HwReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI HwWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI HwWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI HwReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

