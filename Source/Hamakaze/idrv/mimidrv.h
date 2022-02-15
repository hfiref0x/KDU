/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       MIMIDRV.H
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  MIMIDRV driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Mimikatz mimidrv interface
//

#define MIMIDRV_FUNC_VMREAD  (DWORD)0x60
#define MIMIDRV_FUNC_VMWRITE (DWORD)0x61

#define IOCTL_MIMIDRV_VM_READ               \
    CTL_CODE(FILE_DEVICE_UNKNOWN, MIMIDRV_FUNC_VMREAD, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA) //0x0022C183

#define IOCTL_MIMIDRV_VM_WRITE	            \
    CTL_CODE(FILE_DEVICE_UNKNOWN, MIMIDRV_FUNC_VMWRITE, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA) //0x0022C187

BOOL WINAPI MimidrvReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MimidrvWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
