/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       MIMIDRV.CPP
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  Mimikatz "mimidrv" driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/mimidrv.h"

/*
* MimidrvReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via mimidrv.
*
*/
BOOL WINAPI MimidrvReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supCallDriver(DeviceHandle,
        IOCTL_MIMIDRV_VM_READ,
        (PVOID)VirtualAddress,
        0,
        Buffer,
        NumberOfBytes);
}

/*
* MimidrvWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via mimidrv.
*
*/
BOOL WINAPI MimidrvWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supCallDriver(DeviceHandle,
        IOCTL_MIMIDRV_VM_WRITE,
        Buffer,
        NumberOfBytes,
        (PVOID)VirtualAddress,
        0);
}
