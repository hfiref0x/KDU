/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ZODIACON.CPP
*
*  VERSION:     1.32
*
*  DATE:        20 May 2022
*
*  Zodiacon driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/zodiacon.h"

/*
* KObExpReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via KObExp driver.
*
*/
BOOL WINAPI KObExpReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supCallDriver(DeviceHandle, IOCTL_KOBEXP_READ_VMEM,
        &VirtualAddress,
        sizeof(VirtualAddress),
        Buffer,
        NumberOfBytes);
}

/*
* KObExpWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via KObExp driver.
*
*/
BOOL WINAPI KObExpWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return supCallDriver(DeviceHandle, IOCTL_KOBEXP_WRITE_VMEM,
        &VirtualAddress,
        sizeof(VirtualAddress),
        Buffer,
        NumberOfBytes);
}