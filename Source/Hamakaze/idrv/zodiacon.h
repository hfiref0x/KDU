/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ZODIACON.H
*
*  VERSION:     1.32
*
*  DATE:        20 May 2023
*
*  Zodiacon driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define IOCTL_KOBEXP_READ_VMEM        \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_OUT_DIRECT, FILE_READ_ACCESS)

#define IOCTL_KOBEXP_WRITE_VMEM       \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)

BOOL WINAPI KObExpReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KObExpWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
