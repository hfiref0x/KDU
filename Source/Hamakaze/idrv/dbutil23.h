/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       DBUTIL23.H
*
*  VERSION:     1.12
*
*  DATE:        25 Jan 2022
*
*  Dell BIOS Utility 2.3 driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Dell driver interface.
//

#define DBUTIL23_DEVICE_TYPE (DWORD)0x9B0C

#define DBUTIL23_FUNCTION_READVM  (DWORD)0x7B1
#define DBUTIL23_FUNCTION_WRITEVM (DWORD)0x7B2

#define IOCTL_DBUTIL23_READVM    \
    CTL_CODE(DBUTIL23_DEVICE_TYPE, DBUTIL23_FUNCTION_READVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9B0C1EC4

#define IOCTL_DBUTIL23_WRITEVM    \
    CTL_CODE(DBUTIL23_DEVICE_TYPE, DBUTIL23_FUNCTION_WRITEVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9B0C1EC8

//
// Virtual memory read/write
//
typedef struct _DBUTIL_READWRITE_REQUEST {
    ULONG_PTR Unused;
    ULONG_PTR VirtualAddress;
    ULONG_PTR Offset;
    UCHAR Data[1];
} DBUTIL_READWRITE_REQUEST, * PDBUTIL_READWRITE_REQUEST;

//
// Size of data to read/write calculated as: 
// 
// InputBufferSize - sizeof packet header 0x18 bytes length
//

_Success_(return != FALSE)
BOOL WINAPI DbUtilReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI DbUtilWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
