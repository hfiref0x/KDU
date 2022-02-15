/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       DBUTIL.H
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  Dell BIOS Utility driver interface header.
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

#define DBUTIL_DEVICE_TYPE (DWORD)0x9B0C

#define DBUTIL_FUNCTION_READVM  (DWORD)0x7B1
#define DBUTIL_FUNCTION_WRITEVM (DWORD)0x7B2

#define IOCTL_DBUTIL_READVM    \
    CTL_CODE(DBUTIL_DEVICE_TYPE, DBUTIL_FUNCTION_READVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9B0C1EC4

#define IOCTL_DBUTIL_WRITEVM    \
    CTL_CODE(DBUTIL_DEVICE_TYPE, DBUTIL_FUNCTION_WRITEVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9B0C1EC8

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

BOOL DbUtilStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

VOID DbUtilStopVulnerableDriver(
    _In_ KDU_CONTEXT* Context);
