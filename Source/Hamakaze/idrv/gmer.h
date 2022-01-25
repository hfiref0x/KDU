/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       GMER.H
*
*  VERSION:     1.12
*
*  DATE:        25 Jan 2022
*
*  GMER driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once


//
// Gmer driver interface.
//

#define GMER_DEVICE_TYPE   (DWORD)0x7201
#define GMER_DEVICE_TYPE_2 (DWORD)0x9876

#define GMER_FUNCTION_READVM 0xA
#define GMER_FUNCTION_WRITEVM 0xD
#define GMER_FUNCTION_REGISTER_CLIENT 0x1

#define IOCTL_GMER_REGISTER_CLIENT    \
    CTL_CODE(GMER_DEVICE_TYPE_2, GMER_FUNCTION_REGISTER_CLIENT, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x9876C004

#define IOCTL_GMER_READVM    \
    CTL_CODE(GMER_DEVICE_TYPE, GMER_FUNCTION_READVM, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x7201C028

#define IOCTL_GMER_WRITEVM    \
    CTL_CODE(GMER_DEVICE_TYPE, GMER_FUNCTION_WRITEVM, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x7201C034

typedef struct _GMER_READ_REQUEST {
    ULONG_PTR VirtualAddress;
} GMER_READ_REQUEST, * PGMER_READ_REQUEST;

typedef struct _GMER_WRITE_REQUEST {
    ULONG_PTR Unused;
    ULONG_PTR VirtualAddress;
    ULONG DataSize;
    UCHAR Data[1];
} GMER_WRITE_REQUEST, * PGMER_WRITE_REQUEST;

BOOL WINAPI GmerRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

_Success_(return != FALSE)
BOOL WINAPI GmerReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI GmerWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
