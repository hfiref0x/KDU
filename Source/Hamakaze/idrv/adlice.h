/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       ADLICE.H
*
*  VERSION:     1.50
*
*  DATE:        19 Sep 2026
*
*  Adlice driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define RLASER_READ_MEMORY     (DWORD)0x814
#define RLASER_WRITE_MEMORY    (DWORD)0x805

#define RLASER_MAGIC         (DWORD)0xEE00AA77
#define RLASER_WRITE_BIAS    0x70

#define IOCTL_RLASER_READ_MEMORY  \
	CTL_CODE(FILE_DEVICE_UNKNOWN, RLASER_READ_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x0022E050

#define IOCTL_RLASER_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_UNKNOWN, RLASER_WRITE_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x0022E014

#pragma pack(push, 1)
typedef struct _RLASER_WRITE_REQUEST {
    DWORD MagicNumber;      // +0x00 RLASER_MAGIC
    DWORD Padding1;         // +0x04
    DWORD64 BaseAddress;    // +0x08
    DWORD Index;            // +0x10
    DWORD Padding2;         // +0x14
    DWORD64 ValueToWrite;   // +0x18
} RLASER_WRITE_REQUEST, * PRLASER_WRITE_REQUEST;

typedef struct _RLASER_READ_REQUEST {
    DWORD64 TargetAddress;  // +0x00
    DWORD DataLength;       // +0x08 
    DWORD Unknown;          // +0x0C
} RLASER_READ_REQUEST, * PRLASER_READ_REQUEST;

#pragma pack(pop)

BOOL RLaserReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL RLaserWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
