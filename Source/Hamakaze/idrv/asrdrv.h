/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       ASRDRV.H
*
*  VERSION:     1.41
*
*  DATE:        11 Dec 2023
*
*  ASRock driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define ASRDRV_READ_MEMORY     (DWORD)0xA02
#define ASRDRV_WRITE_MEMORY    (DWORD)0xA03
#define ASRDRV_EXEC_DISPATCH   (DWORD)0xB00

#define IOCTL_ASRDRV_READ_MEMORY  \
	CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_READ_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_ASRDRV_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_WRITE_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_ASRDRV_EXEC_DISPATCH \
	CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_EXEC_DISPATCH, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_RWDRV_READ_MEMORY  \
	CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_READ_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x00222808

#define IOCTL_RWDRV_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_WRITE_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x0022280C

#define IOCTL_RWDRV_READ_MEMORY_7N  \
	CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_READ_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x0022E808

#define IOCTL_RWDRV_WRITE_MEMORY_7N \
	CTL_CODE(FILE_DEVICE_UNKNOWN, ASRDRV_WRITE_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS) //0x0022E80C


//
// Based on CVE-2020-15368
//

#pragma pack(push, 1)
typedef struct _ASRDRV_REQUEST {
    WORD Pad0;
    DWORD SizeOfIv;
    BYTE Iv[21];
    BYTE Key[16];
    BYTE Pad1[3];
} ASRDRV_REQUEST, * PASRDRV_REQUEST;

typedef struct _ASRDRV_REQUEST_FOOTER {
    ULONG Size;
    WORD Pad0;
} ASRDRV_REQUEST_FOOTER, * PASRDRV_REQUEST_FOOTER;

typedef enum _ASRDRV_MM_GRANULARITY {
    AsrGranularityByte = 0,
    AsrGranularityWord = 1,
    AsrGranularityDword = 2
} ASRDRV_MM_GRANULARITY;

typedef union _ASRDRV_ARGS {
    BYTE byteArgs[24];
    WORD wordArgs[12];
    DWORD dwordArgs[6];
    UINT64 qwordArgs[3];
} ASRDRV_ARGS;

typedef struct _ASRDRV_COMMAND {
    UINT OperationCode;
    INT Pad0;
    ASRDRV_ARGS Arguments;
} ASRDRV_COMMAND, * PASRDRV_COMMAND;
#pragma pack(pop)

//
// Original RWE layout.
//
typedef struct _ASR_RWE_REQUEST {
    PHYSICAL_ADDRESS Address;           //+0x00
    ULONG Size;                         //+0x08
    ASRDRV_MM_GRANULARITY Granularity;  //+0x0C
    PBYTE Data;                         //+0x10
} ASR_RWE_REQUEST, *PASR_RWE_REQUEST;

BOOL WINAPI AsrReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AsrWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI RweReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI RweWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AsrRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);
