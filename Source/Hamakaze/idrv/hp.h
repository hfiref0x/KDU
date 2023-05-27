/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       HP.H
*
*  VERSION:     1.32
*
*  DATE:        20 May 2023
*
*  Hewlett Packard driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Hewlett Packard interface for ETDi Service Driver.
//

#define HP_DEVICE_TYPE        (DWORD)0x8000

#define HP_READ_VMEM  (DWORD)0x80F
#define HP_WRITE_VMEM (DWORD)0x80E 

#define IOCTL_HP_READ_VMEM        \
    CTL_CODE(HP_DEVICE_TYPE, HP_READ_VMEM, METHOD_BUFFERED, FILE_READ_ACCESS) //0x8000603C

#define IOCTL_HP_WRITE_VMEM       \
    CTL_CODE(HP_DEVICE_TYPE, HP_WRITE_VMEM, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0x80006038

typedef enum _HP_VALUE_GRANULARITY {
    HpByte = 1,
    HpWord = 2,
    HpDword = 4
} HP_VALUE_GRANULARITY;

typedef struct _HP_VMEM_REQUEST { //sizeof 32
    HP_VALUE_GRANULARITY Granularity;
    ULONG Spare0;
    ULONG_PTR Unused0;
    ULONG_PTR Source;
    union {
        union {
            BYTE vtByte;
            WORD vtWord;
            DWORD vtDword;
        } ValueByType;
        DWORD Value;
    } InputOutput;
    ULONG Spare1;
} HP_VMEM_REQUEST, * PHP_VMEM_REQUEST;

_Success_(return != FALSE)
BOOL WINAPI HpEtdReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI HpEtdWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
