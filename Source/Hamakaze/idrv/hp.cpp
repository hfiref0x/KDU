/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       HP.CPP
*
*  VERSION:     1.32
*
*  DATE:        20 May 2022
*
*  Hewlett Packard driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/hp.h"

/*
* HpEtdReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via HP ETD driver.
*
*/
_Success_(return != FALSE)
BOOL WINAPI HpEtdReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    PBYTE BufferPtr = (PBYTE)Buffer;
    ULONG_PTR virtAddress = VirtualAddress;
    ULONG readBytes = 0;
    HP_VMEM_REQUEST request;

    for (ULONG i = 0; i < NumberOfBytes; i++) {

        RtlSecureZeroMemory(&request, sizeof(request));

        request.Source = virtAddress;
        request.Granularity = HpByte;

        if (!supCallDriver(DeviceHandle, IOCTL_HP_READ_VMEM,
            &request, sizeof(request),
            &request, sizeof(request)))
        {
            break;
        }

        BufferPtr[i] = request.InputOutput.ValueByType.vtByte;
        virtAddress += sizeof(BYTE);
        readBytes += sizeof(BYTE);
    }

    return (readBytes == NumberOfBytes);
}

/*
* HpEtdWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via HP ETD driver.
*
*/
_Success_(return != FALSE)
BOOL WINAPI HpEtdWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    PBYTE BufferPtr = (PBYTE)Buffer;

    ULONG_PTR virtAddress = VirtualAddress;
    ULONG writeBytes = 0;
    HP_VMEM_REQUEST request;

    for (ULONG i = 0; i < NumberOfBytes; i++) {

        RtlSecureZeroMemory(&request, sizeof(request));

        request.Source = virtAddress;
        request.Granularity = HpByte;
        request.InputOutput.ValueByType.vtByte = BufferPtr[i];

        if (!supCallDriver(DeviceHandle, IOCTL_HP_WRITE_VMEM,
            &request, sizeof(request),
            NULL, 0))
        {
            break;
        }

        virtAddress += sizeof(BYTE);
        writeBytes += sizeof(BYTE);
    }

    return (writeBytes == NumberOfBytes);
}
