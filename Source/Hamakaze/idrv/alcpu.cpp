/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       ALSYSIO64.CPP
*
*  VERSION:     1.31
*
*  DATE:        14 Apr 2023
*
*  ALSYSIO64 driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/alcpu.h"

/*
* AlcReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI AlcReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ALCPU_READ_REQUEST request;

    request.PhysicalAddress.QuadPart = PhysicalAddress;
    request.Size = NumberOfBytes;

    return supCallDriver(DeviceHandle,
        IOCTL_ALCPU_READ_MEMORY,
        &request,
        sizeof(request),
        Buffer,
        NumberOfBytes);

}

/*
* AlcWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI AlcWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    ALCPU_WRITE_REQUEST* pRequest;
    SIZE_T size;
    ULONG value;

    value = FIELD_OFFSET(ALCPU_WRITE_REQUEST, Data) + NumberOfBytes;
    size = ALIGN_UP_BY(value, PAGE_SIZE);

    pRequest = (ALCPU_WRITE_REQUEST*)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE);

    if (pRequest) {

        pRequest->PhysicalAddress.QuadPart = PhysicalAddress;
        pRequest->Size = NumberOfBytes;
        RtlCopyMemory(&pRequest->Data, Buffer, NumberOfBytes);

        bResult = supCallDriver(DeviceHandle,
            IOCTL_ALCPU_WRITE_MEMORY,
            pRequest,
            (ULONG)size,
            NULL,
            0);

        supFreeLockedMemory(pRequest, size);
    }

    return bResult;
}
