/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       EVGA.H
*
*  VERSION:     1.41
*
*  DATE:        10 Dec 2023
*
*  EVGA driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// EVGA ELEETX1 driver interface.
//

#define EVGA_ELEETX1_DEVICE_TYPE   (DWORD)0x8000

#define EVGA_ELEETX1_FUNCTION_READPHYSMEM 0x905
#define EVGA_ELEETX1_FUNCTION_WRITEPHYSMEM 0x906

#define IOCTL_EVGA_ELEETX1_READ_PHYSMEM    \
    CTL_CODE(EVGA_ELEETX1_DEVICE_TYPE, EVGA_ELEETX1_FUNCTION_READPHYSMEM, METHOD_BUFFERED, FILE_READ_ACCESS) //0x80006414

#define IOCTL_EVGA_ELEETX1_WRITE_PHYSMEM    \
    CTL_CODE(EVGA_ELEETX1_DEVICE_TYPE, EVGA_ELEETX1_FUNCTION_WRITEPHYSMEM, METHOD_BUFFERED, FILE_READ_ACCESS) //0x80006418

//Where-what
typedef struct _EVGA_ELEETX1_WRITE_REQUEST {
    PHYSICAL_ADDRESS Address; //Where
    ULONG64 Value; //What 1, 2, 4, 8 size
} EVGA_ELEETX1_WRITE_REQUEST, * PEVGA_ELEETX1_WRITE_REQUEST;

BOOL WINAPI EvgaReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI EvgaWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
