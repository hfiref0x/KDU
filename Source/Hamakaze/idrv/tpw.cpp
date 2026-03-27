/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       TPW.CPP
*
*  VERSION:     1.47
*
*  DATE:        25 Mar 2026
*
*  TOSHIBA laptop power saving driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/tpw.h"

/*
* TpwReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory via TPwSav driver.
*
*/
BOOL TpwReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL DoWrite)
{
    NTSTATUS ntStatus;
    ULONG ioctl;
    LARGE_INTEGER buffer[2];
    IO_STATUS_BLOCK ioStatus;

    if (NumberOfBytes == 0 || Buffer == NULL)
        return FALSE;

    ioctl = DoWrite ? IOCTL_TPW_WRITE_PHYSICAL_MEMORY : IOCTL_TPW_READ_PHYSICAL_MEMORY;
    PBYTE pBuffer = (PBYTE)Buffer;
    for (ULONG i = 0; i < NumberOfBytes; i++) {
        RtlSecureZeroMemory(buffer, sizeof(buffer));
        buffer[0].QuadPart = (ULONG_PTR)(PhysicalAddress + i);
        buffer[1].QuadPart = 0;

        if (DoWrite) {
            buffer[1].QuadPart = pBuffer[i];

            ntStatus = supCallDriverEx(DeviceHandle,
                ioctl,
                buffer,
                sizeof(buffer),
                NULL,
                0,
                &ioStatus);

            if (!NT_SUCCESS(ntStatus))
                return FALSE;
        }
        else {
            ntStatus = supCallDriverEx(DeviceHandle,
                ioctl,
                buffer,
                sizeof(buffer),
                buffer,
                sizeof(buffer),
                &ioStatus);

            if (!NT_SUCCESS(ntStatus))
                return FALSE;

            pBuffer[i] = (BYTE)(buffer[1].LowPart & 0xFF);
        }
    }

    return TRUE;
}

/*
* TpwReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory via TPwSav driver.
*
*/
BOOL WINAPI TpwReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpwReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* TpwWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory via TPwSav driver.
*
*/
BOOL WINAPI TpwWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpwReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* TpwReadKernelVirtualMemory
*
* Purpose:
*
* Read kernel virtual memory via TPwSav driver using Superfetch translation.
*
*/
BOOL WINAPI TpwReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        TpwReadPhysicalMemory);
}

/*
* TpwWriteKernelVirtualMemory
*
* Purpose:
*
* Write kernel virtual memory via TPwSav using Superfetch translation.
*
*/
BOOL WINAPI TpwWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        TpwWritePhysicalMemory);
}
