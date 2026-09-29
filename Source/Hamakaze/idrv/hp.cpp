/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2026
*
*  TITLE:       HP.CPP
*
*  VERSION:     1.50
*
*  DATE:        24 Sep 2026
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

/*
 * HpWksReadPhysicalMemory
 *
 * Purpose:
 *
 * Read physical memory through IOCTL_HP_WKS_READ_VMEM.
 *
 */
_Success_(return != FALSE)
BOOL HpWksReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    HPWKS_READ_INPUT request;

    request.PhysicalAddress.QuadPart = PhysicalAddress;
    request.NumberOfBytes = NumberOfBytes;

    return supCallDriver(DeviceHandle,
        IOCTL_HP_WKS_READ_VMEM,
        &request,
        sizeof(HPWKS_READ_INPUT),
        Buffer,
        NumberOfBytes);
}

/*
 * HpWksWritePhysicalMemory
 *
 * Purpose:
 *
 * Write to physical memory through IOCTL_HP_WKS_WRITE_VMEM.
 *
 */
_Success_(return != FALSE)
BOOL HpWksWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    HPWKS_WRITE_INPUT request;

    request.PhysicalAddress.QuadPart = PhysicalAddress;
    request.NumberOfBytes = NumberOfBytes;
    request.SourceBuffer = Buffer;
    request.MaxAllowedBytes = NumberOfBytes;

    return supCallDriver(DeviceHandle,
        IOCTL_HP_WKS_WRITE_VMEM,
        &request,
        sizeof(HPWKS_WRITE_INPUT),
        &request,                   //unused but required
        sizeof(HPWKS_WRITE_INPUT)); //unused but required
}

/*
* HpWksVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI HpWksVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress
)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return supVirtualToPhysicalWithSuperfetch(VirtualAddress, PhysicalAddress);
}

/*
* HpWksReadKernelVirtualMemory
*
* Purpose:
*
* Read kernel virtual memory via Superfetch translation + physical memory read.
*
*/
BOOL WINAPI HpWksReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        HpWksReadPhysicalMemory);
}

/*
* HpWksWriteKernelVirtualMemory
*
* Purpose:
*
* Write kernel virtual memory via Superfetch translation + physical memory write.
*
*/
BOOL WINAPI HpWksWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        HpWksWritePhysicalMemory);
}
