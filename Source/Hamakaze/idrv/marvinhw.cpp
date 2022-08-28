/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       MARVINHW.CPP
*
*  VERSION:     1.25
*
*  DATE:        18 Aug 2022
*
*  Marvin HW driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/marvinhw.h"


/*
* HwMapMemory
*
* Purpose:
*
* Map physical memory.
*
*/
PVOID HwMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    HWMEMORYDESC request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.PhysicalAddress.QuadPart = PhysicalAddress;
    request.Length = NumberOfBytes;

    if (supCallDriver(DeviceHandle,
        IOCTL_HWMEM_MAP,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        return request.VirtualAddress;
    }

    return NULL;
}

/*
* HwUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID HwUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap
)
{
    HWMEMORYDESC request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.VirtualAddress = SectionToUnmap;

    supCallDriver(DeviceHandle,
        IOCTL_HWMEM_UNMAP,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* HwQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI HwQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;

    DWORD cbRead = 0x100000;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)HwMapMemory(DeviceHandle,
        0ULL,
        cbRead);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        HwUnmapMemory(DeviceHandle,
            (PVOID)pbLowStub1M);

    }

    return (PML4 != 0);
}

/*
* HwReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI HwReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;

    //
    // Map physical memory section.
    //
    mappedSection = HwMapMemory(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes);

    if (mappedSection) {

        __try {

            if (DoWrite) {
                RtlCopyMemory(mappedSection, Buffer, NumberOfBytes);
            }
            else {
                RtlCopyMemory(Buffer, mappedSection, NumberOfBytes);
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
        HwUnmapMemory(DeviceHandle,
            mappedSection);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* HwReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI HwReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return HwReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* HwWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI HwWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return HwReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* HwVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI HwVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        HwQueryPML4Value,
        HwReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* HwWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory via HW64.
*
*/
BOOL WINAPI HwWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = HwVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = HwReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

    return bResult;
}

/*
* HwReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory via HW64.
*
*/
BOOL WINAPI HwReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = HwVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = HwReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

    return bResult;
}
