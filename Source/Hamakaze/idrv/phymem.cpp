/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       PHYMEM.CPP
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
*
*  PhyMem based drivers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/phymem.h"

//
// Realtek/Supermicro I/O drivers are based on PhyMem open-source library "PhyMem" by "akui" dated back to 2009.
// It is very similar to MAPMEM.SYS Microsoft Windows NT 3.51 DDK example from 1993.
//

/*
* PhyMemMapMemory
*
* Purpose:
*
* Map physical memory.
*
*/
PVOID PhyMemMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    PVOID pMapSection = NULL;
    PHYMEM_MEM request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.pvAddr = (PVOID)PhysicalAddress;
    request.dwSize = NumberOfBytes;

    if (supCallDriver(DeviceHandle,
        IOCTL_PHYMEM_MAP,
        &request,
        sizeof(request),
        (PVOID)&pMapSection,
        sizeof(PVOID)))
    {
        return pMapSection;
    }

    return NULL;
}

/*
* PhyMemUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID PhyMemUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ ULONG NumberOfBytes
)
{
    PHYMEM_MEM request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.pvAddr = SectionToUnmap;
    request.dwSize = NumberOfBytes;

    supCallDriver(DeviceHandle,
        IOCTL_PHYMEM_UNMAP,
        &request,
        sizeof(request),
        NULL,
        0);
}

/*
* PhyMemQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI PhyMemQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD dwError = ERROR_SUCCESS;
    ULONG_PTR PML4 = 0;
    UCHAR* pbLowStub1M;

    *Value = 0;

    do {

        pbLowStub1M = (UCHAR*)supHeapAlloc(0x100000);
        if (pbLowStub1M == NULL) {
            dwError = GetLastError();
            break;
        }

        for (ULONG_PTR i = 0; i < 0x100000; i += PAGE_SIZE) {

            if (!PhyMemReadPhysicalMemory(DeviceHandle,
                i,
                RtlOffsetToPointer(pbLowStub1M, i),
                PAGE_SIZE))
            {
                dwError = GetLastError();
                break;
            }

        }

        if (dwError == ERROR_SUCCESS) {

            PML4 = supGetPML4FromLowStub1M((ULONG_PTR)pbLowStub1M);
            if (PML4)
                *Value = PML4;
            else
                *Value = 0;

        }

    } while (FALSE);

    if (pbLowStub1M)
        supHeapFree(pbLowStub1M);

    SetLastError(dwError);
    return (PML4 != 0);
}

/*
* PhyMemVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI PhyMemVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    BOOL bResult = FALSE;

    if (PhysicalAddress)
        *PhysicalAddress = 0;
    else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    bResult = PwVirtualToPhysical(DeviceHandle,
        PhyMemQueryPML4Value,
        PhyMemReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);

    return bResult;
}

/*
* PhyMemReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI PhyMemReadWritePhysicalMemory(
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
    mappedSection = PhyMemMapMemory(DeviceHandle,
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
            SetLastError(GetExceptionCode());
        }

        //
        // Unmap physical memory section.
        //
        PhyMemUnmapMemory(DeviceHandle,
            mappedSection,
            NumberOfBytes);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* PhyMemReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI PhyMemReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return PhyMemReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* PhyMemWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI PhyMemWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return PhyMemReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* GioWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory via PhyMem.
*
*/
BOOL WINAPI PhyMemWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = PhyMemVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = PhyMemReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

        if (!bResult)
            dwError = GetLastError();

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* PhyMemReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory via PhyMem.
*
*/
BOOL WINAPI PhyMemReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = PhyMemVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = PhyMemReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

        if (!bResult)
            dwError = GetLastError();

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}
