/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       MATROX.CPP
*
*  VERSION:     1.49
*
*  DATE:        05 Jun 2026
*
*  Matrox Graphics Inc. driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/matrox.h"

/*
* MatroxMapMemory
*
* Purpose:
*
* Map physical memory to the user mode.
*
*/
PVOID MatroxMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    MATROX_MAP_MEMORY_INPUT request;
    MATROX_MAP_MEMORY_OUTPUT reply;

    RtlSecureZeroMemory(&request, sizeof(request));
    RtlSecureZeroMemory(&reply, sizeof(reply));

    request.SectionOffset.QuadPart = PhysicalAddress;
    request.ViewSize = NumberOfBytes;
    request.MemoryCachingType = 0; //PAGE_READWRITE

    if (supCallDriver(DeviceHandle,
        IOCTL_MATROX_MAP_MEMORY,
        &request,
        sizeof(request),
        &reply,
        sizeof(reply)))
    {
        return reply.BaseAddress;
    }

    return NULL;
}

/*
* MatroxUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID MatroxUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID BaseAddress)
{
    MATROX_UNMAP_MEMORY_INPUT request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = BaseAddress;

    supCallDriver(DeviceHandle,
        IOCTL_MATROX_UNMAP_MEMORY,
        &request,
        sizeof(request),
        NULL,
        0);
}

/*
* MatroxVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI MatroxVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return supVirtualToPhysicalWithSuperfetch(VirtualAddress, PhysicalAddress);
}

/*
* MatroxReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI MatroxReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;
    ULONG_PTR pageBase, offset;
    ULONG_PTR mapSize;

    supCalcPhysMapParams(PhysicalAddress,
        NumberOfBytes,
        &pageBase,
        &offset,
        &mapSize);

    mappedSection = MatroxMapMemory(DeviceHandle, pageBase, (ULONG)mapSize);
    if (mappedSection) {

        __try {

            RtlCopyMemory(Buffer, RtlOffsetToPointer(mappedSection, offset), NumberOfBytes);
            bResult = TRUE;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        MatroxUnmapMemory(DeviceHandle, mappedSection);
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* MatroxWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI MatroxWritePhysicalMemory(
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

    supCalcPhysMapParams(PhysicalAddress,
        NumberOfBytes,
        &pageBase,
        &offset,
        &mapSize);

    mappedSection = MatroxMapMemory(DeviceHandle, pageBase, (ULONG)mapSize);
    if (mappedSection) {

        __try {

            RtlCopyMemory(RtlOffsetToPointer(mappedSection, offset), Buffer, NumberOfBytes);
            bResult = TRUE;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        MatroxUnmapMemory(DeviceHandle, mappedSection);
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* MatroxWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI MatroxWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        MatroxWritePhysicalMemory);
}

/*
* MatroxReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI MatroxReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        MatroxReadPhysicalMemory);
}
