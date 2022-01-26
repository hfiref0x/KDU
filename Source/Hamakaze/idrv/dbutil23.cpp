/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       DBUTIL23.CPP
*
*  VERSION:     1.12
*
*  DATE:        25 Jan 2022
*
*  Dell BIOS Utility 2.3 driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/dbutil23.h"

/*
* DbUtilReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via Dell DbUtil driver.
*
*/
_Success_(return != FALSE)
BOOL WINAPI DbUtilReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;

    SIZE_T size;
    ULONG value;
    DWORD dwError = ERROR_SUCCESS;
    DBUTIL_READWRITE_REQUEST* pRequest;

    value = FIELD_OFFSET(DBUTIL_READWRITE_REQUEST, Data) + NumberOfBytes;
    size = ALIGN_UP_BY(value, PAGE_SIZE);

    pRequest = (DBUTIL_READWRITE_REQUEST*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->Unused = 0xDEADBEEF;
            pRequest->VirtualAddress = VirtualAddress;
            pRequest->Offset = 0;

            bResult = supCallDriver(DeviceHandle,
                IOCTL_DBUTIL23_READVM,
                pRequest,
                (ULONG)size,
                pRequest,
                (ULONG)size);

            if (!bResult) {
                dwError = GetLastError();
            }
            else {
                RtlCopyMemory(Buffer, pRequest->Data, NumberOfBytes);
            }

            VirtualUnlock(pRequest, size);
        }

        VirtualFree(pRequest, 0, MEM_RELEASE);
    }

    SetLastError(dwError);
    return bResult;

}

/*
* DbUtilWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via Dell DbUtil driver.
*
*/
_Success_(return != FALSE)
BOOL WINAPI DbUtilWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;

    SIZE_T size;
    ULONG value;
    DWORD dwError = ERROR_SUCCESS;

    DBUTIL_READWRITE_REQUEST* pRequest;

    value = FIELD_OFFSET(DBUTIL_READWRITE_REQUEST, Data) + NumberOfBytes;
    size = ALIGN_UP_BY(value, PAGE_SIZE);

    pRequest = (DBUTIL_READWRITE_REQUEST*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->Unused = 0xDEADBEEF;
            pRequest->VirtualAddress = VirtualAddress;
            pRequest->Offset = 0;
            RtlCopyMemory(&pRequest->Data, Buffer, NumberOfBytes);

            bResult = supCallDriver(DeviceHandle,
                IOCTL_DBUTIL23_WRITEVM,
                pRequest,
                (ULONG)size,
                pRequest,
                (ULONG)size);

            if (!bResult)
                dwError = GetLastError();

            VirtualUnlock(pRequest, size);
        }

        VirtualFree(pRequest, 0, MEM_RELEASE);
    }

    SetLastError(dwError);
    return bResult;
}
