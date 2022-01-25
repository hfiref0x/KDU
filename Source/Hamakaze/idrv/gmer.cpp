/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       GMER.CPP
*
*  VERSION:     1.12
*
*  DATE:        25 Jan 2022
*
*  GMER driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/gmer.h"

/*
* GmerRegisterDriver
*
* Purpose:
*
* Driver initialization routine.
*
*/
BOOL WINAPI GmerRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    BOOL bResult;
    ULONG ulRegistration = 0;

    bResult = supCallDriver(DeviceHandle,
        IOCTL_GMER_REGISTER_CLIENT,
        &ulRegistration,
        sizeof(ULONG),
        &ulRegistration,
        sizeof(ULONG));

    return bResult && (ulRegistration == 1);
}

/*
* GmerReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via Gmer.
*
*/
_Success_(return != FALSE)
BOOL WINAPI GmerReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    GMER_READ_REQUEST request;

    request.VirtualAddress = VirtualAddress;

    return supCallDriver(DeviceHandle,
        IOCTL_GMER_READVM,
        &request,
        sizeof(GMER_READ_REQUEST),
        Buffer,
        NumberOfBytes);

}

/*
* GmerWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via Gmer.
*
*/
_Success_(return != FALSE)
BOOL WINAPI GmerWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;

    SIZE_T size;
    ULONG value;
    DWORD dwError = ERROR_SUCCESS;

    GMER_WRITE_REQUEST* pRequest;

    value = FIELD_OFFSET(GMER_WRITE_REQUEST, Data) + NumberOfBytes;
    size = ALIGN_UP_BY(value, PAGE_SIZE);

    pRequest = (GMER_WRITE_REQUEST*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->Unused = 0;
            pRequest->VirtualAddress = VirtualAddress;
            pRequest->DataSize = NumberOfBytes;
            RtlCopyMemory(&pRequest->Data, Buffer, NumberOfBytes);

            bResult = supCallDriver(DeviceHandle,
                IOCTL_GMER_WRITEVM,
                pRequest,
                (ULONG)size,
                NULL,
                0);

            if (!bResult)
                dwError = GetLastError();

            VirtualUnlock(pRequest, size);
        }

        VirtualFree(pRequest, 0, MEM_RELEASE);
    }

    SetLastError(dwError);
    return bResult;

}
