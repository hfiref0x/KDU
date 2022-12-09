/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       RYZEN.CPP
*
*  VERSION:     1.28
*
*  DATE:        07 Dec 2022
*
*  AMD Ryzen Master Service Driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/ryzen.h"

/*
* RmValidatePrerequisites
*
* Purpose:
*
* Check if the current CPU vendor is AMD.
* This driver won't work on anything else as it has hard block on driver entry.
*
*/
BOOL RmValidatePrerequisites(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL bResult;
    UNREFERENCED_PARAMETER(Context);

    bResult = supIsSupportedCpuVendor(CPU_VENDOR_AMD, CPU_VENDOR_AMD_LENGTH);

    if (!bResult)
        supPrintfEvent(kduEventError, "[!] Abort, AMD CPU is required.\r\n");

    return bResult;
}


/*
* RmReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI RmReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;

    RMDRV_REQUEST* pRequest;
    SIZE_T size;

    size = sizeof(RMDRV_REQUEST) + NumberOfBytes;
    pRequest = (RMDRV_REQUEST*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->PhysicalAddress.QuadPart = PhysicalAddress;
            pRequest->Size = NumberOfBytes;

            bResult = supCallDriver(DeviceHandle,
                IOCTL_AMDRM_READ_MEMORY,
                pRequest,
                sizeof(RMDRV_REQUEST),
                pRequest,
                (ULONG)size);

            if (bResult) {

                RtlCopyMemory(
                    Buffer,
                    RtlOffsetToPointer(pRequest, sizeof(RMDRV_REQUEST)),
                    NumberOfBytes);

            }

            VirtualUnlock(pRequest, size);
        }

        VirtualFree(pRequest, 0, MEM_RELEASE);

    }

    return bResult;
}

/*
* RmWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI RmWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    RMDRV_REQUEST* pRequest;
    SIZE_T size;

    size = sizeof(RMDRV_REQUEST) + NumberOfBytes;

    pRequest = (RMDRV_REQUEST*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->PhysicalAddress.QuadPart = PhysicalAddress;
            pRequest->Size = NumberOfBytes;

            RtlCopyMemory(
                RtlOffsetToPointer(pRequest, sizeof(RMDRV_REQUEST)),
                Buffer,
                NumberOfBytes);

            bResult = supCallDriver(DeviceHandle,
                IOCTL_AMDRM_WRITE_MEMORY,
                pRequest,
                (ULONG)size,
                NULL,
                0);

            VirtualUnlock(pRequest, size);
        }

        VirtualFree(pRequest, 0, MEM_RELEASE);

    }

    return bResult;
}
