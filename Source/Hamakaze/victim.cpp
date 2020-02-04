/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2020
*
*  TITLE:       VICTIM.CPP
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
*
*  Victim support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* VictimLoadUnload
*
* Purpose:
*
* Load/Unload driver using Native API.
* This routine will try to force unload driver on loading if Force parameter set to TRUE.
*
*/
BOOL VictimLoadUnload(
    _In_ LPWSTR Name,
    _In_ LPWSTR ImagePath,
    _In_ BOOLEAN Force,
    _In_ BOOLEAN Unload,
    _Out_opt_ NTSTATUS* ErrorStatus)
{
    NTSTATUS ntStatus;

    if (Unload) {
        ntStatus = supUnloadDriver(Name, TRUE);
    }
    else {
        ntStatus = supLoadDriver(Name, ImagePath, Force);
    }

    if (ErrorStatus)
        *ErrorStatus = ntStatus;

    return (NT_SUCCESS(ntStatus));
}

/*
* VictimBuildName
*
* Purpose:
*
* Create filepath to %temp% with given victim name.
*
*/
LPWSTR VictimBuildName(
    _In_ LPWSTR VictimName
)
{
    LPWSTR FileName;
    SIZE_T Length = (1024 + _strlen(VictimName)) * sizeof(WCHAR);

    FileName = (LPWSTR)supHeapAlloc(Length);
    if (FileName == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    else {

        DWORD cch = supExpandEnvironmentStrings(L"%temp%\\", FileName, MAX_PATH);
        if (cch == 0 || cch > MAX_PATH) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            supHeapFree(FileName);
            FileName = NULL;
        }
        else {
            _strcat(FileName, VictimName);
            _strcat(FileName, L".sys");
        }
    }

    return FileName;
}

/*
* VictimCreate
*
* Purpose:
*
* Drop, load and reference victim driver.
*
*/
BOOL VictimCreate(
    _In_ HINSTANCE ModuleBase,
    _In_ LPWSTR Name, //same as device name
    _In_ ULONG ResourceId,
    _Out_opt_ PHANDLE VictimHandle)
{
    PBYTE  drvBuffer = NULL;
    ULONG  resourceSize = 0;
    LPWSTR driverFileName = NULL;
    HANDLE deviceHandle = NULL;

    if (VictimHandle)
        *VictimHandle = NULL;

    driverFileName = VictimBuildName(Name);
    if (driverFileName) {

        do {
            
            if (supIsObjectExists((LPWSTR)L"\\Device", Name)) {
                printf_s("[!] Victim driver already loaded, force reload\r\n");

                printf_s("[!] Attempt to unload %ws\r\n", Name);

                NTSTATUS ntStatus;
                if (!VictimLoadUnload(Name, driverFileName, FALSE, TRUE, &ntStatus)) {
                    printf_s("[!] Could not force unload victim, NTSTATUS(0x%lX) abort\r\n", ntStatus);
                    break;
                }
                else {
                    printf_s("[+] Previous instance of victim driver unloaded\r\n");
                }
            }

            drvBuffer = supQueryResourceData(ResourceId, ModuleBase, &resourceSize);
            if (drvBuffer == NULL) {
                SetLastError(ERROR_FILE_NOT_FOUND);
                break;
            }

            NTSTATUS ntStatus;
            ULONG writeBytes;

            printf_s("[+] Extracting victim driver \"%ws\" as \"%ws\"\r\n", Name, driverFileName);

            writeBytes = (ULONG)supWriteBufferToFile(driverFileName,
                drvBuffer,
                resourceSize,
                TRUE,
                FALSE,
                &ntStatus);

            supHeapFree(drvBuffer);

            if (resourceSize != writeBytes) {
                printf_s("[!] Could not extract victim driver, NTSTATUS(0x%lX) abort\r\n", ntStatus);
                SetLastError(RtlNtStatusToDosError(ntStatus));
                break;
            }

            ntStatus = STATUS_UNSUCCESSFUL;
            if (VictimLoadUnload(Name, driverFileName, TRUE, FALSE, &ntStatus)) {

                SetLastError(RtlNtStatusToDosError(ntStatus));

                if (VictimHandle) {
                   
                    ntStatus = supOpenDriver(Name, &deviceHandle);
                    if (NT_SUCCESS(ntStatus)) {
                        *VictimHandle = deviceHandle;
                    }
                    else {
                        SetLastError(RtlNtStatusToDosError(ntStatus));
                    }
                }

            }
            else {
                SetLastError(RtlNtStatusToDosError(ntStatus));
            }

        } while (FALSE);

        supHeapFree(driverFileName);
    }

    return (deviceHandle != NULL);
}

/*
* VictimRelease
*
* Purpose:
*
* Unload victim driver.
*
*/
BOOL VictimRelease(
    _In_ LPWSTR Name
)
{
    BOOL bResult = FALSE;

    LPWSTR driverFileName = VictimBuildName(Name);
    if (driverFileName) {
        bResult = VictimLoadUnload(Name, driverFileName, FALSE, TRUE, NULL);
        DeleteFile(driverFileName);
        supHeapFree(driverFileName);
    }

    return bResult;
}
