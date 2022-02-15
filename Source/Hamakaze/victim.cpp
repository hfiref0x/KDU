/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2022
*
*  TITLE:       VICTIM.CPP
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
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
* VpCreate
*
* Purpose:
*
* Load victim and obtain handle to it.
*
*/
BOOL VpCreate(
    _Inout_ PKDU_VICTIM_PROVIDER Context,
    _In_opt_ HINSTANCE ModuleBase,
    _Out_opt_ PHANDLE VictimHandle
)
{
    supPrintfEvent(kduEventInformation, 
        "[+] Processing victim \"%ws\" driver\r\n",
        Context->Desc);

    return Context->Callbacks.Create(
        ModuleBase,
        Context->Name,
        Context->ResourceId,
        Context->DesiredAccess,
        VictimHandle);
}

/*
* VpRelease
*
* Purpose:
*
* Unload victim and close it handle.
*
*/
BOOL VpRelease(
    _In_ PKDU_VICTIM_PROVIDER Context,
    _Inout_opt_ PHANDLE VictimHandle
)
{
    HANDLE victimHandle;

    if (VictimHandle) {
        victimHandle = *VictimHandle;
        if (victimHandle) {
            NtClose(victimHandle);
            *VictimHandle = NULL;
        }
    }
    
    return Context->Callbacks.Release(Context->Name);
}

/*
* VpExecutePayload
*
* Purpose:
*
* Execute payload inside victim.
*
*/
VOID VpExecutePayload(
    _In_ PKDU_VICTIM_PROVIDER Context,
    _Out_opt_ PHANDLE VictimHandle
)
{
    Context->Callbacks.Execute(Context->Name, 
        Context->DesiredAccess, 
        VictimHandle);
}

/*
* VppLoadUnloadDriver
*
* Purpose:
*
* Load/Unload driver using Native API.
* This routine will try to force unload driver on loading if Force parameter set to TRUE.
*
*/
BOOL VppLoadUnloadDriver(
    _In_ LPCWSTR Name,
    _In_ LPCWSTR ImagePath,
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
* VppBuildDriverName
*
* Purpose:
*
* Create filepath for given victim name.
*
*/
LPWSTR VppBuildDriverName(
    _In_ LPCWSTR VictimName
)
{
    LPWSTR lpFileName;
    SIZE_T Length = (MAX_PATH + _strlen(VictimName)) * sizeof(WCHAR);

    lpFileName = (LPWSTR)supHeapAlloc(Length);
    if (lpFileName == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    else {

        StringCchPrintf(lpFileName,
            MAX_PATH * 2,
            L"%ws\\system32\\drivers\\%ws.sys",
            USER_SHARED_DATA->NtSystemRoot,
            VictimName);

    }

    return lpFileName;
}

/*
* VpCreateCallback
*
* Purpose:
*
* Drop, load and reference victim driver.
*
*/
BOOL VpCreateCallback(
    _In_ HINSTANCE ModuleBase,
    _In_ LPCWSTR Name, //same as device name
    _In_ ULONG ResourceId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE VictimHandle)
{
    PBYTE  drvBuffer = NULL;
    ULONG  resourceSize = 0;
    LPWSTR driverFileName = NULL;
    HANDLE deviceHandle = NULL;

    if (VictimHandle)
        *VictimHandle = NULL;

    driverFileName = VppBuildDriverName(Name);
    if (driverFileName) {

        do {
            
            if (supIsObjectExists((LPWSTR)L"\\Device", Name)) {
                
                supPrintfEvent(kduEventError, 
                    "[!] Victim driver already loaded, force reload\r\n");

                supPrintfEvent(kduEventError, 
                    "[!] Attempt to unload %ws\r\n", Name);

                NTSTATUS ntStatus;
                if (!VppLoadUnloadDriver(Name, driverFileName, FALSE, TRUE, &ntStatus)) {
                    
                    supPrintfEvent(kduEventError, 
                        "[!] Could not force unload victim, NTSTATUS(0x%lX) abort\r\n", 
                        ntStatus);
                    
                    break;
                }
                else {
                    supPrintfEvent(kduEventInformation, 
                        "[+] Previous instance of victim driver unloaded\r\n");
                }
            }

            drvBuffer = (PBYTE)KDULoadResource(ResourceId, 
                ModuleBase, 
                &resourceSize,
                PROVIDER_RES_KEY,
                TRUE);

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
                
                supPrintfEvent(kduEventError, 
                    "[!] Could not extract victim driver, NTSTATUS(0x%lX) abort\r\n", 
                    ntStatus);
                
                SetLastError(RtlNtStatusToDosError(ntStatus));
                break;
            }

            ntStatus = STATUS_UNSUCCESSFUL;
            if (VppLoadUnloadDriver(Name, driverFileName, TRUE, FALSE, &ntStatus)) {

                SetLastError(RtlNtStatusToDosError(ntStatus));

                if (VictimHandle) {
                   
                    ntStatus = supOpenDriver(Name, DesiredAccess, &deviceHandle);
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
* VpReleaseCallback
*
* Purpose:
*
* Unload victim driver.
*
*/
BOOL VpReleaseCallback(
    _In_ LPCWSTR Name
)
{
    BOOL bResult = FALSE;

    LPWSTR driverFileName = VppBuildDriverName(Name);
    if (driverFileName) {
        bResult = VppLoadUnloadDriver(Name, driverFileName, FALSE, TRUE, NULL);
        DeleteFile(driverFileName);
        supHeapFree(driverFileName);
    }

    return bResult;
}

/*
* VpExecuteCallback
*
* Purpose:
*
* Execute victim payload.
*
*/
VOID VpExecuteCallback(
    _In_ LPCWSTR Name,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE VictimHandle
)
{
    supOpenDriver(Name, DesiredAccess, VictimHandle);
}

/*
* VppOpenExistingDriverDevice
*
* Purpose:
*
* Open existing victim by it device name.
*
*/
BOOL VppOpenExistingDriverDevice(
    _In_ LPCWSTR Name,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE VictimHandle
)
{
    HANDLE deviceHandle = NULL;
    NTSTATUS ntStatus;
    LPWSTR lpDeviceName;
    SIZE_T sz;

    if (VictimHandle)
        *VictimHandle = NULL;

    sz = 64 + (1 + _strlen(Name)) * sizeof(WCHAR);
    lpDeviceName = (LPWSTR)supHeapAlloc(sz);
    if (lpDeviceName) {

        StringCchPrintf(lpDeviceName,
            sz / sizeof(WCHAR),
            L"\\Device\\%ws",
            Name);

        ntStatus = supOpenDriverEx(lpDeviceName, DesiredAccess, &deviceHandle);
        if (NT_SUCCESS(ntStatus)) {
            if (VictimHandle)
                *VictimHandle = deviceHandle;
        }
        else {
            SetLastError(RtlNtStatusToDosError(ntStatus));
        }

        supHeapFree(lpDeviceName);
    }

    return (deviceHandle != NULL);
}

/*
* VpExecuteFromExistingCallback
*
* Purpose:
*
* Execute victim payload in existing loaded driver.
*
*/
VOID VpExecuteFromExistingCallback(
    _In_ LPCWSTR Name,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE VictimHandle
)
{
    VppOpenExistingDriverDevice(Name, DesiredAccess, VictimHandle);
}

/*
* VpCreateFromExistingCallback
*
* Purpose:
*
* Create victim from existing loaded driver.
*
*/
BOOL VpCreateFromExistingCallback(
    _In_ HINSTANCE ModuleBase,
    _In_ LPCWSTR Name,
    _In_ ULONG ResourceId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE VictimHandle)
{
    UNREFERENCED_PARAMETER(ModuleBase);
    UNREFERENCED_PARAMETER(ResourceId);

    return VppOpenExistingDriverDevice(Name, DesiredAccess, VictimHandle);
}

/*
* VpReleaseCallbackStub
*
* Purpose:
*
* Stub routine.
*
*/
BOOL VpReleaseCallbackStub(
    _In_ LPCWSTR Name
)
{
    UNREFERENCED_PARAMETER(Name);

    return TRUE;
}
