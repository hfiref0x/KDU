/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.44
*
*  DATE:        10 Jul 2025
*
*  Hamakaze main logic and entrypoint.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define CMD_PRV         L"-prv"
#define CMD_MAP         L"-map"
#define CMD_SCV         L"-scv"
#define CMD_PS          L"-ps"
#define CMD_PSE         L"-pse"
#define CMD_DMP         L"-dmp"
#define CMD_DSE         L"-dse"
#define CMD_LIST        L"-list"
#define CMD_SI          L"-diag"
#define CMD_TEST        L"-test"
#define CMD_RNG         L"-rng"

#define CMD_DRVNAME     L"-drvn"
#define CMD_DRVREG      L"-drvr"

#define T_KDUUSAGE   "[?] No valid parameters combination specified or command is not recognized, see Usage for help\r\n"\
                     "[?] Usage: kdu [Provider][Command]\r\n\n"\
                     "Parameters: \r\n"\
                     "kdu -list         - List available providers\r\n"\
                     "kdu -diag         - Run system diagnostic for troubleshooting\r\n"\
                     "kdu -prv id       - Optional, sets provider id to be used with rest of commands, default 0\r\n"\
                     "kdu -pse cmdline  - Launch program as PPL\r\n"\
                     "kdu -dmp pid      - Dump virtual memory of the given process\r\n"\
                     "kdu -ps pid       - Disable ProtectedProcess for given pid\r\n"\
                     "kdu -dse value    - Write user defined value to the system DSE state flags\r\n"\
                     "kdu -map filename - Map driver to the kernel and execute it entry point, this command have dependencies listed below\r\n"\
                     "-scv version      - Optional, select shellcode version, default 1\r\n"\
                     "-drvn name        - Driver object name (only valid for shellcode version 3)\r\n"\
                     "-drvr name        - Optional, driver registry key name (only valid for shellcode version 3)\r\n"

#define T_PRNTDEFAULT   "%s\r\n"

/*
* KDUProcessDmpSwitch
*
* Purpose:
*
* Handle -dmp switch.
*
*/
INT KDUProcessDmpSwitch(
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ ULONG ProviderId,
    _In_ HANDLE ProcessId)
{
    INT retVal = 0;
    KDU_CONTEXT* provContext;

    provContext = KDUProviderCreate(ProviderId,
        HvciEnabled,
        NtBuildNumber,
        KDU_SHELLCODE_NONE,
        ActionTypeDumpProcess);

    if (provContext) {
        retVal = KDUDumpProcessMemory(provContext, ProcessId);
        KDUProviderRelease(provContext);
    }

    return retVal;
}

/*
* KDUProcessPSEObjectSwitch
*
* Purpose:
*
* Handle -pse switch.
*
*/
INT KDUProcessPSEObjectSwitch(
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ ULONG ProviderId,
    _In_ LPWSTR CommandLine
)
{
    INT retVal = 0;
    KDU_CONTEXT* provContext;

    provContext = KDUProviderCreate(ProviderId,
        HvciEnabled,
        NtBuildNumber,
        KDU_SHELLCODE_NONE,
        ActionTypeDKOM);

    if (provContext) {
        retVal = KDURunCommandPPL(provContext, CommandLine);
        KDUProviderRelease(provContext);
    }

    return retVal;
}

/*
* KDUProcessPSObjectSwitch
*
* Purpose:
*
* Handle -ps switch.
*
*/
INT KDUProcessPSObjectSwitch(
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ ULONG ProviderId,
    _In_ ULONG_PTR ProcessId
)
{
    INT retVal = 0;
    KDU_CONTEXT* provContext;

    provContext = KDUProviderCreate(ProviderId,
        HvciEnabled,
        NtBuildNumber,
        KDU_SHELLCODE_NONE,
        ActionTypeDKOM);

    if (provContext) {
        retVal = KDUUnprotectProcess(provContext, ProcessId);
        KDUProviderRelease(provContext);
    }

    return retVal;
}

/*
* KDUProcessDSEFixSwitch
*
* Purpose:
*
* Handle -dse switch.
*
*/
INT KDUProcessDSEFixSwitch(
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ ULONG ProviderId,
    _In_ ULONG DSEValue
)
{
    INT retVal = 0;
    KDU_CONTEXT* provContext;
    ULONG_PTR ciVarAddress;

    provContext = KDUProviderCreate(ProviderId,
        HvciEnabled,
        NtBuildNumber,
        KDU_SHELLCODE_NONE,
        ActionTypeDSECorruption);

    if (provContext) {

        if (provContext->Provider->Callbacks.ControlDSE) {

            ciVarAddress = KDUQueryCodeIntegrityVariableAddress(NtBuildNumber);

            if (ciVarAddress == 0) {

                ciVarAddress = KDUQueryCodeIntegrityVariableSymbol(NtBuildNumber);

            }

            if (ciVarAddress == 0) {

                supPrintfEvent(kduEventError,
                    "[!] Could not query system variable address, abort.\r\n");

            }
            else {

                retVal = provContext->Provider->Callbacks.ControlDSE(provContext,
                    DSEValue,
                    ciVarAddress);

            }

        }
        KDUProviderRelease(provContext);
    }

    return retVal;
}

/*
* KDUProcessDrvMapSwitch
*
* Purpose:
*
* Handle -map switch.
*
*/
INT KDUProcessDrvMapSwitch(
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ ULONG ProviderId,
    _In_ ULONG ShellVersion,
    _In_ LPWSTR DriverFileName,
    _In_opt_ LPWSTR DriverObjectName,
    _In_opt_ LPWSTR DriverRegistryPath
)
{
    INT retVal = 0;
    KDU_CONTEXT* provContext;

    if (!RtlDoesFileExists_U(DriverFileName)) {

        supPrintfEvent(kduEventError,
            "[!] Input file cannot be found, abort.\r\n");

        return 0;
    }

    printf_s("[*] Driver mapping using shellcode version: %lu\r\n", ShellVersion);

    if (ShellVersion == KDU_SHELLCODE_V3) {

        if (DriverObjectName == NULL) {

            supPrintfEvent(kduEventError, "[!] Driver object name is required when working with this shellcode\r\n"\
                "[?] Use the following commands to supply object name and optionally registry key name\r\n"\
                "\t-drvn [ObjectName] and/or\r\n"\
                "\t-drvr [ObjectKeyName]\r\n"\
                "\te.g. kdu -scv 3 -drvn MyName -map MyDriver.sys\r\n"
            );

            return 0;
        }
        else {
            printf_s("[+] Driver object name: \"%ws\"\r\n", DriverObjectName);
        }

        if (DriverRegistryPath) {
            printf_s("[+] Registry key name: \"%ws\"\r\n", DriverRegistryPath);
        }
        else {
            printf_s("[+] No driver registry key name specified, driver object name will be used instead\r\n");
        }

    }

    PVOID pvImage = NULL;
    NTSTATUS ntStatus = supLoadFileForMapping(DriverFileName, &pvImage);

    if ((!NT_SUCCESS(ntStatus)) || (pvImage == NULL)) {
        supShowHardError("[!] Error while loading input driver file", ntStatus);
        return 0;
    }
    else {
        printf_s("[+] Input driver file \"%ws\" loaded at 0x%p\r\n", DriverFileName, pvImage);

        provContext = KDUProviderCreate(ProviderId,
            HvciEnabled,
            NtBuildNumber,
            ShellVersion,
            ActionTypeMapDriver);

        if (provContext) {

            if (ShellVersion == KDU_SHELLCODE_V3) {

                if (DriverObjectName) {
                    ScCreateFixedUnicodeString(&provContext->DriverObjectName,
                        DriverObjectName);

                }

                //
                // Registry path name is optional.
                // If not specified we will assume its the same name as driver object.
                //
                if (DriverRegistryPath) {
                    ScCreateFixedUnicodeString(&provContext->DriverRegistryPath,
                        DriverRegistryPath);
                }

            }

            retVal = provContext->Provider->Callbacks.MapDriver(provContext, pvImage);
            KDUProviderRelease(provContext);
        }

        LdrUnloadDll(pvImage);
    }

    return retVal;
}

/*
* KDUProcessCommandLine
*
* Purpose:
*
* Parse command line and do stuff.
*
*/
INT KDUProcessCommandLine(
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber
)
{
    INT         retVal = 0;
    ULONG       providerId = KDU_PROVIDER_DEFAULT, dseValue = 0, paramLength = 0, shellVersion;
    ULONG_PTR   processId;
    LPWSTR      lpParam1, lpParam2;
    WCHAR       szParameter[MAX_PATH], szExtraParameter[MAX_PATH];

    FUNCTION_ENTER_MSG(__FUNCTION__);

    RtlSecureZeroMemory(szParameter, sizeof(szParameter));
    RtlSecureZeroMemory(szExtraParameter, sizeof(szExtraParameter));

    do {

#ifdef _DEBUG

        //
        // Test switches, never used/present in the release build.
        //

        if (supGetCommandLineOption(CMD_TEST,
            FALSE,
            NULL,
            0,
            NULL))
        {
            KDUTest();
            retVal = 1;
            break;
        }

        if (supGetCommandLineOption(CMD_RNG,
            FALSE,
            NULL,
            0,
            NULL))
        {
            DWORD dwKey = 0;
            if (supGenRandom((PBYTE)&dwKey, sizeof(DWORD))) {
                printf_s("[+] RNG: %lu\r\n", dwKey);
            }
            else {
                printf_s("[!] RNG failed\r\n");
            }
            retVal = 1;
            break;
        }

#endif
        //
        // List providers.
        //
        if (supGetCommandLineOption(CMD_LIST,
            FALSE,
            NULL,
            0,
            NULL))
        {
            KDUProvList();
            retVal = 1;
            break;
        }

        //
        // List system information
        //
        if (supGetCommandLineOption(CMD_SI,
            FALSE,
            NULL,
            0,
            NULL))
        {
            KDUDiagStart();
            retVal = 1;
            break;
        }

        //
        // Select CVE provider.
        //
        if (supGetCommandLineOption(CMD_PRV,
            TRUE,
            szParameter,
            RTL_NUMBER_OF(szParameter),
            NULL))
        {
            providerId = _strtoul(szParameter);
            if (providerId >= KDUProvGetCount()) {

                supPrintfEvent(kduEventError,
                    "[!] Invalid provider id %lu specified, default will be used (%lu)\r\n",
                    providerId,
                    KDU_PROVIDER_DEFAULT);

                providerId = KDU_PROVIDER_DEFAULT;

            }

            printf_s("[+] Selected provider: %lu\r\n", providerId);
        }

        //
        // Mutually exclusive commands.
        // -dse -map -ps
        //

        //
        // Check if -dse specified.
        //
        if (supGetCommandLineOption(CMD_DSE,
            TRUE,
            szParameter,
            RTL_NUMBER_OF(szParameter),
            NULL))
        {
            dseValue = _strtoul(szParameter);
            retVal = KDUProcessDSEFixSwitch(HvciEnabled,
                NtBuildNumber,
                providerId,
                dseValue);
        }
        else

            //
            // Check if -map specified.
            //
            if (supGetCommandLineOption(CMD_MAP,
                TRUE,
                szParameter,
                RTL_NUMBER_OF(szParameter),
                &paramLength))
            {
                if (paramLength == 0) {

                    supPrintfEvent(kduEventError,
                        "[!] Input file not specified\r\n");

                }
                else {

                    //
                    // Shell selection, -scv switch.
                    //
                    shellVersion = KDU_SHELLCODE_V1;

                    if (supGetCommandLineOption(CMD_SCV,
                        TRUE,
                        szExtraParameter,
                        RTL_NUMBER_OF(szExtraParameter),
                        NULL))
                    {
                        shellVersion = _strtoul(szExtraParameter);
                        if (shellVersion == 0 || shellVersion > KDU_SHELLCODE_VMAX) {

                            supPrintfEvent(kduEventError,
                                "[!] Unrecognized shellcode version %lu, default will be used (%lu)\r\n",
                                shellVersion,
                                KDU_SHELLCODE_V1);

                            shellVersion = KDU_SHELLCODE_V1;
                        }
                    }

                    WCHAR szDriverName[MAX_PATH], szDriverRegPath[MAX_PATH];

                    //
                    // Process extra DRVN/DRVR commands if present.
                    //
                    RtlSecureZeroMemory(szDriverName, sizeof(szDriverName));
                    paramLength = 0;
                    supGetCommandLineOption(CMD_DRVNAME,
                        TRUE,
                        szDriverName,
                        RTL_NUMBER_OF(szDriverName),
                        &paramLength);

                    lpParam1 = (paramLength != 0) ? szDriverName : NULL;

                    RtlSecureZeroMemory(szDriverRegPath, sizeof(szDriverRegPath));
                    paramLength = 0;
                    supGetCommandLineOption(CMD_DRVREG,
                        TRUE,
                        szDriverRegPath,
                        RTL_NUMBER_OF(szDriverRegPath),
                        &paramLength);

                    lpParam2 = (paramLength != 0) ? szDriverRegPath : NULL;

                    retVal = KDUProcessDrvMapSwitch(HvciEnabled,
                        NtBuildNumber,
                        providerId,
                        shellVersion,
                        szParameter,
                        lpParam1,
                        lpParam2);

                }
            }

            else

                //
                // Check if -ps specified.
                //
                if (supGetCommandLineOption(CMD_PS,
                    TRUE,
                    szParameter,
                    RTL_NUMBER_OF(szParameter),
                    NULL))
                {
                    processId = strtou64(szParameter);

                    retVal = KDUProcessPSObjectSwitch(HvciEnabled,
                        NtBuildNumber,
                        providerId,
                        processId);
                }

                else if (supGetCommandLineOption(CMD_PSE,
                    TRUE,
                    szParameter,
                    RTL_NUMBER_OF(szParameter),
                    NULL))
                {
                    retVal = KDUProcessPSEObjectSwitch(HvciEnabled,
                        NtBuildNumber,
                        providerId,
                        szParameter);
                }

                else if (supGetCommandLineOption(CMD_DMP,
                    TRUE,
                    szParameter,
                    RTL_NUMBER_OF(szParameter),
                    NULL))
                {
                    processId = strtou64(szParameter);

                    retVal = KDUProcessDmpSwitch(HvciEnabled,
                        NtBuildNumber,
                        providerId,
                        (HANDLE)processId);
                }

                else {
                    //
                    // Nothing set, show help.
                    //
                    printf_s(T_PRNTDEFAULT, T_KDUUSAGE);
                }

    } while (FALSE);

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return retVal;
}

/*
* KDUMain
*
* Purpose:
*
* KDU main.
*
*/
int KDUMain()
{
    INT iResult = 0;
    OSVERSIONINFO osv;

#ifdef _DEBUG
    printf_s("[*] Debug Mode Run, several features (like a shellcode proper generation) will be unavailable\r\n");
#endif

    FUNCTION_ENTER_MSG(__FUNCTION__);

    do {

        CHAR vendorString[0x20];

        RtlFillMemory(vendorString, sizeof(vendorString), 0);
        GET_CPU_VENDOR_STRING(vendorString);
        printf_s("[*] CPU vendor string: %s\r\n", vendorString);

        RtlSecureZeroMemory(&osv, sizeof(osv));
        osv.dwOSVersionInfoSize = sizeof(osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
        if ((osv.dwMajorVersion < 6) ||
            (osv.dwMajorVersion == 6 && osv.dwMinorVersion == 0) ||
            (osv.dwBuildNumber == NT_WIN7_RTM))
        {

            supPrintfEvent(kduEventError,
                "[!] Unsupported WinNT version\r\n");

            iResult = ERROR_UNKNOWN_REVISION;
            break;
        }

        if (!ntsupUserIsFullAdmin()) {
            supPrintfEvent(kduEventError, "[!] Administrator privileges are required to continue.\r\n"\
                "[!] Verify that you have sufficient privileges and you are not running program under any compatibility layer.\r\n");
            iResult = ERROR_PRIVILEGE_NOT_HELD;
            break;
        }

        CHAR szVersion[100];

        StringCchPrintfA(szVersion, 100,
            "[*] Windows version: %u.%u build %u",
            osv.dwMajorVersion,
            osv.dwMinorVersion,
            osv.dwBuildNumber);

        printf_s(T_PRNTDEFAULT, szVersion);

        BOOLEAN secureBoot;

        if (supQuerySecureBootState(&secureBoot)) {
            printf_s("[*] SecureBoot is %sbled on this machine\r\n", secureBoot ? "ena" : "disa");
        }

        BOOLEAN hvciEnabled;
        BOOLEAN hvciStrict;
        BOOLEAN hvciIUM;

        //
        // Providers maybe *not* HVCI compatible.
        //
        if (supQueryHVCIState(&hvciEnabled, &hvciStrict, &hvciIUM)) {

            if (hvciEnabled) {
                printf_s("[*] Windows HVCI mode detected\r\n");
            }

        }

        SYSTEM_CODEINTEGRITY_INFORMATION ciPolicy;
        ULONG dummy = 0;

        ciPolicy.Length = sizeof(ciPolicy);
        ciPolicy.CodeIntegrityOptions = 0;
        if (NT_SUCCESS(NtQuerySystemInformation(
            SystemCodeIntegrityInformation,
            &ciPolicy,
            sizeof(ciPolicy),
            &dummy)))
        {
            if (ciPolicy.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
                printf_s("[*] Test Mode ENABLED\r\n");

            if (ciPolicy.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED)
                printf_s("[*] Debug Mode ENABLED\r\n");

            if (ciPolicy.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED)
                printf_s("[*] HVCI KMCI ENABLED\r\n");

            if (ciPolicy.CodeIntegrityOptions & CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED)
                printf_s("[*] WHQL enforcement ENABLED\r\n");

        }

        if (osv.dwBuildNumber >= NT_WIN10_REDSTONE5) {
            BOOL bEnabled = FALSE;
            if (supDetectMsftBlockList(&bEnabled, FALSE)) {
                printf_s("[+] MSFT Driver block list is %sbled\r\n", (bEnabled) ? "ena" : "disa");
            }
        }

        iResult = KDUProcessCommandLine(hvciEnabled, osv.dwBuildNumber);

    } while (FALSE);

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return iResult;
}

/*
* KDUIntroBanner
*
* Purpose:
*
* Display general KDU version info.
*
*/
VOID KDUIntroBanner()
{
    IMAGE_NT_HEADERS* ntHeaders = RtlImageNtHeader(NtCurrentPeb()->ImageBaseAddress);

    printf_s("[#] Kernel Driver Utility v%lu.%lu.%lu (build %lu) started, (c)2020 - %lu KDU Project\r\n"\
        "[#] Built at %s, header checksum 0x%lX\r\n"\
        "[#] Supported x64 OS : Windows 7 and above\r\n",
        KDU_VERSION_MAJOR,
        KDU_VERSION_MINOR,
        KDU_VERSION_REVISION,
        KDU_VERSION_BUILD,
        KDU_COPYRIGHT_YEAR,
        __TIMESTAMP__,
        ntHeaders->OptionalHeader.CheckSum);
}

/*
* KDUCheckAnotherInstance
*
* Purpose:
*
* Check if there is another instance running.
*
*/
UINT KDUCheckAnotherInstance()
{
    HANDLE mutantHandle;
    WCHAR szObject[MAX_PATH + 1];
    WCHAR szName[128];

    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usName;

    RtlSecureZeroMemory(szName, sizeof(szName));
    RtlSecureZeroMemory(szObject, sizeof(szObject));

    supGenerateSharedObjectName(KDU_SYNC_MUTANT, (LPWSTR)&szName);

    StringCchPrintf(szObject,
        MAX_PATH,
        L"\\BaseNamedObjects\\%ws",
        szName);

    RtlInitUnicodeString(&usName, szObject);
    InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS status = NtCreateMutant(&mutantHandle, MUTANT_ALL_ACCESS, &obja, FALSE);

    if (status == STATUS_OBJECT_NAME_COLLISION) {
        return ERROR_ALREADY_EXISTS;
    }

    return 0;
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
int main()
{
    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
    KDUIntroBanner();

    int retVal = KDUCheckAnotherInstance();

    if (retVal != ERROR_ALREADY_EXISTS) {

        __try {
            retVal = KDUMain();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf_s("[!] Unhandled exception 0x%lx\r\n", GetExceptionCode());
            return -1;
        }

    }
    else {
        supPrintfEvent(kduEventError,
            "[!] Another instance is running, close it before\r\n");
    }

    printf_s("[+] Return value: %d. Bye-bye!\r\n", retVal);
    return retVal;
}
