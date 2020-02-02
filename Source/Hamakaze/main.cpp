/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
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

KDU_CONTEXT* g_ProvContext;

#pragma data_seg("iris")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:iris,RWS")

#define T_KDUUNSUP   "[!] Unsupported WinNT version"
#define T_KDURUN     "[!] Another instance running, close it before"

#define CMD_PRV         L"-prv"
#define CMD_MAP         L"-map"
#define CMD_PS          L"-ps"
#define CMD_LIST        L"-list"
#define CMD_COMPRESS    L"-compress"

#define T_KDUUSAGE   "[?] No parameters specified, see Usage for help\r\n[?] Usage: kdu Mode [Provider][Command]\r\n\n"\
                     "Parameters: \r\n"\
                     "kdu -prv id       - optional parameter, provider id, default 0\r\n"\
                     "kdu -ps pid       - disable ProtectedProcess for given pid\r\n"\
                     "kdu -map filename - map driver to the kernel and execute it entry point\r\n"\
                     "kdu -list         - list available providers\r\n"                     

#define T_KDUINTRO   "[+] Kernel Driver Utility v1.0.0 started, (c) 2020 KDU Project\r\n[+] Supported x64 OS: Windows 7 and above"
#define T_PRNTDEFAULT   "%s\r\n"

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
    INT     retVal = -1;
    ULONG   providerId = KDU_PROVIDER_DEFAULT;
    WCHAR   szParameter[MAX_PATH + 1];

    HINSTANCE hInstance = GetModuleHandle(NULL);

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    RtlSecureZeroMemory(szParameter, sizeof(szParameter));

    do {

        //
        // List providers.
        //
        if (supGetCommandLineOption(CMD_LIST,
            FALSE,
            NULL,
            0))
        {
            KDUProvList();
            retVal = 0;
            break;
        }

        if (supGetCommandLineOption(CMD_COMPRESS,
            TRUE,
            szParameter,
            sizeof(szParameter) / sizeof(WCHAR)))
        {
            KDUCompressResource(szParameter);
            retVal = 0;
            break;
        }

        //
        // Select CVE provider.
        //
        if (supGetCommandLineOption(CMD_PRV,
            TRUE,
            szParameter,
            sizeof(szParameter) / sizeof(WCHAR)))
        {
            providerId = strtoul(szParameter);
            if (providerId >= KDU_PROVIDERS_MAX)
                providerId = KDU_PROVIDER_DEFAULT;
        }

        //
        // Check if -map specified.
        //
        if (supGetCommandLineOption(CMD_MAP,
            TRUE,
            szParameter,
            sizeof(szParameter) / sizeof(WCHAR)))
        {
            //map driver
            if (RtlDoesFileExists_U(szParameter)) {

                g_ProvContext = KDUProviderCreate(providerId,
                    HvciEnabled,
                    NtBuildNumber,
                    hInstance,
                    ActionTypeMapDriver);

                if (g_ProvContext) {
                    retVal = KDUMapDriver(g_ProvContext, szParameter);
                    KDUProviderRelease(g_ProvContext);
                }
            }
            else {
                printf_s("[!] Input file not found\r\n");
            }
        }

        else

            //
            // Check if -ps specified.
            //
            if (supGetCommandLineOption(CMD_PS,
                TRUE,
                szParameter,
                sizeof(szParameter) / sizeof(WCHAR)))
            {
                g_ProvContext = KDUProviderCreate(providerId,
                    HvciEnabled,
                    NtBuildNumber,
                    hInstance,
                    ActionTypeDKOM);

                if (g_ProvContext) {

                    if (KDUControlProcess(g_ProvContext, strtou64(szParameter)))
                        retVal = 0;

                    KDUProviderRelease(g_ProvContext);
                }
            }

            else {
                //
                // Nothing set, show help.
                //
                printf_s(T_PRNTDEFAULT, T_KDUUSAGE);
            }

    } while (FALSE);

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
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
    INT iResult = -1;
    OSVERSIONINFO osv;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    do {

        x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
        if (x > 1) {
            printf_s(T_PRNTDEFAULT, T_KDURUN);
            break;
        }

        RtlSecureZeroMemory(&osv, sizeof(osv));
        osv.dwOSVersionInfoSize = sizeof(osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
        if (osv.dwMajorVersion < 6) {
            printf_s(T_PRNTDEFAULT, T_KDUUNSUP);
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
            printf_s("[*] SecureBoot is %s on this machine\r\n", secureBoot ? "enabled" : "disabled");
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

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return iResult;
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

    printf_s(T_PRNTDEFAULT, T_KDUINTRO);  

    int retVal = 0;

    __try {
        retVal = KDUMain();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf_s("[!] Unhandled exception 0x%lx\r\n", GetExceptionCode());
    }
    return retVal;
}
