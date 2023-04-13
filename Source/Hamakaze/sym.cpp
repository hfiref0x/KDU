/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       SYM.CPP
*
*  VERSION:     1.31
*
*  DATE:        08 Apr 2023
*
*  Program symbols support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include <dbghelp.h>

static HMODULE g_hDbgHelp = NULL;
static HMODULE g_hSymSrv = NULL;
static BOOL g_symInitialized = FALSE;

typedef  DWORD(WINAPI* pfnSymSetOptions)(
    _In_ DWORD   SymOptions
    );

typedef BOOL(WINAPI* pfnSymInitialize)(
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR UserSearchPath,
    _In_ BOOL fInvadeProcess);

typedef DWORD64(WINAPI* pfnSymLoadModuleEx)(
    _In_ HANDLE hProcess,
    _In_opt_ HANDLE hFile,
    _In_opt_ PCWSTR ImageName,
    _In_opt_ PCWSTR ModuleName,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD DllSize,
    _In_opt_ PMODLOAD_DATA Data,
    _In_opt_ DWORD Flags);

typedef BOOL(WINAPI* pfnSymFromName)(
    _In_ HANDLE hProcess,
    _In_ PCSTR Name,
    _Inout_ PSYMBOL_INFO Symbol);

pfnSymSetOptions SymSetOptionsProto;
pfnSymInitialize SymInitializeProto;
pfnSymLoadModuleEx SymLoadModuleExProto;
pfnSymFromName SymFromNameProto;

/*
* symLoadImageSymbols
*
* Purpose:
*
* SymLoadModuleEx wrapper.
*
*/
BOOL symLoadImageSymbols(
    _In_ LPCWSTR lpFileName,
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize)
{
    BOOL bResult = FALSE;

    if (g_symInitialized) {

        printf_s("[~] Please wait, loading symbols for %ws file.\r\n", lpFileName);

        bResult = (NULL != SymLoadModuleExProto(NtCurrentProcess(),
            NULL,
            lpFileName,
            NULL,
            (DWORD64)ImageBase,
            ImageSize,
            NULL,
            0));

        if (!bResult) {
            supShowWin32Error("[!] Failed to load symbols", GetLastError());
        }

    }

    return bResult;

}

/*
* symLookupAddressBySymbol
*
* Purpose:
*
* SymFromName wrapper.
*
*/
BOOL symLookupAddressBySymbol(
    _In_ LPCSTR SymbolName,
    _Out_ PULONG_PTR Address
)
{
    BOOL bResult = FALSE;
    SIZE_T symSize;
    ULONG64 symAddress = 0;
    PSYMBOL_INFO symbolInfo = NULL;

    if (g_symInitialized) {

        symSize = sizeof(SYMBOL_INFO);

        symbolInfo = (PSYMBOL_INFO)supHeapAlloc(symSize);
        if (symbolInfo) {

            symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbolInfo->MaxNameLen = 0;

            bResult = SymFromNameProto(
                NtCurrentProcess(),
                SymbolName,
                symbolInfo);

            if (!bResult) {

                supPrintfEvent(kduEventError,
                    "Cannot find symbol for %s name, GetLastError %lu\r\n",
                    SymbolName,
                    GetLastError());

            }

            symAddress = symbolInfo->Address;

            supHeapFree(symbolInfo);
        }

    }

    *Address = symAddress;

    return bResult;
}

/*
* symInit
*
* Purpose:
*
* Load image help dlls and initialize symbols.
*
*/
BOOL symInit()
{
    DWORD cch;
    BOOL bInitSuccess = FALSE;

    if (g_symInitialized)
        return TRUE;

    SetDllDirectory(NULL);

    do {
        WCHAR szFileName[MAX_PATH * 2];

        RtlSecureZeroMemory(&szFileName, sizeof(szFileName));

        cch = GetCurrentDirectory(MAX_PATH, szFileName);
        if (cch == 0 || cch > MAX_PATH) {
            supShowWin32Error("[!] Cannot query current directory", GetLastError());
            break;
        }

        _strcat(szFileName, TEXT("\\"));

        LPWSTR lpEnd = _strend(szFileName);

        _strcat(lpEnd, TEXT("dbghelp.dll"));

        g_hDbgHelp = LoadLibrary(szFileName);
        if (g_hDbgHelp == NULL) {
            supShowWin32Error("[!] Cannot load dbghelp.dll, make sure it is in program directory", GetLastError());
            break;
        }
        *lpEnd = 0;
        _strcat(lpEnd, TEXT("symsrv.dll"));
        g_hSymSrv = LoadLibrary(szFileName);
        if (g_hSymSrv == NULL) {

            supShowWin32Error(
                "[!] Cannot load symsrv.dll, make sure it is in program directory",
                GetLastError());

            break;
        }

        SymSetOptionsProto = (pfnSymSetOptions)GetProcAddress(g_hDbgHelp, "SymSetOptions");
        SymInitializeProto = (pfnSymInitialize)GetProcAddress(g_hDbgHelp, "SymInitializeW");

        SymLoadModuleExProto = (pfnSymLoadModuleEx)GetProcAddress(g_hDbgHelp, "SymLoadModuleExW");
        SymFromNameProto = (pfnSymFromName)GetProcAddress(g_hDbgHelp, "SymFromName");

        if (SymSetOptionsProto == NULL ||
            SymInitializeProto == NULL ||
            SymLoadModuleExProto == NULL ||
            SymFromNameProto == NULL)
        {
            supPrintfEvent(kduEventError,
                "[!] Not all symbol API pointers resolved, abort\r\n");
            break;
        }

        SymSetOptionsProto(
            SYMOPT_CASE_INSENSITIVE |
            SYMOPT_UNDNAME |
            SYMOPT_FAIL_CRITICAL_ERRORS |
            SYMOPT_EXACT_SYMBOLS |
            SYMOPT_AUTO_PUBLICS);

        WCHAR szUserSearchPath[MAX_PATH * 2];
        WCHAR szTemp[MAX_PATH + 1];

        RtlSecureZeroMemory(&szUserSearchPath, sizeof(szUserSearchPath));
        RtlSecureZeroMemory(&szTemp, sizeof(szTemp));

        cch = ExpandEnvironmentStrings(L"%temp%", szTemp, MAX_PATH);
        if (cch > 0 && cch < MAX_PATH) {

            StringCchPrintf(szUserSearchPath,
                RTL_NUMBER_OF(szUserSearchPath),
                L"srv*%ws\\Symbols*https://msdl.microsoft.com/download/symbols",
                szTemp);

        }
        else {

            supShowWin32Error("[!] Cannot query temp directory", GetLastError());

            break;
        }

        bInitSuccess = SymInitializeProto(NtCurrentProcess(),
            szUserSearchPath,
            FALSE);

        if (!bInitSuccess) {
            supShowWin32Error("[!] SymInitialize failed", GetLastError());
        }
        else {
            supPrintfEvent(kduEventInformation, "[+] Symbols initialized\r\n");
        }

        g_symInitialized = bInitSuccess;

    } while (FALSE);

    if (!bInitSuccess) {
        if (g_hDbgHelp) {
            FreeLibrary(g_hDbgHelp);
            g_hDbgHelp = NULL;
        }
        if (g_hSymSrv) {
            FreeLibrary(g_hSymSrv);
            g_hSymSrv = NULL;
        }
    }

    return bInitSuccess;
}
