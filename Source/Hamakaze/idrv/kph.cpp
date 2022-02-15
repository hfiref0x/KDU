/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       KPH.CPP
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  KProcessHacker2 driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/kph.h"

HANDLE g_KphPhysicalMemorySection = NULL;

/*
* KphpMapMemory
*
* Purpose:
*
* Map physical memory.
*
*/
PVOID KphpMapMemory(
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL MapForWrite
)
{
    return supMapPhysicalMemory(g_KphPhysicalMemorySection,
        PhysicalAddress,
        NumberOfBytes,
        MapForWrite);
}

/*
* KphpUnmapMemory
*
* Purpose:
*
* Unmap physical memory.
*
*/
VOID KphpUnmapMemory(
    _In_ PVOID BaseAddress
)
{
    supUnmapPhysicalMemory(BaseAddress);
}

/*
* KphpReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI KphpReadWritePhysicalMemory(
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    return supReadWritePhysicalMemory(g_KphPhysicalMemorySection,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        DoWrite);
}

/*
* KphReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI KphReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return KphpReadWritePhysicalMemory(PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* KphWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI KphWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return KphpReadWritePhysicalMemory(PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* KphQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI KphQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;
    ULONG cbRead = 0x100000;

    UNREFERENCED_PARAMETER(DeviceHandle);

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)KphpMapMemory(0ULL,
        cbRead,
        FALSE);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        KphpUnmapMemory((PVOID)pbLowStub1M);

    }

    return (PML4 != 0);
}

/*
* KphVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI KphVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    return PwVirtualToPhysical(DeviceHandle,
        KphQueryPML4Value,
        KphReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* KphReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI KphReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    UNREFERENCED_PARAMETER(DeviceHandle);
    SetLastError(ERROR_SUCCESS);

    bResult = KphVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = KphpReadWritePhysicalMemory(physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

    return bResult;
}

/*
* KphWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI KphWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;

    UNREFERENCED_PARAMETER(DeviceHandle);
    SetLastError(ERROR_SUCCESS);

    bResult = KphVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = KphpReadWritePhysicalMemory(physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

    return bResult;
}

/*
* KphpDuplicateHandle
*
* Purpose:
*
* Duplicate handle via KPH driver request.
*
*/
BOOL KphpDuplicateHandle(
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
    KPH_DUPLICATE_OBJECT_REQUEST request;

    UNREFERENCED_PARAMETER(SourceProcessId);

    request.DesiredAccess = DesiredAccess;
    request.HandleAttributes = HandleAttributes;
    request.Options = Options;
    request.SourceHandle = SourceHandle;
    request.SourceProcessHandle = SourceProcessHandle;
    request.TargetHandle = TargetHandle;
    request.TargetProcessHandle = NtCurrentProcess();

    return supCallDriver(DeviceHandle,
        IOCTL_KPH_DUPOBJECT,
        &request,
        sizeof(request),
        NULL,
        0);
}

/*
* KphpOpenProcess
*
* Purpose:
*
* Open process handle via KPH driver request.
*
*/
BOOL KphpOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    CLIENT_ID clientId;
    KPH_OPEN_PROCESS_REQUEST request;

    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    request.ClientId = &clientId;
    request.ProcessHandle = ProcessHandle;
    request.DesiredAccess = DesiredAccess;

    return supCallDriver(DeviceHandle,
        IOCTL_KPH_OPENPROCESS,
        &request,
        sizeof(request),
        NULL,
        0);
}

/*
* KphRegisterDriver
*
* Purpose:
*
* Driver initialization routine.
*
*/
BOOL WINAPI KphRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    return supOpenPhysicalMemory(DeviceHandle,
        (pfnOpenProcessCallback)KphpOpenProcess,
        (pfnDuplicateHandleCallback)KphpDuplicateHandle,
        &g_KphPhysicalMemorySection);
}

/*
* KphUnregisterDriver
*
* Purpose:
*
* Free KPH driver related resources.
*
*/
BOOL WINAPI KphUnregisterDriver(
    _In_ HANDLE DeviceHandle)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    if (g_KphPhysicalMemorySection) {
        NtClose(g_KphPhysicalMemorySection);
        g_KphPhysicalMemorySection = NULL;
    }

    return TRUE;
}
