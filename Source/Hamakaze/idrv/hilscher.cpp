/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       HILSCHER.CPP
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
*
*  Hilscher physmem driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/hilscher.h"

/*
* PhmpReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write from physical memory.
*
*/
BOOL WINAPI PhmpReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL DoWrite)
{
    DWORD bytesIO = 0;
    BOOL bResult;
    NTSTATUS ntStatus;
    PHYSMEM_MAP_IN request;

    request.ullPhysicalAddress = PhysicalAddress;
    request.ulMapSize = NumberOfBytes;

    ntStatus = supCallDriverEx(DeviceHandle,
        IOCTL_PHYSMEM_MAP,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        NULL);

    if (!NT_SUCCESS(ntStatus)) {
        SetLastError(RtlNtStatusToDosError(ntStatus));
        return FALSE;
    }

    SetFilePointer(DeviceHandle, 0, NULL, FILE_BEGIN);

    if (DoWrite)
        bResult = WriteFile(DeviceHandle, Buffer, NumberOfBytes, &bytesIO, NULL);
    else
        bResult = ReadFile(DeviceHandle, Buffer, NumberOfBytes, &bytesIO, NULL);

    return bResult;
}

/*
* PhmReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI PhmReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return PhmpReadWritePhysicalMemory(DeviceHandle, PhysicalAddress, Buffer, NumberOfBytes, FALSE);
}

/*
* PhmWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI PhmWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return PhmpReadWritePhysicalMemory(DeviceHandle, PhysicalAddress, Buffer, NumberOfBytes, TRUE);
}

/*
* PhmRegisterDriver
*
* Purpose:
*
* Set physmem access type.
*
*/
BOOL WINAPI PhmRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    PHYSMEM_ACCESS_IN request;

    request.ulAccessType = PHYSMEM_READWRITE_ACCESS_8BIT;

    return supCallDriver(DeviceHandle, IOCTL_PHYSMEM_SETACCESS, &request, sizeof(request), NULL, 0);
}
