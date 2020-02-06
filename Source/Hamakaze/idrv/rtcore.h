/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       RTCORE.H
*
*  VERSION:     1.00
*
*  DATE:        02 Feb 2020
*
*  RTCore64 driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// RTCore64 driver interface for CVE-2019-16098.
//

#define RTCORE_DEVICE_TYPE      (DWORD)0x8000

#define RTCORE_FUNCTION_READMSR (DWORD)0x80C
#define RTCORE_FUNCTION_READVM  (DWORD)0x812
#define RTCORE_FUNCTION_WRITEVM (DWORD)0x813

#define IOCTL_RTCORE_READMSR    \
    CTL_CODE(RTCORE_DEVICE_TYPE, RTCORE_FUNCTION_READMSR, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002030

#define IOCTL_RTCORE_READVM     \
    CTL_CODE(RTCORE_DEVICE_TYPE, RTCORE_FUNCTION_READVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002048

#define IOCTL_RTCORE_WRITEVM    \
    CTL_CODE(RTCORE_DEVICE_TYPE, RTCORE_FUNCTION_WRITEVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x8000204C

typedef struct _RTCORE_REQUEST {
    ULONG_PTR Unknown0;
    ULONG_PTR Address;
    ULONG_PTR Unknown1;
    ULONG Size;
    ULONG Value;
    ULONG_PTR Unknown2;
    ULONG_PTR Unknown3;
} RTCORE_REQUEST, * PRTCORE_REQUEST;

typedef struct _RTCORE_MSR {
    ULONG Register;
    ULONG ValueHigh;
    ULONG ValueLow;
} RTCORE_MSR, * PRTCORE_MSR;

BOOL RTCoreReadMsr(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG Msr,
    _Out_ ULONG64* Value);

_Success_(return != FALSE)
BOOL RTCoreReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL RTCoreWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
