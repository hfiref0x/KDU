/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       DELL.H
*
*  VERSION:     1.31
*
*  DATE:        10 Apr 2023
*
*  Dell drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Dell driver interface.
//

#define DBUTIL_DEVICE_TYPE (DWORD)0x9B0C

#define DBUTIL_FUNCTION_READVM  (DWORD)0x7B1
#define DBUTIL_FUNCTION_WRITEVM (DWORD)0x7B2

#define PCDCSRVC_FUNCTION_REGISTER (DWORD)0x801
#define PCDCSRVC_FUNCTION_READPHYS (DWORD)0x821
#define PCDCSRVC_FUNCTION_WRITEPHYS (DWORD)0x822

#define IOCTL_DBUTIL_READVM     \
    CTL_CODE(DBUTIL_DEVICE_TYPE, DBUTIL_FUNCTION_READVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9B0C1EC4

#define IOCTL_DBUTIL_WRITEVM    \
    CTL_CODE(DBUTIL_DEVICE_TYPE, DBUTIL_FUNCTION_WRITEVM, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9B0C1EC8

#define IOCTL_PCDCSRVC_REGISTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PCDCSRVC_FUNCTION_REGISTER, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222004

#define IOCTL_PCDCSRVC_READPHYSMEM  \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PCDCSRVC_FUNCTION_READPHYS, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222084

#define IOCTL_PCDCSRVC_WRITEPHYSMEM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PCDCSRVC_FUNCTION_WRITEPHYS, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x222088

//
// Virtual memory read/write
//
// Size of data to read/write calculated as: 
// InputBufferSize - sizeof packet header 0x18 bytes length
//
typedef struct _DBUTIL_READWRITE_REQUEST {
    ULONG_PTR Unused;
    ULONG_PTR VirtualAddress;
    ULONG_PTR Offset;
    UCHAR Data[ANYSIZE_ARRAY];
} DBUTIL_READWRITE_REQUEST, * PDBUTIL_READWRITE_REQUEST;

//
// Physical memory read/write for DELL PC Doctor
//
// Sizeof 13 bytes.
//
#pragma pack(push, 1)
typedef struct _PCDCSRVC_READWRITE_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Size;
    BYTE Granularity;
    // UCHAR Data[ANYSIZE_ARRAY]; //not a part of this structure
} PCDCSRVC_READWRITE_REQUEST, *PPCDCSRVC_READWRITE_REQUEST;
#pragma pack(pop)

_Success_(return != FALSE)
BOOL WINAPI DbUtilReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI DbUtilWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL DbUtilStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

VOID DbUtilStopVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

BOOL WINAPI DpdReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI DpdWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI DellRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);
