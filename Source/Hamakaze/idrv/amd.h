/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2026
*
*  TITLE:       AMD.H
*
*  VERSION:     1.49
*
*  DATE:        04 Jun 2026
*
*  AMD drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FILE_DEVICE_AMD_RM    (DWORD)0x8111
#define FILE_DEVICE_AMD_PDFW  (DWORD)0x8000

#define PDFW_MEMCPY_FUNC (DWORD)0x805

#define RM_READ_MEMORY  (DWORD)0xBC2
#define RM_WRITE_MEMORY (DWORD)0xBC3

#define AMDAFF_READ_MEMORY  (DWORD)0x80B
#define AMDAFF_WRITE_MEMORY (DWORD)0x80C

#define IOCTL_AMDRM_READ_MEMORY  \
	CTL_CODE(FILE_DEVICE_AMD_RM, RM_READ_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x81112F08

#define IOCTL_AMDRM_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_AMD_RM, RM_WRITE_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x81112F0C

#define IOCTL_AMDPDFW_MEMCPY \
	CTL_CODE(FILE_DEVICE_AMD_PDFW, PDFW_MEMCPY_FUNC, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002014

#define IOCTL_AMDAFF_READ_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AMDAFF_READ_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x22202C

#define IOCTL_AMDAFF_WRITE_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AMDAFF_WRITE_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222030

#pragma pack( push, 1 ) //strict sizeof 0xC
typedef struct _RMDRV_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Size;
   // UCHAR Data[ANYSIZE_ARRAY]; //not a part of this structure
} RMDRV_REQUEST, * PRMDRV_REQUEST;
#pragma pack( pop )

typedef struct _PDFW_MEMCPY {
    BYTE Reserved[16];
    PVOID Destination;
    PVOID Source;
    PVOID Reserved2;
    DWORD Size;
    DWORD Reserved3;
} PDFW_MEMCPY, * PPDFW_MEMCPY;

typedef struct _AFFDRV_WRITE_REQUEST {
    ULONG Size;
    ULONG Padding;
    PVOID InputBuffer;
    LARGE_INTEGER PhysicalAddress;
} AFFDRV_WRITE_REQUEST, * PAFFDRV_WRITE_REQUEST;

typedef struct _AFFDRV_WRITE_REPLY {
    ULONG Status;
    ULONG Reserved;
    PVOID ZeroField;
} AFFDRV_WRITE_REPLY, * PAFFDRV_WRITE_REPLY;

typedef struct _AFFDRV_READ_REQUEST {
    LARGE_INTEGER PhysicalAddress;
    ULONG64 Size;
} AFFDRV_READ_REQUEST, * PAFFDRV_READ_REQUEST;

typedef struct _AFFDRV_READ_REPLY {
    ULONG64 Reserved;
    UCHAR Data[PAGE_SIZE];
} AFFDRV_READ_REPLY, * PAFFDRV_READ_REPLY;

BOOL RmValidatePrerequisites(
    _In_ KDU_CONTEXT* Context);

BOOL WINAPI RmReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI RmWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PdFwWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PdFwReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AffVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI AffReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AffWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AffWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AffReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
