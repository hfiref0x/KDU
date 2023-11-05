/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       AMD.H
*
*  VERSION:     1.41
*
*  DATE:        04 Nov 2023
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

#define IOCTL_AMDRM_READ_MEMORY  \
	CTL_CODE(FILE_DEVICE_AMD_RM, RM_READ_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x81112F08

#define IOCTL_AMDRM_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_AMD_RM, RM_WRITE_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x81112F0C

#define IOCTL_AMDPDFW_MEMCPY \
	CTL_CODE(FILE_DEVICE_AMD_PDFW, PDFW_MEMCPY_FUNC, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002014

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
