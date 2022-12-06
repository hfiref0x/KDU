/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       RYZEN.H
*
*  VERSION:     1.28
*
*  DATE:        02 Dec 2022
*
*  AMD Ryzen Master Service Driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FILE_DEVICE_AMD_RM    (DWORD)0x8111

#define RM_READ_MEMORY  (DWORD)0xBC2
#define RM_WRITE_MEMORY (DWORD)0xBC3

#define IOCTL_AMDRM_READ_MEMORY  \
	CTL_CODE(FILE_DEVICE_AMD_RM, RM_READ_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x81112F08

#define IOCTL_AMDRM_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_AMD_RM, RM_WRITE_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x81112F0C

#pragma pack( push, 1 ) //strict sizeof 0xC
typedef struct _RMDRV_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Size;
   // UCHAR Data[ANYSIZE_ARRAY]; //not a part of this structure
} RMDRV_REQUEST, * PRMDRV_REQUEST;
#pragma pack( pop )

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
