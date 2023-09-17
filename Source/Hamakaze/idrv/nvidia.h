/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       NVIDIA.H
*
*  VERSION:     1.34
*
*  DATE:        16 Sep 2023
*
*  NVidia drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define NV_FUNCID_READ_CRX   0x0
#define NV_FUNCID_WRITE_CRX  0x1
#define NV_FUNCID_PHYS_READ  0x14
#define NV_FUNCID_PHYS_WRITE 0x15

#define FILE_DEVICE_NVOCLOCK  (DWORD)0x9C40

#define NVOCLOCK_DISPATCH     (DWORD)0x921

#define IOCTL_NVOCLOCK_DISPATCH  \
	CTL_CODE(FILE_DEVICE_NVOCLOCK, NVOCLOCK_DISPATCH, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0x9C40A484

//
// Multipurpose structure, other defines are irrelevant, size is 0x138 and checked in handlers.
//
typedef struct _NVOCLOCK_REQUEST {
    ULONG FunctionId; //NV_FUNCID_*
    ULONG Size;
    PVOID Destination;
    PVOID Source;
    BYTE OutputBuffer[32];
    BYTE EncryptKey[64]; //encrypted message here
    BYTE Reserved0[192];
} NVOCLOCK_REQUEST, * PNVOCLOCK_REQUEST;

BOOL WINAPI NvoReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI NvoWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
