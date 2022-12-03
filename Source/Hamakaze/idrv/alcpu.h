/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       ALCPU.H
*
*  VERSION:     1.28
*
*  DATE:        01 Dec 2022
*
*  ALSYSIO64 driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FILE_DEVICE_ALCPU     (DWORD)0x9C40

#define ALCPU_READ_MEMORY     (DWORD)0x986
#define ALCPU_WRITE_MEMORY    (DWORD)0x987

#define IOCTL_ALCPU_READ_MEMORY  \
	CTL_CODE(FILE_DEVICE_ALCPU, ALCPU_READ_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9C402618

#define IOCTL_ALCPU_WRITE_MEMORY \
	CTL_CODE(FILE_DEVICE_ALCPU, ALCPU_WRITE_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9C40261C

typedef struct _ALCPU_READ_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Size;
} ALCPU_READ_REQUEST, * PALCPU_READ_REQUEST;

typedef struct _ALCPU_WRITE_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Size;
    UCHAR Data[ANYSIZE_ARRAY];
} ALCPU_WRITE_REQUEST, * PALCPU_WRITE_REQUEST;

BOOL WINAPI AlcReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI AlcWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
