/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       HILSCHER.H
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
*
*  HILSCHER physmem driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define PHYSMEM_READWRITE_ACCESS_8BIT   1 //byte 
#define PHYSMEM_READWRITE_ACCESS_16BIT  2 //word
#define PHYSMEM_READWRITE_ACCESS_32BIT  3 //dword
#define PHYSMEM_READWRITE_ACCESS_64BIT  4 //qword
#define PHYSMEM_READWRITE_ACCESS_MEMCPY 5 //memcpy

#define	FILE_DEVICE_HILSCHER   FILE_DEVICE_UNKNOWN

#define PHYSMEM_MAP             (DWORD)0x900
#define PHYSMEM_SETACCESS       (DWORD)0x901

#define IOCTL_PHYSMEM_MAP     \
    CTL_CODE(FILE_DEVICE_HILSCHER, PHYSMEM_MAP,\
             METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_PHYSMEM_SETACCESS   \
    CTL_CODE(FILE_DEVICE_HILSCHER, PHYSMEM_SETACCESS,\
             METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//
// Hilscher HW driver interface.
//

typedef struct _PHYSMEM_ACCESS_IN {
    ULONG ulAccessType;
} PHYSMEM_ACCESS_IN, * PPHYSMEM_ACCESS_IN;

typedef struct _PHYSMEM_MAP_IN {
    ULONGLONG ullPhysicalAddress;
    ULONG ulMapSize;
} PHYSMEM_MAP_IN, * PPHYSMEM_MAP_IN;

BOOL WINAPI PhmReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PhmWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PhmRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);
