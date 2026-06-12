/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       LECO.H
*
*  VERSION:     1.49
*
*  DATE:        11 Jun 2026
*
*  LECO LECOMA driver definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FILE_DEVICE_LECO       (DWORD)0x8000

#define LECO_MAP_FUNCID      (DWORD)0x800
#define LECO_UNMAP_FUNCID    (DWORD)0x801

#define IOCTL_LECO_MAP_USER_PHYSICAL_MEMORY \
    CTL_CODE(FILE_DEVICE_LECO, LECO_MAP_FUNCID, METHOD_NEITHER, FILE_ANY_ACCESS) //0x80002003

#define IOCTL_LECO_UNMAP_USER_PHYSICAL_MEMORY \
    CTL_CODE(FILE_DEVICE_LECO, LECO_UNMAP_FUNCID, METHOD_NEITHER, FILE_ANY_ACCESS) //0x80002007

#pragma pack(push, 1)
typedef struct _LECO_REQUEST {
    DWORD64 PhysAddr;    /* +0x00  physical address to map                    */
    DWORD   Key0;        /* +0x08  lookup key 0 (must echo back for unmap)    */
    DWORD   PoolType;    /* +0x0C  1=NonPagedPool, else PagedPool             */
    DWORD   Size;        /* +0x10  mapping size in bytes                      */
    DWORD   Key1;        /* +0x14  lookup key 1 (must echo back for unmap)    */
    DWORD   CacheFlags;  /* +0x18  0=MmCached, 0x200=MmNonCached              */
    DWORD   TypeDisc;    /* +0x1C  2 = IoSpace+MDL path (MapPhysMem)          */
} LECO_REQUEST, PLECO_REQUEST; /* sizeof = 0x20 */
#pragma pack(pop)

BOOL WINAPI LecoVirtualToPhysical(
    HANDLE DeviceHandle,
    ULONG_PTR VirtualAddress,
    ULONG_PTR* PhysicalAddress);

BOOL WINAPI LecoReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LecoWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LecoWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI LecoReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
