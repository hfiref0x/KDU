/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       IPCDEC.H
*
*  VERSION:     1.48
*
*  DATE:        25 Mar 2026
*
*  IPCType by Digital Electronics Corp. driver interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define IPCTYPE_DEVICE_TYPE   (DWORD)0x8010
#define IPCTYPE_MAP_FUNCID    (DWORD)0x810
#define IPCTYPE_UNMAP_FUNCID  (DWORD)0x811

#define IOCTL_IPCTYPE_MAPBUFFER CTL_CODE(IPCTYPE_DEVICE_TYPE,     \
    IPCTYPE_MAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80102040

#define IOCTL_IPCTYPE_UNMAPBUFFER CTL_CODE(IPCTYPE_DEVICE_TYPE,   \
    IPCTYPE_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x80102044

#pragma pack(push, 1)

typedef struct _IPCTYPE_MAP_MEMORY {
    UINT8            Unused[8];          // +0
    ULONG            Length;             // +8
    PHYSICAL_ADDRESS PhysicalAddress;    // +12
    ULONG64          UserMapping;        // +20 [OUT]
} IPCTYPE_MAP_MEMORY, * PIPCTYPE_MAP_MEMORY;

typedef struct _IPCTYPE_UNMAP_MEMORY {
    UINT8            Unused[8];          // +0
    ULONG            Reserved;           // +8
    PHYSICAL_ADDRESS Reserved2;          // +12
    ULONG64          UserMapping;        // +20 [IN]
} IPCTYPE_UNMAP_MEMORY, * PIPCTYPE_UNMAP_MEMORY;

#pragma pack(pop)

BOOL WINAPI IpcVirtualToPhysical(
    HANDLE DeviceHandle,
    ULONG_PTR VirtualAddress,
    ULONG_PTR* PhysicalAddress);

BOOL WINAPI IpcReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI IpcWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI IpcWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI IpcReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
