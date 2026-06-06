/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       MATROX.H
*
*  VERSION:     1.49
*
*  DATE:        05 Jun 2026
*
*  Matrox Graphics Inc. driver interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FILE_DEVICE_MATROX      (DWORD)0x9C40

#define MATROX_MAP_MEMORY       (DWORD)0x913
#define MATROX_UNMAP_MEMORY     (DWORD)0x914

#define IOCTL_MATROX_MAP_MEMORY \
	CTL_CODE(FILE_DEVICE_MATROX, MATROX_MAP_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS) //0x9C40644C

#define IOCTL_MATROX_UNMAP_MEMORY \
	CTL_CODE(FILE_DEVICE_MATROX, MATROX_UNMAP_MEMORY, METHOD_BUFFERED, FILE_READ_ACCESS) //0x9C406450

#pragma pack(push, 1)
typedef struct _MATROX_MAP_MEMORY_INPUT {
    LARGE_INTEGER SectionOffset; // 0x00
    ULONG ViewSize;              // 0x08
    ULONG MemoryCachingType;     // 0x0C
} MATROX_MAP_MEMORY_INPUT, * PMATROX_MAP_MEMORY_INPUT;

typedef struct _MATROX_MAP_MEMORY_OUTPUT {
    PVOID BaseAddress;           // 0x00
} MATROX_MAP_MEMORY_OUTPUT, * PMATROX_MAP_MEMORY_OUTPUT;

typedef struct _MATROX_UNMAP_MEMORY_INPUT {
    PVOID BaseAddress;           // 0x00
} MATROX_UNMAP_MEMORY_INPUT, * PMATROX_UNMAP_MEMORY_INPUT;
#pragma pack(pop)

PVOID MatroxMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes);

VOID MatroxUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID BaseAddress);

BOOL WINAPI MatroxVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI MatroxReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MatroxWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MatroxWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MatroxReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
