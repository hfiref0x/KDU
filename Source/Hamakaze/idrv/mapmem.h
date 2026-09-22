/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       MAPMEM.H
*
*  VERSION:     1.50
*
*  DATE:        22 Sep 2026
*
*  MAPMEM driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// GIGABYTE GDRV driver interface for CVE-2018-19320.
//

#define GDRV_DEVICE_TYPE        (DWORD)0xC350

#define GDRV_VIRTUALTOPHYSICAL  (DWORD)0xA03
#define GRV_IOCTL_INDEX         (DWORD)0x800 

#define IOCTL_GDRV_VIRTUALTOPHYSICAL            \
    CTL_CODE(GDRV_DEVICE_TYPE, GDRV_VIRTUALTOPHYSICAL, METHOD_BUFFERED, FILE_ANY_ACCESS) //0xC350280C

#define IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY     \
    CTL_CODE(GDRV_DEVICE_TYPE, GRV_IOCTL_INDEX+1, METHOD_BUFFERED, FILE_ANY_ACCESS) //0xC3502004

#define IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY   \
    CTL_CODE(GDRV_DEVICE_TYPE, GRV_IOCTL_INDEX+2, METHOD_BUFFERED, FILE_ANY_ACCESS) //0xC3502008

//
// SuperMicro SUPERBMC driver interface.
//

#define SUPERBMC_DEVICE_TYPE  (DWORD)0x8010

#define SUPERBMC_MAP_FUNCID   (DWORD)0x88E
#define SUPERBMC_UNMAP_FUNCID (DWORD)0x890

#define IOCTL_SUPERBMC_MAP_USER_PHYSICAL_MEMORY      \
    CTL_CODE(SUPERBMC_DEVICE_TYPE, SUPERBMC_MAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102238

#define IOCTL_SUPERBMC_UNMAP_USER_PHYSICAL_MEMORY    \
    CTL_CODE(SUPERBMC_DEVICE_TYPE, SUPERBMC_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102240

//
// Codesys driver interface (basically copy-paste from mapmem ddk).
//

#define FILE_DEVICE_MAPMEM            (DWORD)0x00008000
#define MAPMEM_IOCTL_INDEX            (DWORD)0x800

#define IOCTL_MAPMEM_MAP_USER_PHYSICAL_MEMORY   CTL_CODE(FILE_DEVICE_MAPMEM , \
                                                         MAPMEM_IOCTL_INDEX,  \
                                                         METHOD_BUFFERED,     \
                                                         FILE_ANY_ACCESS)

#define IOCTL_MAPMEM_UNMAP_USER_PHYSICAL_MEMORY CTL_CODE(FILE_DEVICE_MAPMEM,  \
                                                         MAPMEM_IOCTL_INDEX+1,\
                                                         METHOD_BUFFERED,     \
                                                         FILE_ANY_ACCESS)

typedef struct _GIO_VIRTUAL_TO_PHYSICAL {
    ULARGE_INTEGER Address;
} GIO_VIRTUAL_TO_PHYSICAL, * PGIO_VIRTUAL_TO_PHYSICAL;

typedef struct _MAPMEM_PHYSICAL_MEMORY_INFO {
    INTERFACE_TYPE   InterfaceType;
    ULONG            BusNumber;
    PHYSICAL_ADDRESS BusAddress;
    ULONG            AddressSpace;
    ULONG            Length;
} MAPMEM_PHYSICAL_MEMORY_INFO, * PMAPMEM_PHYSICAL_MEMORY_INFO;

BOOL WINAPI MapMemVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI MapMemReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength);

BOOL WINAPI MapMemWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MapMemWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MapMemReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI MapMemRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

//
// These are specific to the Teledynes CORMEM.SYS driver.
//

#define CORMEM_DEVICE_TYPE  FILE_DEVICE_UNKNOWN
#define CORMEM_MAP_FUNCID   (DWORD)0x803
#define CORMEM_UNMAP_FUNCID (DWORD)0x804

#define IOCTL_CORMEM_MAPBUFFER      \
    CTL_CODE(CORMEM_DEVICE_TYPE, CORMEM_MAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x22200C

#define IOCTL_CORMEM_UNMAPBUFFER    \
    CTL_CODE(CORMEM_DEVICE_TYPE, CORMEM_UNMAP_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) // 0x222010

typedef struct _CORMEM_MAPBUFFER_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    SIZE_T Size;
    ULONGLONG Unused;
} CORMEM_MAPBUFFER_REQUEST, * PCORMEM_MAPBUFFER_REQUEST;

BOOL WINAPI CorMemVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI CorMemReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI CorMemWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI CorMemWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI CorMemReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// These are specific for Kontron driver.
//

#define KONTRON_DEVICE_TYPE     (DWORD)0x8200
#define KONTRON_MAP_FUNCID      (DWORD)0xC00
#define KONTRON_UNMAP_FUNCID    (DWORD)0xC40

#define KONTRON_IOCTL_MAP_MEMORY \
    CTL_CODE(KONTRON_DEVICE_TYPE, KONTRON_MAP_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS) //0x82007000

#define KONTRON_IOCTL_UNMAP_MEMORY \
    CTL_CODE(KONTRON_DEVICE_TYPE, KONTRON_UNMAP_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS) //0x82007100

#pragma pack(push, 1)
typedef struct _KONTRON_MAP_MEMORY_REQUEST {
    union {
        struct {
            ULONG InterfaceType;
            ULONG BusNumber;
            PHYSICAL_ADDRESS BusAddress;
            ULONG AddressSpace;        // 0 = MMIO, 1 = I/O
            ULONG ViewSize;
        } In;
        struct {
            PVOID VirtualAddress;
        } Out;
    };
} KONTRON_MAP_MEMORY_REQUEST, * PKONTRON_MAP_MEMORY_REQUEST;

typedef struct _KONTRON_UNMAP_MEMORY_REQUEST {
    PVOID BaseAddress;
} KONTRON_UNMAP_MEMORY_REQUEST, * PKONTRON_UNMAP_MEMORY_REQUEST;
#pragma pack(pop)

BOOL WINAPI KontronVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI KontronReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KontronWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KontronWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI KontronReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);
