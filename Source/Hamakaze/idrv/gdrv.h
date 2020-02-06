/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       GDRV.H
*
*  VERSION:     1.00
*
*  DATE:        02 Feb 2020
*
*  GigaByte GiveIO Gdrv driver interface header.
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


typedef struct _GIO_VIRTUAL_TO_PHYSICAL {
    ULARGE_INTEGER Address;
} GIO_VIRTUAL_TO_PHYSICAL, * PGIO_VIRTUAL_TO_PHYSICAL;

typedef enum _INTERFACE_TYPE {
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    MaximumInterfaceType
} INTERFACE_TYPE, * PINTERFACE_TYPE;

typedef LARGE_INTEGER PHYSICAL_ADDRESS;

typedef struct _GDRV_PHYSICAL_MEMORY_INFO {
    INTERFACE_TYPE   InterfaceType; 
    ULONG            BusNumber;     
    PHYSICAL_ADDRESS BusAddress;
    ULONG            AddressSpace;  
    ULONG            Length;        
} GDRV_PHYSICAL_MEMORY_INFO, * PGDRV_PHYSICAL_MEMORY_INFO;

BOOL GioVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL GioReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength);

BOOL WINAPI GioWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI GioWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI GioReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI GioQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);
