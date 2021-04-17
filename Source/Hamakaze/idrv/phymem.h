/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       PHYMEM.H
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
*
*  PhyMem based drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// PhyMem driver interface definitions.
//
// Taken from PhyMem source.
//

#define	FILE_DEVICE_PHYMEM	(DWORD)0x8000

#define PHYMEM_MAP          (DWORD)0x800
#define PHYMEM_UNMAP        (DWORD)0x801

#define IOCTL_PHYMEM_MAP	\
	CTL_CODE(FILE_DEVICE_PHYMEM, PHYMEM_MAP,\
			 METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PHYMEM_UNMAP	\
	CTL_CODE(FILE_DEVICE_PHYMEM, PHYMEM_UNMAP,\
			 METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct tagPHYMEM_MEM {
	PVOID pvAddr;	//physical addr when mapping, virtual addr when unmapping
	ULONG dwSize;	//memory size to map or unmap
} PHYMEM_MEM, * PPHYMEM_MEM;

BOOL WINAPI PhyMemQueryPML4Value(
	_In_ HANDLE DeviceHandle,
	_Out_ ULONG_PTR* Value);

BOOL WINAPI PhyMemVirtualToPhysical(
	_In_ HANDLE DeviceHandle,
	_In_ ULONG_PTR VirtualAddress,
	_Out_ ULONG_PTR* PhysicalAddress);

BOOL WINAPI PhyMemReadPhysicalMemory(
	_In_ HANDLE DeviceHandle,
	_In_ ULONG_PTR PhysicalAddress,
	_In_ PVOID Buffer,
	_In_ ULONG NumberOfBytes);

BOOL WINAPI PhyMemWritePhysicalMemory(
	_In_ HANDLE DeviceHandle,
	_In_ ULONG_PTR PhysicalAddress,
	_In_reads_bytes_(NumberOfBytes) PVOID Buffer,
	_In_ ULONG NumberOfBytes);

BOOL WINAPI PhyMemWriteKernelVirtualMemory(
	_In_ HANDLE DeviceHandle,
	_In_ ULONG_PTR Address,
	_Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
	_In_ ULONG NumberOfBytes);

BOOL WINAPI PhyMemReadKernelVirtualMemory(
	_In_ HANDLE DeviceHandle,
	_In_ ULONG_PTR Address,
	_Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
	_In_ ULONG NumberOfBytes);
