/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       ECHODRV.H
*
*  VERSION:     1.33
*
*  DATE:        16 Jul 2023
*
*  Inspect Element LTD spyware (anticheat) driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Echo.ac driver uses a ridiculous IOCTL scheme which could be a side effect of intense copy-paste. 
//

#define ECHODRV_DEVICE_TYPE         (DWORD)0x9E6A
#define ECHODRV_INTERFACE_TYPE_1    (DWORD)0xE622
#define ECHODRV_INTERFACE_TYPE_2    (DWORD)0x60A2

#define ECHODRV_FUNCTION_REGISTER       (DWORD)0x165
#define ECHODRV_FUNCTION_OPEN_PROCESS   (DWORD)0x92
#define ECHODRV_FUNCTION_COPYVM         (DWORD)0x849

#define IOCTL_ECHODRV_REGISTER          \
    CTL_CODE(ECHODRV_DEVICE_TYPE, ECHODRV_FUNCTION_REGISTER, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9E6A0594

#define IOCTL_ECHODRV_OPEN_PROCESS      \
    CTL_CODE(ECHODRV_INTERFACE_TYPE_1, ECHODRV_FUNCTION_OPEN_PROCESS, METHOD_BUFFERED, FILE_READ_ACCESS) //0xE6224248

#define IOCTL_ECHODRV_COPYVM            \
    CTL_CODE(ECHODRV_INTERFACE_TYPE_2, ECHODRV_FUNCTION_COPYVM, METHOD_BUFFERED, FILE_READ_ACCESS) //0x60A26124

typedef struct _ECHODRV_REGISTER {
    _In_ PUCHAR pvSignature;
    _In_ SIZE_T cbSignature;
    _Out_ BOOL bSuccess;
    _Out_ DWORD UniqCode; //0x1000 for call
} ECHODRV_REGISTER, * PECHODRV_REGISTER;

typedef struct _ECHODRV_VALIDATE_PROCESS {
    _In_ DWORD ProcessId;
    _In_ ACCESS_MASK DesiredAccess;
    _Out_ HANDLE ProcessHandle;
    _Out_ BOOL bSuccess;
    _Out_ DWORD UniqCode; //0x1001 for call
} ECHODRV_VALIDATE_PROCESS, * PECHODRV_VALIDATE_PROCESS;

typedef struct _ECHODRV_COPYVM_REQUEST {
    _In_ HANDLE ProcessHandle;
    _In_ PVOID FromAddress;
    _In_ PVOID ToAddress;
    _In_ SIZE_T BufferSize;
    _Out_ SIZE_T NumberOfBytesCopied;
    _Out_ BOOL bSuccess;
    _Out_ DWORD UniqCode; //0x1002 for call
} ECHODRV_COPYVM_REQUEST, * PECHODRV_COPY_REQUEST;

BOOL WINAPI EchoDrvRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI EchoDrvUnregisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI EchoDrvReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI EchoDrvWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
