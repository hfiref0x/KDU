/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       BINALYZE.H
*
*  VERSION:     1.40
*
*  DATE:        20 Oct 2023
*
*  Binalyze driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define IREC_DEVICE_TYPE            (DWORD)0x8001
#define IREC_FUNCTION_OPEN_PROCESS  (DWORD)0x80A

#define IOCTL_IREC_OPEN_PROCESS      \
    CTL_CODE(IREC_DEVICE_TYPE, IREC_FUNCTION_OPEN_PROCESS, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80012028

BOOL WINAPI BeDrvOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);
