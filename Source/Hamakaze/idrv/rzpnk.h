/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       RZPNK.H
*
*  VERSION:     1.40
*
*  DATE:        20 Oct 2023
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
// Razer Overlay Support driver interface for CVE-2017-9769.
//

#define RAZER_DEVICE_TYPE FILE_DEVICE_UNKNOWN

#define RAZER_OPEN_PROCESS_FUNCID   (DWORD)0x814

#define IOCTL_RZPNK_OPEN_PROCESS    \
    CTL_CODE(RAZER_DEVICE_TYPE, RAZER_OPEN_PROCESS_FUNCID, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0x22A050

typedef struct _RAZER_OPEN_PROCESS {
    HANDLE ProcessId;
    HANDLE ProcessHandle;
} RAZER_OPEN_PROCESS, * PRAZER_OPEN_PROCESS;

BOOL WINAPI RazerOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);
