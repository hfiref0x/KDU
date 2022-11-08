/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       ZEMANA.H
*
*  VERSION:     1.27
*
*  DATE:        08 Nov 2022
*
*  Zemana driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Zemana generic driver interface
//
//
// WARNING:
//
// Zemana has many faces since it driver was distributed as part of their "SDK". 
// The derivatives are all the same and exceptionally bugged as well, e.g. MalwareFox, WatchDog Anti-Malware etc.
//
#define FILE_DEVICE_ZEMANA (DWORD)0x8000

#define ZEMANA_REGISTER_PROCESS  (DWORD)0x804
#define ZEMANA_SCSI_READ         (DWORD)0x805
#define ZEMANA_SCSI_WRITE        (DWORD)0x806
#define ZEMANA_PROTECT_REGISTRY  (DWORD)0x810
#define ZEMANA_SAVE_MINIPORT_FIX (DWORD)0x811

#define IOCTL_ZEMANA_REGISTER_PROCESS       \
    CTL_CODE(FILE_DEVICE_ZEMANA, ZEMANA_REGISTER_PROCESS, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002010

#define IOCTL_ZEMANA_SCSI_READ              \
    CTL_CODE(FILE_DEVICE_ZEMANA, ZEMANA_SCSI_READ, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002014

#define IOCTL_ZEMANA_SCSI_WRITE     \
    CTL_CODE(FILE_DEVICE_ZEMANA, ZEMANA_SCSI_WRITE, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002018

#define IOCTL_ZEMANA_SAVE_MINIPORT_FIX      \
    CTL_CODE(FILE_DEVICE_ZEMANA, ZEMANA_SAVE_MINIPORT_FIX, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002044

#define IOCTL_ZEMANA_PROTECT_REGISTRY      \
    CTL_CODE(FILE_DEVICE_ZEMANA, ZEMANA_PROTECT_REGISTRY, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80002040

BOOL ZmMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase);

BOOL ZmControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address);

BOOL WINAPI ZmRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);
