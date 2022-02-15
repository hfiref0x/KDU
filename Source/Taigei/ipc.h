/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       IPC.H
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  Inter-process communication prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define KDU_PORT_NAME L"\\KduPort"

typedef struct _KDU_LPC_MESSAGE {
    PORT_MESSAGE64 Header;
    BYTE Data[128];
} KDU_LPC_MESSAGE, * PKDU_LPC_MESSAGE;

typedef struct _KDU_MSG {
    ULONG Function;
    NTSTATUS Status;
    ULONG64 Data;
    ULONG64 ReturnedLength;
} KDU_MSG, * PKDU_MSG;

VOID IpcSendHandleToServer(
    _In_ HANDLE ProcessHandle);
