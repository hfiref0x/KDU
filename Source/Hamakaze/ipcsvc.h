/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       IPCSVC.H
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

typedef VOID(CALLBACK* IpcOnReceive)(
    _In_ PCLIENT_ID ClientId,
    _In_ PKDU_MSG Message,
    _In_opt_ PVOID UserContext
    );

typedef VOID(CALLBACK* IpcOnConnect)(
    _In_ PCLIENT_ID ClientId,
    _In_ BOOLEAN ConnectionAccepted,
    _In_opt_ PVOID UserContext
    );

typedef VOID(CALLBACK* IpcOnException)(
    _In_ ULONG ExceptionCode,
    _In_opt_ PVOID UserContext
    );

typedef VOID(CALLBACK* IpcOnPortClose)(
    _In_ HANDLE PortHandle,
    _In_opt_ PVOID UserContext
    );

typedef struct _KDU_SERVER_PARAMS {
    IpcOnReceive OnReceive;
    IpcOnException OnReceiveException;
    IpcOnConnect OnConnect;
    IpcOnPortClose OnPortClose;
    PVOID UserContext;
    HANDLE ServerHandle;
} KDU_SERVER_PARAMS, * PKDU_SERVER_PARAMS;

PVOID IpcStartApiServer(
    _In_ IpcOnReceive OnReceive,
    _In_ IpcOnException OnException,
    _In_opt_ IpcOnConnect OnConnect,
    _In_opt_ IpcOnPortClose OnPortClose,
    _In_opt_ PVOID UserContext);

BOOL IpcStopApiServer(
    PVOID ServerHandle);
