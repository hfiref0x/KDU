/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       IPC.CPP
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  Inter-process communication.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define DBK_GET_HANDLE 0x1337

NTSTATUS IpcConnectToPort(
    _In_ LPCWSTR PortName,
    _Out_ PHANDLE PortHandle
)
{
    NTSTATUS ntStatus;
    HANDLE portHandle = NULL;
    SECURITY_QUALITY_OF_SERVICE securityQos;
    UNICODE_STRING portName;

    securityQos.Length = sizeof(securityQos);
    securityQos.ImpersonationLevel = SecurityImpersonation;
    securityQos.EffectiveOnly = FALSE;
    securityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    RtlInitUnicodeString(&portName, PortName);

    do {

        ntStatus = NtConnectPort(&portHandle,
            &portName,
            &securityQos,
            NULL, NULL, NULL, NULL, NULL);

        Sleep(200);

    } while (!NT_SUCCESS(ntStatus));

    *PortHandle = portHandle;

    return ntStatus;
}

void IpcpSetMessageSize(
    _In_ PPORT_MESSAGE64 Message,
    _In_ ULONG Size
)
{
    Message->u1.s1.TotalLength = (CSHORT)(Size + sizeof(PORT_MESSAGE64));
    Message->u1.s1.DataLength = (CSHORT)Size;
}

NTSTATUS IpcSendReply(
    _In_ HANDLE PortHandle,
    _In_ ULONG Function,
    _In_ ULONG64 Data,
    _In_ ULONG64 ReturnedLength,
    _In_ NTSTATUS Status
)
{
    KDU_LPC_MESSAGE rxMsg, txMsg;

    KDU_MSG* pMsg;

    RtlSecureZeroMemory(&txMsg, sizeof(txMsg));
    IpcpSetMessageSize((PPORT_MESSAGE64)&txMsg.Header, sizeof(KDU_MSG));

    RtlSecureZeroMemory(&rxMsg, sizeof(rxMsg));
    IpcpSetMessageSize((PPORT_MESSAGE64)&rxMsg.Header, sizeof(KDU_MSG));

    pMsg = (KDU_MSG*)&txMsg.Data[0];
    pMsg->Function = Function;
    pMsg->Data = Data;
    pMsg->Status = Status;
    pMsg->ReturnedLength = ReturnedLength;

    return NtRequestWaitReplyPort(PortHandle,
        (PPORT_MESSAGE)&txMsg.Header,
        (PPORT_MESSAGE)&rxMsg.Header);
}

VOID IpcSendHandleToServer(
    _In_ HANDLE ProcessHandle
)
{
    HANDLE portHandle = NULL;
    NTSTATUS ntStatus;

    ntStatus = IpcConnectToPort(KDU_PORT_NAME, &portHandle);
    if (NT_SUCCESS(ntStatus)) {

        ntStatus = IpcSendReply(portHandle,
            DBK_GET_HANDLE,
            (ULONG64)ProcessHandle,
            sizeof(ProcessHandle),
            STATUS_SECRET_TOO_LONG);

        NtClose(portHandle);
    }

}
