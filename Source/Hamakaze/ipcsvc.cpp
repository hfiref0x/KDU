/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       IPCSVC.CPP
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  Inter-process communication, simplified ALPC server.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "../Shared/ntos/ntalpc.h"

void IpcpSetMessageSize(
	_In_ PPORT_MESSAGE64 Message,
	_In_ ULONG Size
)
{
	Message->u1.s1.TotalLength = (CSHORT)(Size + sizeof(PORT_MESSAGE64));
	Message->u1.s1.DataLength = (CSHORT)Size;
}

NTSTATUS IpcpCreateServerPort(
	_Out_ PHANDLE PortHandle)
{
	NTSTATUS ntStatus;
	ULONG sdLength;
	ALPC_PORT_ATTRIBUTES portAttr;
	PSECURITY_DESCRIPTOR pSD;
	PACL dacl;
	PSID adminSid;

	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	UCHAR sidBuffer[FIELD_OFFSET(SID, SubAuthority) + sizeof(ULONG) * 2];
	SID everyoneSid = { SID_REVISION, 1, SECURITY_WORLD_SID_AUTHORITY, { SECURITY_WORLD_RID } };

	OBJECT_ATTRIBUTES attr;
	UNICODE_STRING portName;

	adminSid = (PSID)sidBuffer;
	RtlInitializeSid(adminSid, &ntAuthority, 2);
	*RtlSubAuthoritySid(adminSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
	*RtlSubAuthoritySid(adminSid, 1) = DOMAIN_ALIAS_RID_ADMINS;

	sdLength = SECURITY_DESCRIPTOR_MIN_LENGTH +
		(ULONG)sizeof(ACL) +
		(ULONG)sizeof(ACCESS_ALLOWED_ACE) +
		RtlLengthSid(adminSid) +
		(ULONG)sizeof(ACCESS_ALLOWED_ACE) +
		RtlLengthSid(&everyoneSid);

	pSD = supHeapAlloc(sdLength);
	if (pSD) {
		dacl = (PACL)RtlOffsetToPointer(pSD, SECURITY_DESCRIPTOR_MIN_LENGTH);
		RtlCreateSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
		RtlCreateAcl(dacl, sdLength - SECURITY_DESCRIPTOR_MIN_LENGTH, ACL_REVISION);
		RtlAddAccessAllowedAce(dacl, ACL_REVISION, PORT_ALL_ACCESS, adminSid);
		RtlAddAccessAllowedAce(dacl, ACL_REVISION, PORT_CONNECT, &everyoneSid);
		RtlSetDaclSecurityDescriptor(pSD, TRUE, dacl, FALSE);
	}

	RtlInitUnicodeString(&portName, KDU_PORT_NAME);
	InitializeObjectAttributes(&attr, &portName, OBJ_CASE_INSENSITIVE, NULL, pSD);

	RtlSecureZeroMemory(&portAttr, sizeof(portAttr));
	portAttr.MaxMessageLength = sizeof(KDU_LPC_MESSAGE);

	ntStatus = NtAlpcCreatePort(PortHandle, &attr, &portAttr);

	if (pSD) supHeapFree(pSD);

	return ntStatus;
}

DWORD WINAPI IpcPortThreadWorker(
	_In_ LPVOID Param
)
{
	NTSTATUS ntStatus;
	LONG_PTR index;
	HANDLE serverPort = NULL;
	HANDLE clientPort;

	PKDU_LPC_MESSAGE plpcTxMsg = NULL;
	PKDU_MSG pMsg;
	LPVOID contextPtr;

	PKDU_SERVER_PARAMS serverParams = (PKDU_SERVER_PARAMS)Param;

#define MAX_KDU_CLIENTS 2
	HANDLE portClients[MAX_KDU_CLIENTS];
	KDU_LPC_MESSAGE lpcTxMsg, lpcRxMsg;

	FUNCTION_ENTER_MSG(__FUNCTION__);

	ntStatus = IpcpCreateServerPort(&serverPort);
	if (!NT_SUCCESS(ntStatus))
		return (DWORD)-2;

	RtlSecureZeroMemory(&portClients, sizeof(portClients));
	RtlSecureZeroMemory(&lpcTxMsg, sizeof(lpcTxMsg));
	RtlSecureZeroMemory(&lpcRxMsg, sizeof(lpcRxMsg));

	while (TRUE) {
		
		contextPtr = NULL;
		
		ntStatus = NtReplyWaitReceivePort(serverPort,
			&contextPtr, 
			(PPORT_MESSAGE)plpcTxMsg , 
			(PPORT_MESSAGE)&lpcRxMsg);
		
		plpcTxMsg = NULL;

		if (!NT_SUCCESS(ntStatus))
			continue;

		switch (lpcRxMsg.Header.u2.s2.Type & (~LPC_CONTINUATION_REQUIRED))
		{

		case LPC_CONNECTION_REQUEST:

			index = -1;
			for (INT c = 0; c < MAX_KDU_CLIENTS; ++c)
			{
				if (portClients[c] == NULL)
				{
					index = c;
					break;
				}
			}

			clientPort = NULL;
			if (index >= 0) {

				if (serverParams->OnConnect) {
					serverParams->OnConnect((PCLIENT_ID)&lpcRxMsg.Header.ClientId,
						TRUE,
						serverParams->UserContext);
				}

				ntStatus = NtAlpcAcceptConnectPort(&clientPort,
					serverPort,
					0, 
					NULL, 
					NULL, 
					(PVOID)(index + 4096), 
					(PPORT_MESSAGE)&lpcRxMsg.Header, 
					NULL, 
					TRUE);

				if (NT_SUCCESS(ntStatus)) {
					portClients[index] = clientPort;
				}


			}
			else {

				if (serverParams->OnConnect) {
					serverParams->OnConnect((PCLIENT_ID)&lpcRxMsg.Header.ClientId,
						FALSE,
						serverParams->UserContext);
				}

				NtAlpcAcceptConnectPort(&clientPort,
					serverPort,
					0, 
					NULL, 
					NULL, 
					NULL, 
					(PPORT_MESSAGE)&lpcRxMsg.Header, 
					NULL, 
					FALSE);

			}

			break;

		case LPC_CLIENT_DIED:
		case LPC_PORT_CLOSED:

			index = (LONG_PTR)contextPtr - 4096;
			if (index >= 0 && index < MAX_KDU_CLIENTS) {
				if (portClients[index] != NULL)
				{
					NtAlpcDisconnectPort(portClients[index], 0);

					if (serverParams->OnPortClose) {
						serverParams->OnPortClose(portClients[index], 
							serverParams->UserContext);
					}

					NtClose(portClients[index]);
					portClients[index] = NULL;
				}
			}
			break;

        case LPC_REQUEST:

            pMsg = (PKDU_MSG)&lpcRxMsg.Data[0];
            __try {
                serverParams->OnReceive((CLIENT_ID*)&lpcRxMsg.Header.ClientId, 
					pMsg, 
					serverParams->UserContext);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                serverParams->OnReceiveException(GetExceptionCode(), serverParams->UserContext);
            }

            RtlSecureZeroMemory(&lpcTxMsg, sizeof(lpcTxMsg));
            IpcpSetMessageSize((PPORT_MESSAGE64)&lpcTxMsg.Header, sizeof(KDU_MSG));
            lpcTxMsg.Header.u2.s2.Type = LPC_REPLY;
            lpcTxMsg.Header.MessageId = lpcRxMsg.Header.MessageId;
            plpcTxMsg = &lpcTxMsg;

            break;

		default:
			break;
		}

	}

	if (serverPort)
		NtClose(serverPort);

	ExitThread(ERROR_SUCCESS);
}

PVOID IpcStartApiServer(
	_In_ IpcOnReceive OnReceive,
	_In_ IpcOnException OnException,
	_In_opt_ IpcOnConnect OnConnect,
	_In_opt_ IpcOnPortClose OnPortClose,
	_In_opt_ PVOID UserContext
)
{
	DWORD dwThreadId = 0;

	PKDU_SERVER_PARAMS params;

	params = (PKDU_SERVER_PARAMS)supHeapAlloc(sizeof(KDU_SERVER_PARAMS));
	if (params) {

		params->OnReceive = OnReceive;
		params->UserContext = UserContext;
		params->OnReceiveException = OnException;
		if (OnConnect) params->OnConnect = OnConnect;
		if (OnPortClose) params->OnPortClose = OnPortClose;

		HANDLE hThread = CreateThread(NULL,
			0,
			(LPTHREAD_START_ROUTINE)IpcPortThreadWorker,
			(PVOID)params,
			0,
			&dwThreadId);

		if (hThread) {
			params->ServerHandle = hThread;
		}
		else
		{
			supHeapFree(params);
			params = NULL;
		}

	}

	return params;
}

#pragma warning(push)
#pragma warning(disable: 6258)
BOOL IpcStopApiServer(
    PVOID ServerHandle
)
{
    PKDU_SERVER_PARAMS params = (PKDU_SERVER_PARAMS)ServerHandle;

    if (params == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (WaitForSingleObject(params->ServerHandle, 2000) == WAIT_TIMEOUT)
        TerminateThread(params->ServerHandle, 0);

    CloseHandle(params->ServerHandle);

    supHeapFree(params);

    return TRUE;
}
#pragma warning(pop)
