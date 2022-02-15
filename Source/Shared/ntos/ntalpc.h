/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2022, translated from Microsoft sources/debugger
*
*  TITLE:       NTALPC.H
*
*  VERSION:     1.95
*
*  DATE:        02 Feb 2022
*
*  Common header file for the ntos ALPC/CSR related functions and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef NTALPC_RTL
#define NTALPC_RTL

//
// NTALPC_RTL HEADER BEGIN
//

#if defined(__cplusplus)
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#define CSR_API_PORT_NAME               L"ApiPort"

#define WINSS_OBJECT_DIRECTORY_NAME     L"\\Windows"

#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

#define CSR_CSRSS_SECTION_SIZE          65536

#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000

typedef enum _ALPC_PORT_INFORMATION_CLASS {
    AlpcBasicInformation,
    AlpcPortInformation,
    AlpcAssociateCompletionPortInformation,
    AlpcConnectedSIDInformation,
    AlpcServerInformation,
    AlpcMessageZoneInformation,
    AlpcRegisterCompletionListInformation,
    AlpcUnregisterCompletionListInformation,
    AlpcAdjustCompletionListConcurrencyCountInformation,
    AlpcRegisterCallbackInformation,
    AlpcCompletionListRundownInformation,
    AlpcWaitForPortReferences,
    MaxAlpcInformation
} ALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_SERVER_INFORMATION {
    union
    {
        struct
        {
            HANDLE ThreadHandle;
        } In;
        struct
        {
            BOOLEAN ThreadBlocked;
            HANDLE ConnectedProcessId;
            UNICODE_STRING ConnectionPortName;
        } Out;
    };
} ALPC_SERVER_INFORMATION, *PALPC_SERVER_INFORMATION;

typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef struct _ALPC_MESSAGE_ATTRIBUTES {
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_BASIC_INFORMATION {
    ULONG Flags;
    ULONG SequenceNo;
    PVOID PortContext;
} ALPC_BASIC_INFORMATION, *PALPC_BASIC_INFORMATION;

typedef struct _ALPC_HANDLE_TABLE {
    struct _ALPC_HANDLE_ENTRY *Handles;
    ULONG TotalHandles;
    ULONG Flags;
    struct _EX_PUSH_LOCK Lock;
} ALPC_HADNLE_TABLE, *PALPC_HANDLE_TABLE;

// Windows 7 - Windows 8
typedef struct _ALPC_COMMUNICATION_INFO_V1 {
    struct _ALPC_PORT *ConnectionPort;
    struct _ALPC_PORT *ServerCommunicationPort;
    struct _ALPC_PORT *ClientCommunicationPort;
    struct _LIST_ENTRY CommunicationList;
    struct _ALPC_HANDLE_TABLE HandleTable;
} ALPC_COMMUNICATION_INFO_V1, *PALPC_COMMUNICATION_INFO_V1;

// Windows 8.1+
typedef struct _ALPC_COMMUNICATION_INFO_V2 {
    struct _ALPC_PORT *ConnectionPort;
    struct _ALPC_PORT *ServerCommunicationPort;
    struct _ALPC_PORT *ClientCommunicationPort;
    struct _LIST_ENTRY CommunicationList;
    struct _ALPC_HANDLE_TABLE HandleTable;
    struct _KALPC_MESSAGE *CloseMessage;
} ALPC_COMMUNICATION_INFO_V2, *PALPC_COMMUNICATION_INFO_V2;

//
// Compatible fields only structure.
//
typedef struct _ALPC_COMMUNICATION_INFO_COMPAT {
    struct _ALPC_PORT* ConnectionPort;
    struct _ALPC_PORT* ServerCommunicationPort;
    struct _ALPC_PORT* ClientCommunicationPort;
    struct _LIST_ENTRY CommunicationList;
    struct _ALPC_HANDLE_TABLE HandleTable;
} ALPC_COMMUNICATION_INFO_COMPAT, * PALPC_COMMUNICATION_INFO_COMPAT;

typedef union _ALPC_PORT_STATE {
    struct
    {
        unsigned long Initialized : 1;
        unsigned long Type : 2;
        unsigned long ConnectionPending : 1;
        unsigned long ConnectionRefused : 1;
        unsigned long Disconnected : 1;
        unsigned long Closed : 1;
        unsigned long NoFlushOnClose : 1;
        unsigned long ReturnExtendedInfo : 1;
        unsigned long Waitable : 1;
        unsigned long DynamicSecurity : 1;
        unsigned long Wow64CompletionList : 1;
        unsigned long Lpc : 1;
        unsigned long LpcToLpc : 1;
        unsigned long HasCompletionList : 1;
        unsigned long HadCompletionList : 1;
        unsigned long EnableCompletionList : 1;
    } s1;
    unsigned long State;
} ALPC_PORT_STATE, *PALPC_PORT_STATE;

//
// ALPC port object collection.
//
// Windows 7 ALPC port object.
//
typedef struct _ALPC_PORT_7600 {
    /* 0x0000 */ struct _LIST_ENTRY PortListEntry;
    /* 0x0010 */ struct _ALPC_COMMUNICATION_INFO_V1* CommunicationInfo;
    /* 0x0018 */ struct _EPROCESS* OwnerProcess;
    /* 0x0020 */ void* CompletionPort;
    /* 0x0028 */ void* CompletionKey;
    /* 0x0030 */ struct _ALPC_COMPLETION_PACKET_LOOKASIDE* CompletionPacketLookaside;
    /* 0x0038 */ void* PortContext;
    /* 0x0040 */ struct _SECURITY_CLIENT_CONTEXT StaticSecurity;
    /* 0x0088 */ struct _LIST_ENTRY MainQueue;
    /* 0x0098 */ struct _LIST_ENTRY PendingQueue;
    /* 0x00a8 */ struct _LIST_ENTRY LargeMessageQueue;
    /* 0x00b8 */ struct _LIST_ENTRY WaitQueue;
    union
    {
        /* 0x00c8 */ struct _KSEMAPHORE* Semaphore;
        /* 0x00c8 */ struct _KEVENT* DummyEvent;
    }; /* size: 0x0008 */
    /* 0x00d0 */ struct _ALPC_PORT_ATTRIBUTES PortAttributes;
    /* 0x0118 */ struct _EX_PUSH_LOCK Lock;
    /* 0x0120 */ struct _EX_PUSH_LOCK ResourceListLock;
    /* 0x0128 */ struct _LIST_ENTRY ResourceListHead;
    /* 0x0138 */ struct _ALPC_COMPLETION_LIST* CompletionList;
    /* 0x0140 */ struct _ALPC_MESSAGE_ZONE* MessageZone;
    /* 0x0148 */ struct _CALLBACK_OBJECT* CallbackObject;
    /* 0x0150 */ void* CallbackContext;
    /* 0x0158 */ struct _LIST_ENTRY CanceledQueue;
    /* 0x0168 */ volatile long SequenceNo;
    union
    {
        struct
        {
            unsigned long Initialized : 1; /* bit position: 0 */
            unsigned long Type : 2; /* bit position: 1 */
            unsigned long ConnectionPending : 1; /* bit position: 3 */
            unsigned long ConnectionRefused : 1; /* bit position: 4 */
            unsigned long Disconnected : 1; /* bit position: 5 */
            unsigned long Closed : 1; /* bit position: 6 */
            unsigned long NoFlushOnClose : 1; /* bit position: 7 */
            unsigned long ReturnExtendedInfo : 1; /* bit position: 8 */
            unsigned long Waitable : 1; /* bit position: 9 */
            unsigned long DynamicSecurity : 1; /* bit position: 10 */
            unsigned long Wow64CompletionList : 1; /* bit position: 11 */
            unsigned long Lpc : 1; /* bit position: 12 */
            unsigned long LpcToLpc : 1; /* bit position: 13 */
            unsigned long HasCompletionList : 1; /* bit position: 14 */
            unsigned long HadCompletionList : 1; /* bit position: 15 */
            unsigned long EnableCompletionList : 1; /* bit position: 16 */
        } s1;
        /* 0x016c */ unsigned long State;
    } u1;
    /* 0x0170 */ struct _ALPC_PORT* TargetQueuePort;
    /* 0x0178 */ struct _ALPC_PORT* TargetSequencePort;
    /* 0x0180 */ struct _KALPC_MESSAGE* volatile CachedMessage;
    /* 0x0188 */ unsigned long MainQueueLength;
    /* 0x018c */ unsigned long PendingQueueLength;
    /* 0x0190 */ unsigned long LargeMessageQueueLength;
    /* 0x0194 */ unsigned long CanceledQueueLength;
    /* 0x0198 */ unsigned long WaitQueueLength;
    /* 0x019c */ long __PADDING__[1];
} ALPC_PORT_7600, *PALPC_PORT_7600; /* size: 0x01a0 */

//
// Windows 8 ALPC port object.
//
typedef struct _ALPC_PORT_9200 {
    /* 0x0000 */ struct _LIST_ENTRY PortListEntry;
    /* 0x0010 */ struct _ALPC_COMMUNICATION_INFO_V1* CommunicationInfo;
    /* 0x0018 */ struct _EPROCESS* OwnerProcess;
    /* 0x0020 */ void* CompletionPort;
    /* 0x0028 */ void* CompletionKey;
    /* 0x0030 */ struct _ALPC_COMPLETION_PACKET_LOOKASIDE* CompletionPacketLookaside;
    /* 0x0038 */ void* PortContext;
    /* 0x0040 */ struct _SECURITY_CLIENT_CONTEXT StaticSecurity;
    /* 0x0088 */ struct _EX_PUSH_LOCK IncomingQueueLock;
    /* 0x0090 */ struct _LIST_ENTRY MainQueue;
    /* 0x00a0 */ struct _LIST_ENTRY LargeMessageQueue;
    /* 0x00b0 */ struct _EX_PUSH_LOCK PendingQueueLock;
    /* 0x00b8 */ struct _LIST_ENTRY PendingQueue;
    /* 0x00c8 */ struct _EX_PUSH_LOCK WaitQueueLock;
    /* 0x00d0 */ struct _LIST_ENTRY WaitQueue;
    union
    {
        /* 0x00e0 */ struct _KSEMAPHORE* Semaphore;
        /* 0x00e0 */ struct _KEVENT* DummyEvent;
    }; /* size: 0x0008 */
    /* 0x00e8 */ struct _ALPC_PORT_ATTRIBUTES PortAttributes;
    /* 0x0130 */ struct _EX_PUSH_LOCK ResourceListLock;
    /* 0x0138 */ struct _LIST_ENTRY ResourceListHead;
    /* 0x0148 */ struct _EX_PUSH_LOCK PortObjectLock;
    /* 0x0150 */ struct _ALPC_COMPLETION_LIST* CompletionList;
    /* 0x0158 */ struct _ALPC_MESSAGE_ZONE* MessageZone;
    /* 0x0160 */ struct _CALLBACK_OBJECT* CallbackObject;
    /* 0x0168 */ void* CallbackContext;
    /* 0x0170 */ struct _LIST_ENTRY CanceledQueue;
    /* 0x0180 */ long SequenceNo;
    union
    {
        struct
        {
            unsigned long Initialized : 1; /* bit position: 0 */
            unsigned long Type : 2; /* bit position: 1 */
            unsigned long ConnectionPending : 1; /* bit position: 3 */
            unsigned long ConnectionRefused : 1; /* bit position: 4 */
            unsigned long Disconnected : 1; /* bit position: 5 */
            unsigned long Closed : 1; /* bit position: 6 */
            unsigned long NoFlushOnClose : 1; /* bit position: 7 */
            unsigned long ReturnExtendedInfo : 1; /* bit position: 8 */
            unsigned long Waitable : 1; /* bit position: 9 */
            unsigned long DynamicSecurity : 1; /* bit position: 10 */
            unsigned long Wow64CompletionList : 1; /* bit position: 11 */
            unsigned long Lpc : 1; /* bit position: 12 */
            unsigned long LpcToLpc : 1; /* bit position: 13 */
            unsigned long HasCompletionList : 1; /* bit position: 14 */
            unsigned long HadCompletionList : 1; /* bit position: 15 */
            unsigned long EnableCompletionList : 1; /* bit position: 16 */
        } s1;
        /* 0x0184 */ unsigned long State;
    } u1;
    /* 0x0188 */ struct _ALPC_PORT* TargetQueuePort;
    /* 0x0190 */ struct _ALPC_PORT* TargetSequencePort;
    /* 0x0198 */ struct _KALPC_MESSAGE* CachedMessage;
    /* 0x01a0 */ unsigned long MainQueueLength;
    /* 0x01a4 */ unsigned long LargeMessageQueueLength;
    /* 0x01a8 */ unsigned long PendingQueueLength;
    /* 0x01ac */ unsigned long CanceledQueueLength;
    /* 0x01b0 */ unsigned long WaitQueueLength;
    /* 0x01b4 */ long __PADDING__[1];
} ALPC_PORT_9200, *PALPC_PORT_9200; /* size: 0x01b8 */

//
// Windows 8.1 ALPC port object.
//
typedef struct _ALPC_PORT_9600 {
    /* 0x0000 */ struct _LIST_ENTRY PortListEntry;
    /* 0x0010 */ struct _ALPC_COMMUNICATION_INFO_V2* CommunicationInfo;
    /* 0x0018 */ struct _EPROCESS* OwnerProcess;
    /* 0x0020 */ void* CompletionPort;
    /* 0x0028 */ void* CompletionKey;
    /* 0x0030 */ struct _ALPC_COMPLETION_PACKET_LOOKASIDE* CompletionPacketLookaside;
    /* 0x0038 */ void* PortContext;
    /* 0x0040 */ struct _SECURITY_CLIENT_CONTEXT StaticSecurity;
    /* 0x0088 */ struct _EX_PUSH_LOCK IncomingQueueLock;
    /* 0x0090 */ struct _LIST_ENTRY MainQueue;
    /* 0x00a0 */ struct _LIST_ENTRY LargeMessageQueue;
    /* 0x00b0 */ struct _EX_PUSH_LOCK PendingQueueLock;
    /* 0x00b8 */ struct _LIST_ENTRY PendingQueue;
    /* 0x00c8 */ struct _EX_PUSH_LOCK WaitQueueLock;
    /* 0x00d0 */ struct _LIST_ENTRY WaitQueue;
    union
    {
        /* 0x00e0 */ struct _KSEMAPHORE* Semaphore;
        /* 0x00e0 */ struct _KEVENT* DummyEvent;
    }; /* size: 0x0008 */
    /* 0x00e8 */ struct _ALPC_PORT_ATTRIBUTES PortAttributes;
    /* 0x0130 */ struct _EX_PUSH_LOCK ResourceListLock;
    /* 0x0138 */ struct _LIST_ENTRY ResourceListHead;
    /* 0x0148 */ struct _EX_PUSH_LOCK PortObjectLock;
    /* 0x0150 */ struct _ALPC_COMPLETION_LIST* CompletionList;
    /* 0x0158 */ struct _CALLBACK_OBJECT* CallbackObject;
    /* 0x0160 */ void* CallbackContext;
    /* 0x0168 */ struct _LIST_ENTRY CanceledQueue;
    /* 0x0178 */ long SequenceNo;
    /* 0x017c */ long ReferenceNo;
    /* 0x0180 */ struct _PALPC_PORT_REFERENCE_WAIT_BLOCK* ReferenceNoWait;
    union
    {
        struct
        {
            unsigned long Initialized : 1; /* bit position: 0 */
            unsigned long Type : 2; /* bit position: 1 */
            unsigned long ConnectionPending : 1; /* bit position: 3 */
            unsigned long ConnectionRefused : 1; /* bit position: 4 */
            unsigned long Disconnected : 1; /* bit position: 5 */
            unsigned long Closed : 1; /* bit position: 6 */
            unsigned long NoFlushOnClose : 1; /* bit position: 7 */
            unsigned long ReturnExtendedInfo : 1; /* bit position: 8 */
            unsigned long Waitable : 1; /* bit position: 9 */
            unsigned long DynamicSecurity : 1; /* bit position: 10 */
            unsigned long Wow64CompletionList : 1; /* bit position: 11 */
            unsigned long Lpc : 1; /* bit position: 12 */
            unsigned long LpcToLpc : 1; /* bit position: 13 */
            unsigned long HasCompletionList : 1; /* bit position: 14 */
            unsigned long HadCompletionList : 1; /* bit position: 15 */
            unsigned long EnableCompletionList : 1; /* bit position: 16 */
        } s1;
        /* 0x0188 */ unsigned long State;
    } u1;
    /* 0x0190 */ struct _ALPC_PORT* TargetQueuePort;
    /* 0x0198 */ struct _ALPC_PORT* TargetSequencePort;
    /* 0x01a0 */ struct _KALPC_MESSAGE* CachedMessage;
    /* 0x01a8 */ unsigned long MainQueueLength;
    /* 0x01ac */ unsigned long LargeMessageQueueLength;
    /* 0x01b0 */ unsigned long PendingQueueLength;
    /* 0x01b4 */ unsigned long CanceledQueueLength;
    /* 0x01b8 */ unsigned long WaitQueueLength;
    /* 0x01bc */ long __PADDING__[1];
} ALPC_PORT_9600, *PALPC_PORT_9600; /* size: 0x01c0 */

//
// Windows 10 (10240 - 18290) ALPC port object.
//
typedef struct _ALPC_PORT_10240 {
    /* 0x0000 */ struct _LIST_ENTRY PortListEntry;
    /* 0x0010 */ struct _ALPC_COMMUNICATION_INFO_V2* CommunicationInfo;
    /* 0x0018 */ struct _EPROCESS* OwnerProcess;
    /* 0x0020 */ void* CompletionPort;
    /* 0x0028 */ void* CompletionKey;
    /* 0x0030 */ struct _ALPC_COMPLETION_PACKET_LOOKASIDE* CompletionPacketLookaside;
    /* 0x0038 */ void* PortContext;
    /* 0x0040 */ struct _SECURITY_CLIENT_CONTEXT StaticSecurity;
    /* 0x0088 */ struct _EX_PUSH_LOCK IncomingQueueLock;
    /* 0x0090 */ struct _LIST_ENTRY MainQueue;
    /* 0x00a0 */ struct _LIST_ENTRY LargeMessageQueue;
    /* 0x00b0 */ struct _EX_PUSH_LOCK PendingQueueLock;
    /* 0x00b8 */ struct _LIST_ENTRY PendingQueue;
    /* 0x00c8 */ struct _EX_PUSH_LOCK DirectQueueLock;
    /* 0x00d0 */ struct _LIST_ENTRY DirectQueue;
    /* 0x00e0 */ struct _EX_PUSH_LOCK WaitQueueLock;
    /* 0x00e8 */ struct _LIST_ENTRY WaitQueue;
    union
    {
        /* 0x00f8 */ struct _KSEMAPHORE* Semaphore;
        /* 0x00f8 */ struct _KEVENT* DummyEvent;
    }; /* size: 0x0008 */
    /* 0x0100 */ struct _ALPC_PORT_ATTRIBUTES PortAttributes;
    /* 0x0148 */ struct _EX_PUSH_LOCK ResourceListLock;
    /* 0x0150 */ struct _LIST_ENTRY ResourceListHead;
    /* 0x0160 */ struct _EX_PUSH_LOCK PortObjectLock;
    /* 0x0168 */ struct _ALPC_COMPLETION_LIST* CompletionList;
    /* 0x0170 */ struct _CALLBACK_OBJECT* CallbackObject;
    /* 0x0178 */ void* CallbackContext;
    /* 0x0180 */ struct _LIST_ENTRY CanceledQueue;
    /* 0x0190 */ long SequenceNo;
    /* 0x0194 */ long ReferenceNo;
    /* 0x0198 */ struct _PALPC_PORT_REFERENCE_WAIT_BLOCK* ReferenceNoWait;
    union
    {
        struct /* bitfield */
        {
            /* 0x01a0 */ unsigned long Initialized : 1; /* bit position: 0 */
            /* 0x01a0 */ unsigned long Type : 2; /* bit position: 1 */
            /* 0x01a0 */ unsigned long ConnectionPending : 1; /* bit position: 3 */
            /* 0x01a0 */ unsigned long ConnectionRefused : 1; /* bit position: 4 */
            /* 0x01a0 */ unsigned long Disconnected : 1; /* bit position: 5 */
            /* 0x01a0 */ unsigned long Closed : 1; /* bit position: 6 */
            /* 0x01a0 */ unsigned long NoFlushOnClose : 1; /* bit position: 7 */
            /* 0x01a0 */ unsigned long ReturnExtendedInfo : 1; /* bit position: 8 */
            /* 0x01a0 */ unsigned long Waitable : 1; /* bit position: 9 */
            /* 0x01a0 */ unsigned long DynamicSecurity : 1; /* bit position: 10 */
            /* 0x01a0 */ unsigned long Wow64CompletionList : 1; /* bit position: 11 */
            /* 0x01a0 */ unsigned long Lpc : 1; /* bit position: 12 */
            /* 0x01a0 */ unsigned long LpcToLpc : 1; /* bit position: 13 */
            /* 0x01a0 */ unsigned long HasCompletionList : 1; /* bit position: 14 */
            /* 0x01a0 */ unsigned long HadCompletionList : 1; /* bit position: 15 */
            /* 0x01a0 */ unsigned long EnableCompletionList : 1; /* bit position: 16 */
        } s1;
        /* 0x01a0 */ unsigned long State;
    } u1;
    /* 0x01a8 */ struct _ALPC_PORT* TargetQueuePort;
    /* 0x01b0 */ struct _ALPC_PORT* TargetSequencePort;
    /* 0x01b8 */ struct _KALPC_MESSAGE* CachedMessage;
    /* 0x01c0 */ unsigned long MainQueueLength;
    /* 0x01c4 */ unsigned long LargeMessageQueueLength;
    /* 0x01c8 */ unsigned long PendingQueueLength;
    /* 0x01cc */ unsigned long DirectQueueLength;
    /* 0x01d0 */ unsigned long CanceledQueueLength;
    /* 0x01d4 */ unsigned long WaitQueueLength;
} ALPC_PORT_10240, *PALPC_PORT_10240; /* size: 0x01d8 */

NTSYSAPI
NTSTATUS 
NTAPI 
NtAlpcCreatePort(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes);

NTSYSAPI
NTSTATUS 
NTAPI 
NtAlpcDisconnectPort(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags);

NTSYSAPI
NTSTATUS 
NTAPI 
NtAlpcQueryInformation(
    _In_ HANDLE PortHandle,
    _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    _Inout_updates_bytes_to_(Length, *ReturnLength) PVOID PortInformation,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength);

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcAcceptConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ HANDLE ConnectionPortHandle,
    _In_ ULONG Flags,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_opt_ PVOID PortContext,
    _In_opt_ PPORT_MESSAGE ConnectionRequest,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    _In_ BOOLEAN AcceptConnection);

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcSendWaitReceivePort(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_opt_ PPORT_MESSAGE pSendMessage,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    _Out_opt_ PPORT_MESSAGE pReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout);

//
// NTALPC_RTL HEADER END
//

#ifdef __cplusplus
}
#endif

#pragma warning(pop)

#endif NTALPC_RTL
