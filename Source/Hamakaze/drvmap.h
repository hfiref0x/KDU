/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       DRVMAP.H
*
*  VERSION:     1.01
*
*  DATE:        20 Apr 2020
*
*  Prototypes and definitions for driver mapping.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef ULONG(NTAPI* pfnDbgPrint)(
    _In_ PCHAR Format,
    ...);

typedef PVOID(NTAPI* pfnExAllocatePool)(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes);

typedef VOID(NTAPI* pfnExFreePool)(
    _In_ PVOID P);

typedef NTSTATUS(NTAPI* pfnPsCreateSystemThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_  HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ PVOID StartContext);

typedef NTSTATUS(NTAPI* pfnZwClose)(
    _In_ HANDLE Handle);

typedef NTSTATUS(NTAPI* pfnZwOpenKey)(
    _Out_ PHANDLE KeyHandle,
    _In_  ACCESS_MASK DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI* pfnZwQueryValueKey)(
    _In_      HANDLE KeyHandle,
    _In_      PUNICODE_STRING ValueName,
    _In_      KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_opt_ PVOID KeyValueInformation,
    _In_      ULONG Length,
    _Out_     PULONG ResultLength);

typedef NTSTATUS(NTAPI* pfnZwDeleteValueKey)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName);

typedef VOID(NTAPI* pfnIofCompleteRequest)(
    _In_ VOID* Irp,
    _In_ CCHAR PriorityBoost);

typedef NTSTATUS(NTAPI* pfnObReferenceObjectByHandle)(
    _In_ HANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PVOID* Object,
    _Out_opt_ PVOID HandleInformation);

typedef VOID(NTAPI* pfnObfDereferenceObject)(
    _In_ PVOID Object);

typedef NTSTATUS(NTAPI* pfnKeSetEvent)(
    _In_ PKEVENT Event,
    _In_ KPRIORITY Increment,
    _In_ _Literal_ BOOLEAN Wait);

typedef struct _FUNC_TABLE {
    pfnExAllocatePool ExAllocatePool;
    pfnExFreePool ExFreePool;
    pfnPsCreateSystemThread PsCreateSystemThread;
    pfnIofCompleteRequest IofCompleteRequest;
    pfnZwClose ZwClose;
    pfnZwOpenKey ZwOpenKey;
    pfnZwQueryValueKey ZwQueryValueKey;
    pfnZwDeleteValueKey ZwDeleteValueKey;
    pfnObReferenceObjectByHandle ObReferenceObjectByHandle;
    pfnObfDereferenceObject ObfDereferenceObject;
    pfnKeSetEvent KeSetEvent;
   // pfnDbgPrint DbgPrint;
} FUNC_TABLE, * PFUNC_TABLE;

BOOL KDUMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ LPWSTR lpMapDriverFileName);
