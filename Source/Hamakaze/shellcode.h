/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       SHELLCODE.H
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  Default driver mapping shellcode(s) prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _PAYLOAD_HEADER_V1 {
    ULONG ImageSize;
    IO_STATUS_BLOCK IoStatus;

    //
    // Variant specific fields.
    // 
    pfnPsCreateSystemThread PsCreateSystemThread;
    pfnZwClose ZwClose;

    //BYTE Payload[ANYSIZE_ARRAY]; //following header, not a part of this structure
} PAYLOAD_HEADER_V1, * PPAYLOAD_HEADER_V1;

typedef struct _PAYLOAD_HEADER_V2 {
    ULONG ImageSize;
    IO_STATUS_BLOCK IoStatus;

    //
    // Variant specific fields.
    //
    pfnExQueueWorkItem ExQueueWorkItem;

    //BYTE Payload[ANYSIZE_ARRAY]; //following header, not a part of this structure
} PAYLOAD_HEADER_V2, * PPAYLOAD_HEADER_V2;

typedef struct _PAYLOAD_HEADER_V3 {
    ULONG ImageSize;
    IO_STATUS_BLOCK IoStatus;

    //
    // Variant specific fields.
    //
    PVOID IoDriverObjectType;
    pfnObCreateObject ObCreateObject;
    pfnObInsertObject ObInsertObject;
    pfnObMakeTemporaryObject ObMakeTemporaryObject;
    pfnZwMakeTemporaryObject ZwMakeTemporaryObject;
    pfnZwClose ZwClose;

    FIXED_UNICODE_STRING ObjectName;
    FIXED_UNICODE_STRING RegistryPath;

    //BYTE Payload[ANYSIZE_ARRAY]; //following header, not a part of this structure
} PAYLOAD_HEADER_V3, * PPAYLOAD_HEADER_V3;

SIZE_T ScGetViewSize(
    _In_ ULONG ShellVersion,
    _In_ PVOID ShellCodePtr);

DWORD ScSizeOf(
    _In_ ULONG ShellVersion,
    _Out_opt_ PULONG PayloadSize);

BOOLEAN ScCreateFixedUnicodeString(
    _Inout_ PFIXED_UNICODE_STRING DestinationString,
    _In_ PCWSTR SourceString);

HANDLE ScCreateReadyEvent(
    _In_ ULONG ShellVersion,
    _In_ PVOID ShellPtr);

BOOLEAN ScStoreVersionSpecificData(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID PayloadPtr);

VOID ScFree(
    _In_ PVOID ShellPtr);

BOOLEAN ScResolveImportForPayload(
    _In_ ULONG ShellVersion,
    _In_ PVOID PayloadHead,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase);

PVOID ScAllocate(
    _In_ ULONG ShellVersion,
    _In_ HANDLE SectionHandle,
    _In_ SIZE_T SectionViewSize,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG MemoryTag,
    _Out_ PULONG ShellSize);
