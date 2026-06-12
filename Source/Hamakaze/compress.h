/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       COMPRESS.H
*
*  VERSION:     1.49
*
*  DATE:        11 Jun 2026
*
*  Compression support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

VOID EncodeBuffer(
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ ULONG Key);

PVOID KDULoadResource(
    _In_ ULONG ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize,
    _In_ ULONG DecryptKey,
    _In_ BOOLEAN VerifyChecksum);

PVOID KDUDecompressResource(
    _In_ PVOID ResourcePtr,
    _In_ SIZE_T ResourceSize,
    _Out_ PSIZE_T DecompressedSize,
    _In_ ULONG DecryptKey,
    _In_ BOOLEAN VerifyChecksum);

