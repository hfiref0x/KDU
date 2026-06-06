/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       HASH.H
*
*  VERSION:     1.49
*
*  DATE:        06 Jun 2026
*
*  In-memory hash support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef struct _KDU_IMAGE_HASH_INFO {
    BYTE FileHashSha1[20];
    BYTE AuthenticodeHashSha1[20];
    BYTE PageHashSha1[20];
    BYTE PageHashSha256[32];
    BOOL FileHashSha1Valid;
    BOOL AuthenticodeHashSha1Valid;
    BOOL PageHashSha1Valid;
    BOOL PageHashSha256Valid;
} KDU_IMAGE_HASH_INFO, * PKDU_IMAGE_HASH_INFO;

_Success_(return != FALSE)
BOOL KDUCalcImageHashes(
    _In_reads_bytes_(ImageSize) PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKDU_IMAGE_HASH_INFO HashInfo);

VOID KDUPrintHashValue(
    _In_reads_bytes_(HashSize) PBYTE Hash,
    _In_ ULONG HashSize);
