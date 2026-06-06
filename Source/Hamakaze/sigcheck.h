/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       SIGCHECK.H
*
*  VERSION:     1.49
*
*  DATE:        06 Jun 2026
*
*  In-memory signature parsing support.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef enum _KDU_SIGNINFO_STATE {
    KduSignInfoUnavailable = 0,
    KduSignInfoSigned
} KDU_SIGNINFO_STATE;

typedef struct _KDU_SIGN_INFO {
    KDU_SIGNINFO_STATE State;
    LPWSTR SignerName;
} KDU_SIGN_INFO, * PKDU_SIGN_INFO;

_Success_(return != FALSE)
BOOL KDUQueryImageSignInfo(
    _In_reads_bytes_(ImageSize) PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKDU_SIGN_INFO SignInfo);

VOID KDUFreeImageSignInfo(
    _In_ PKDU_SIGN_INFO SignInfo);
