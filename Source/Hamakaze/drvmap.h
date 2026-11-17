/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       DRVMAP.H
*
*  VERSION:     1.51
*
*  DATE:        14 Nov 2026
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

PVOID KDUSetupShellCode(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase,
    _Out_ PHANDLE SectionHandle);

VOID KDUShowPayloadResult(
    _In_ PKDU_CONTEXT Context,
    _In_ HANDLE SectionHandle,
    _In_ BOOL EventSignaled);

BOOL KDUMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase);

BOOL WINAPI KDUPagePatchCallback(
    _In_ ULONG_PTR Address,
    _In_ PVOID UserContext);
