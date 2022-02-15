/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       DRVMAP.H
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
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
    _In_ HANDLE SectionHandle);

BOOL KDUMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase);
