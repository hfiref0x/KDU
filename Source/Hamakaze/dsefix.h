/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2025
*
*  TITLE:       DSEFIX.H
*
*  VERSION:     1.45
*
*  DATE:        02 Dec 2025
*
*  CI DSE corruption prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

ULONG_PTR KDUQueryCodeIntegrityVariableAddress(
    _In_ ULONG NtBuildNumber);

ULONG_PTR KDUQueryCodeIntegrityVariableSymbol(
    _In_ ULONG NtBuildNumber);

BOOL KDUControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address);

BOOL KDUControlDSE2(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address);

