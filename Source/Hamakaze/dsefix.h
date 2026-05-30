/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2026
*
*  TITLE:       DSEFIX.H
*
*  VERSION:     1.48
*
*  DATE:        29 May 2026
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

BOOL KDUInstructionIsRipRelativeStore32(
    _In_ hde64s* Hs,
    _In_ PBYTE Code);

NTSTATUS KDUQueryCiOptions(
    _In_ HMODULE ImageMappedBase,
    _In_ ULONG_PTR ImageLoadedBase,
    _Out_ ULONG_PTR* ResolvedAddress,
    _In_ ULONG NtBuildNumber);

NTSTATUS KDUQueryCiOptionsEx(
    _In_ HMODULE ImageMappedBase,
    _In_ ULONG_PTR ImageLoadedBase,
    _In_ PBYTE CiInitialize,
    _Out_ ULONG_PTR* ResolvedAddress,
    _In_ ULONG NtBuildNumber);

ULONG KDUValidateCiInitializeCode(
    _In_ PBYTE Code,
    _In_ ULONG Offset,
    _In_ ULONG MaxLength);

BOOL KDUControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address);

BOOL KDUControlDSE2(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address);

