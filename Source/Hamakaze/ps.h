/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2022
*
*  TITLE:       PS.H
*
*  VERSION:     1.12
*
*  DATE:        25 Jan 2022
*
*  Processes support prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define PsProtectionOffset_9600  (ULONG_PTR)0x67A
#define PsProtectionOffset_10240 (ULONG_PTR)0x6AA
#define PsProtectionOffset_10586 (ULONG_PTR)0x6B2
#define PsProtectionOffset_14393 (ULONG_PTR)0x6C2
#define PsProtectionOffset_15063 (ULONG_PTR)0x6CA //same for 16299, 17134, 17763
#define PsProtectionOffset_18362 (ULONG_PTR)0x6FA
#define PsProtectionOffset_18363 (ULONG_PTR)0x6FA
#define PsProtectionOffset_19041 (ULONG_PTR)0x87A //same for 19042..19044

#define EPROCESS_TO_PROTECTION(Object, PsProtectionOffset) ((ULONG_PTR)Object + (ULONG_PTR)PsProtectionOffset)

BOOL KDUUnprotectProcess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId);

BOOL KDURunCommandPPL(
    _In_ PKDU_CONTEXT Context,
    _In_ LPWSTR CommandLine);

BOOL KDUControlProcess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ PS_PROTECTED_SIGNER PsProtectionSigner,
    _In_ PS_PROTECTED_TYPE PsProtectionType);

