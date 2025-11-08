/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       PS.H
*
*  VERSION:     1.44
*
*  DATE:        01 Nov 2025
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

#define PsProtectionOffset_9600  0x67A
#define PsProtectionOffset_10240 0x6AA
#define PsProtectionOffset_10586 0x6B2
#define PsProtectionOffset_14393 0x6C2
#define PsProtectionOffset_15063 0x6CA //same for 16299, 17134, 17763
#define PsProtectionOffset_18362 0x6FA
#define PsProtectionOffset_18363 0x6FA
#define PsProtectionOffset_19041 0x87A //same for 19042..19045
#define PsProtectionOffset_26100 0x5FA //sane for 26100..26200 (24H2, 25H2)

//RS3..RS4
#define PsMitigationFlags1Offset_RS3    0x828
#define PsMitigationFlags2Offset_RS3    0x82c

#define PsMitigationFlags1Offset_RS5    0x820
#define PsMitigationFlags2Offset_RS5    0x824

// 1903..1909
#define PsMitigationFlags1Offset_18362  0x850
#define PsMitigationFlags2Offset_18362  0x854

// 2004..23H2
#define PsMitigationFlags1Offset_19041  0x9d0
#define PsMitigationFlags2Offset_19041  0x9d4

//24H2..25H2
#define PsMitigationFlags1Offset_26100 0x750
#define PsMitigationFlags2Offset_26100 0x754

#define PS_MITIGATION_FLAGS1 0x00000001
#define PS_MITIGATION_FLAGS2 0x00000002

#define EPROCESS_TO_PROTECTION(Object, Offset) ((ULONG_PTR)(Object) + (Offset))
#define EPROCESS_TO_MITIGATIONFLAGS(Object, FlagsOffset) ((ULONG_PTR)(Object) + (FlagsOffset))

BOOL KDUUnprotectProcess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId);

BOOL KDUUnmitigateProcess(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG PsNewMitigation,
    _In_ INT TargetedFlags);

BOOL KDURunCommandPPL(
    _In_ PKDU_CONTEXT Context,
    _In_ LPWSTR CommandLine,
    _In_ BOOL HighestSigner);

BOOL KDUDumpProcessMemory(
    _In_ PKDU_CONTEXT Context,
    _In_ HANDLE ProcessId);

BOOL KDUControlProcessProtections(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ PS_PROTECTED_SIGNER PsProtectionSigner,
    _In_ PS_PROTECTED_TYPE PsProtectionType);

BOOL KDUControlProcessMitigationFlags(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG_PTR ProcessId,
    _In_ ULONG PsMitigations,
    _In_ INT TargetedFlags);
