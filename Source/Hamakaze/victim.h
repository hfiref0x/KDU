/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2022
*
*  TITLE:       VICTIM.H
*
*  VERSION:     1.20
*
*  DATE:        08 Feb 2022
*
*  Victim support prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef BOOL(WINAPI* pfnVictimCreate)(
    _In_opt_ HINSTANCE ModuleBase,
    _In_ LPCWSTR Name,
    _In_ ULONG ResourceId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE VictimHandle
    );

typedef BOOL(WINAPI* pfnVictimRelease)(
    _In_ LPCWSTR Name
    );

typedef VOID(WINAPI* pfnVictimExecute)(
    _In_ LPCWSTR Name,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE VictimHandle
    );

//
// No optional victim flags specified, this is default value.
//
#define KDU_VICTIM_FLAGS_NONE               0x00000000

//
// Victim can be reloaded.
//
#define KDU_VICTIM_FLAGS_SUPPORT_RELOAD     0x00000001

typedef struct _KDU_VICTIM_PROVIDER {
    LPCWSTR Name; //same as device name
    LPCWSTR Desc; //optional
    ULONG ResourceId;
    ACCESS_MASK DesiredAccess;
    union {
        ULONG Flags;
        struct {
            ULONG SupportReload : 1;
            ULONG Reserved : 31;
        };
    };
    struct {
        pfnVictimCreate Create;
        pfnVictimRelease Release;
        pfnVictimExecute Execute;
    } Callbacks;
} KDU_VICTIM_PROVIDER, * PKDU_VICTIM_PROVIDER;

BOOL VpCreate(
    _Inout_ PKDU_VICTIM_PROVIDER Context,
    _In_opt_ HINSTANCE ModuleBase,
    _Out_opt_ PHANDLE VictimHandle);

BOOL VpRelease(
    _In_ PKDU_VICTIM_PROVIDER Context,
    _Inout_opt_ PHANDLE VictimHandle);

VOID VpExecutePayload(
    _In_ PKDU_VICTIM_PROVIDER Context,
    _Out_opt_ PHANDLE VictimHandle);

BOOL VpCreateCallback(
    _In_ HINSTANCE ModuleBase,
    _In_ LPCWSTR Name,
    _In_ ULONG ResourceId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE VictimHandle);

BOOL VpReleaseCallback(
    _In_ LPCWSTR Name);

VOID VpExecuteCallback(
    _In_ LPCWSTR Name,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE VictimHandle);

BOOL VpCreateFromExistingCallback(
    _In_ HINSTANCE ModuleBase,
    _In_ LPCWSTR Name,
    _In_ ULONG ResourceId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE VictimHandle);

VOID VpExecuteFromExistingCallback(
    _In_ LPCWSTR Name,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE VictimHandle);

BOOL VpReleaseCallbackStub(
    _In_ LPCWSTR Name);
