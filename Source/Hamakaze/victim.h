/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2021
*
*  TITLE:       VICTIM.H
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
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

BOOL VictimCreate(
    _In_ HINSTANCE ModuleBase,
    _In_ LPWSTR Name, //same as device name
    _In_ ULONG ResourceId,
    _Out_opt_ PHANDLE VictimHandle);

BOOL VictimRelease(
    _In_ LPWSTR Name);
