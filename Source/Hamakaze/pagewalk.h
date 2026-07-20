/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2026
*
*  TITLE:       PAGEWALK.H
*
*  VERSION:     1.13
*
*  DATE:        18 Jul 2026
*
*  Page table translation prototypes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

BOOL PwIsCanonicalAddress(
    _In_ BOOL IsLA57,
    _In_ ULONG_PTR Address);

BOOL PwVirtualToPhysicalEx(
    _In_ BOOL UseLA57,
    _In_ HANDLE DeviceHandle,
    _In_ provQueryPageTableBase QueryPageTableBaseRoutine,
    _In_ provReadPhysicalMemory ReadPhysicalMemoryRoutine,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);

BOOL PwVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ provQueryPageTableBase QueryPageTableBaseRoutine,
    _In_ provReadPhysicalMemory ReadPhysicalMemoryRoutine,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);
