/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       SYM.H
*
*  VERSION:     1.30
*
*  DATE:        08 Apr 2023
*
*  Symbols routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

BOOL symInit();

BOOL symLoadImageSymbols(
    _In_ LPCWSTR lpFileName,
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize);

BOOL symLookupAddressBySymbol(
    _In_ LPCSTR SymbolName,
    _Out_ PULONG_PTR Address);
