/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020 gruf0x
*
*  TITLE:       COMPRESS.H
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
*
*  Compression support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

PVOID KDUDecompressResource(
    _In_ PVOID ResourcePtr,
    _In_ SIZE_T ResourceSize,
    _Out_ PSIZE_T DecompressedSize);

VOID KDUCompressResource(
    _In_ LPWSTR lpFileName);
