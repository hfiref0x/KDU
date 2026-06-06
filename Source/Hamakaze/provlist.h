/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       PROVLIST.H
*
*  VERSION:     1.49
*
*  DATE:        06 Jun 2026
*
*  Provider list output support.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

VOID KDUProvList();
BOOL KDUProvListCsv(
    _In_opt_ LPCWSTR OutputFileName);
