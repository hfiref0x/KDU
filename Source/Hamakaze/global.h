/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
*
*  Common include header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

//
// Ignored warnings
//
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4091) // 'typedef ': ignored on left of '%s' when no variable is declared
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'

#include <Windows.h>
#include <strsafe.h>
#include <ntstatus.h>
#include <intrin.h>
#include "ntdll/ntos.h"
#include "resource.h"

#if defined(__cplusplus)
extern "C" {
#endif

#include "hde/hde64.h"
#include "minirtl/minirtl.h"
#include "minirtl/rtltypes.h"
#include "minirtl/cmdline.h"
#include "minirtl/_filename.h"

#ifdef __cplusplus
}
#endif

#include "consts.h"
#include "sup.h"
#include "compress.h"
#include "kduprov.h"
#include "drvmap.h"
#include "ps.h"
#include "victim.h"
#include "pagewalk.h"
#include "tests.h"
