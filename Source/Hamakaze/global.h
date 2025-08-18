/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.44
*
*  DATE:        18 Aug 2025
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

#define KDU_SHELLCODE_NONE  (0)
#define KDU_SHELLCODE_V1    (1)
#define KDU_SHELLCODE_V2    (2)
#define KDU_SHELLCODE_V3    (3)
#define KDU_SHELLCODE_V4    (4)
#define KDU_SHELLCODE_VMAX  KDU_SHELLCODE_V4

#include <Windows.h>
#include <strsafe.h>
#include <ntstatus.h>
#include <intrin.h>
#include <rpc.h>
#include <SetupAPI.h>
#include <newdev.h>
#include <Bcrypt.h>
#include<fltuser.h>

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

#include "ntos/ntos.h"
#include "ntos/halamd64.h"
#include "ntos/ntbuilds.h"
#include "ntos/ntsup.h"
#include "ldr/ldr.h"
#include "wdksup.h"
#include "resource.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Newdev.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "FltLib.lib")

#include "shared/consts.h"
#include "shared/kdubase.h"
#include "sig.h"
#include "ipcsvc.h"
#include "sup.h"
#include "sym.h"
#include "compress.h"
#include "victim.h"
#include "kduprov.h"
#include "shellcode.h"
#include "drvmap.h"
#include "ps.h"
#include "pagewalk.h"
#include "dsefix.h"
#include "diag.h"
#include "tests.h"

#define ASSERT_RESOLVED_FUNC(FunctionPtr) { if (FunctionPtr == 0) break; }
#define ASSERT_RESOLVED_FUNC_ABORT(FunctionPtr) { if (FunctionPtr == 0) return FALSE; }
