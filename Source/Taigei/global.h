/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  Common include header file for Taigei.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if defined(_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma warning(disable: 4005)

#include <Windows.h>
#include <ntstatus.h>
#include "../Shared/ntos/ntos.h"

#if defined(__cplusplus)
extern "C" {
#endif

#include "../Shared/minirtl/minirtl.h"
#include "../Shared/minirtl/rtltypes.h"

#ifdef __cplusplus
}
#endif

#include "ipc.h"
#include "asio.h"
