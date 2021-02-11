/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.02
*
*  DATE:        11 Feb 2021
*
*  Global consts.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define NT_REG_PREP             L"\\Registry\\Machine"
#define DRIVER_REGKEY           L"%wS\\System\\CurrentControlSet\\Services\\%wS"

#define PROCEXP152              L"PROCEXP152"

#define NTOSKRNL_EXE            "ntoskrnl.exe"
#define CI_DLL                  "CI.dll"

//
// Defines for Major Windows NT release builds
//

// Windows 7 RTM
#define NT_WIN7_RTM             7600

// Windows 7 SP1
#define NT_WIN7_SP1             7601

// Windows 8 RTM
#define NT_WIN8_RTM             9200

// Windows 8.1
#define NT_WIN8_BLUE            9600

// Windows 10 TH1
#define NT_WIN10_THRESHOLD1     10240

// Windows 10 TH2
#define NT_WIN10_THRESHOLD2     10586

// Windows 10 RS1
#define NT_WIN10_REDSTONE1      14393

// Windows 10 RS2
#define NT_WIN10_REDSTONE2      15063

// Windows 10 RS3
#define NT_WIN10_REDSTONE3      16299

// Windows 10 RS4
#define NT_WIN10_REDSTONE4      17134

// Windows 10 RS5
#define NT_WIN10_REDSTONE5      17763

// Windows 10 19H1
#define NT_WIN10_19H1           18362

// Windows 10 19H2
#define NT_WIN10_19H2           18363

// Windows 10 20H1
#define NT_WIN10_20H1           19041

// Windows 10 20H2
#define NT_WIN10_20H2           19042

// Windows 10 21H1
#define NT_WIN10_21H1           19043

// Windows 10 Active Develepment Branch (21XX)
#define NTX_WIN10_ADB           21296
