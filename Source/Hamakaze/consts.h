/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.25
*
*  DATE:        17 Aug 2022
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

#define KDU_VERSION_MAJOR       1
#define KDU_VERSION_MINOR       2
#define KDU_VERSION_REVISION    5
#define KDU_VERSION_BUILD       2208

#define KDU_BASE_ID             0xff123456
#define KDU_SYNC_MUTANT         0xabcd

#define NT_REG_PREP             L"\\Registry\\Machine"
#define DRIVER_REGKEY           L"%wS\\System\\CurrentControlSet\\Services\\%wS"

#define PROCEXP152              L"PROCEXP152"
#define PROCEXP_DESC            L"Process Explorer"

#define NTOSKRNL_EXE            L"ntoskrnl.exe"
#define CI_DLL                  L"CI.dll"

#define DRV64DLL                L"drv64.dll"
#define DUMMYDLL                L"SB_SMBUS_SDK.dll"

#define WINIO_BASE_DESC         "WinIo by Yariv Kaplan"
#define WINRING0_BASE_DESC      "WinRing0 by Noriyuki Miyazaki"
#define MAPMEM_BASE_DESC        "MapMem from NTDDK 3.51"
#define PHYMEM_BASE_DESC        "PhyMem by akui"

#define SHELL_POOL_TAG          '  oI'

#define PROVIDER_RES_KEY        ' owo' // Giving you enough uwu's.

#define SYSTEM_PID_MAGIC             4

//
// Data id table
//
#define IDR_DATA_DBUTILCAT              1000
#define IDR_DATA_DBUTILINF              1001
#define IDR_DATA_KMUEXE                 1002
#define IDR_DATA_KMUSIG                 1003
#define IDR_DATA_ASUSCERTSERVICE        1004

//
// Driver id table
//
#define IDR_PROCEXP                     100
#define IDR_iQVM64                      103
#define IDR_RTCORE64                    105
#define IDR_GDRV                        106
#define IDR_ATSZIO64                    107
#define IDR_MSIO64                      108
#define IDR_GLCKIO2                     109
#define IDR_ENEIO64                     110
#define IDR_WINRING0                    111
#define IDR_ENETECHIO64                 112
#define IDR_PHYMEMX64                   113
#define IDR_RTKIO64                     114
#define IDR_ENETECHIO64B                115
#define IDR_LHA                         116
#define IDR_ASUSIO2                     117
#define IDR_DIRECTIO64                  118
#define IDR_GMERDRV                     119
#define IDR_DBUTIL23                    120
#define IDR_MIMIDRV                     121
#define IDR_KPH                         122
#define IDR_DBUTILDRV2                  123
#define IDR_DBK64                       124
#define IDR_ASUSIO3                     125
#define IDR_HW64                        126
