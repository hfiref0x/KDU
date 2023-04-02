/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.30
*
*  DATE:        24 Mar 2023
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
#define KDU_VERSION_MINOR       3
#define KDU_VERSION_REVISION    0
#define KDU_VERSION_BUILD       2303

#define KDU_MIN_NTBUILDNUMBER   0x1DB1      //Windows 7 SP1
#define KDU_MAX_NTBUILDNUMBER   0xFFFFFFFF  //Undefined

#define KDU_BASE_ID             0xff123456
#define KDU_SYNC_MUTANT         0xabcd

#define NT_REG_PREP             L"\\Registry\\Machine"
#define DRIVER_REGKEY           L"%wS\\System\\CurrentControlSet\\Services\\%wS"

#define PROCEXP152              L"PROCEXP152"
#define PROCEXP1627_DESC        L"Process Explorer v16"
#define PROCEXP1702_DESC        L"Process Explorer v17"

#define NTOSKRNL_EXE            L"ntoskrnl.exe"
#define CI_DLL                  L"CI.dll"

#define DRV64DLL                L"drv64.dll"
#define DUMMYDLL                L"SB_SMBUS_SDK.dll"

#define WINIO_BASE_DESC         "WinIo by Yariv Kaplan"
#define WINRING0_BASE_DESC      "WinRing0 by Noriyuki Miyazaki"
#define MAPMEM_BASE_DESC        "MapMem from NTDDK 3.51"
#define PHYMEM_BASE_DESC        "PhyMem by akui"
#define RWEVERYTHING_BASE_DESC  "RWEverything by ckimchan.tw"

#define CPU_VENDOR_INTEL        "GenuineIntel"
#define CPU_VENDOR_INTEL_LENGTH sizeof(CPU_VENDOR_INTEL) - sizeof(CHAR)
#define CPU_VENDOR_AMD          "AuthenticAMD"
#define CPU_VENDOR_AMD_LENGTH sizeof(CPU_VENDOR_AMD) - sizeof(CHAR)

#define SHELL_POOL_TAG          '  oI'

#define PROVIDER_RES_KEY        ' owo' // Giving you enough uwu's.

#define SYSTEM_PID_MAGIC           4

#define TEXT_SECTION ".text"
#define TEXT_SECTION_LEGNTH sizeof(TEXT_SECTION)

#define SHELLCODE_SMALL            0x200

//
// Victim providers id table
//
#define KDU_VICTIM_PE1627  0
#define KDU_VICTIM_PE1702  1
#define KDU_VICTIM_MAX     2
#define KDU_VICTIM_DEFAULT KDU_VICTIM_PE1702

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
#define IDR_PROCEXP1627                 2000
#define IDR_PROCEXP1702                 2001
#define IDR_INTEL_NAL                   103
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
#define IDR_SYSDRV3S                    127
#define IDR_ZEMANA                      128
#define IDR_INPOUTX64                   129
#define IDR_PASSMARK_OSF                130
#define IDR_ASROCKDRV                   131
#define IDR_ALSYSIO64                   132
#define IDR_AMD_RYZENMASTER             133
#define IDR_PHYSMEM                     134
#define IDR_RESERVED1                   135
#define IDR_RESERVED2                   136
#define IDR_RESERVED3                   137
#define IDR_RESERVED4                   138
#define IDR_RESERVED6                   140

//
// Vulnerable drivers providers id
//
#define KDU_PROVIDER_INTEL_NAL          0
#define KDU_PROVIDER_UNWINDER_RTCORE    1
#define KDU_PROVIDER_GIGABYTE_GDRV      2
#define KDU_PROVIDER_ASUSTEK_ATSZIO     3
#define KDU_PROVIDER_PATRIOT_MSIO64     4
#define KDU_PROVIDER_GLCKIO2            5
#define KDU_PROVIDER_ENEIO64            6
#define KDU_PROVIDER_WINRING0           7
#define KDU_PROVIDER_ENETECHIO64        8
#define KDU_PROVIDER_PHYMEM64           9
#define KDU_PROVIDER_RTKIO64            10
#define KDU_PROVIDER_ENETECHIO64B       11
#define KDU_PROVIDER_LHA                12
#define KDU_PROVIDER_ASUSIO2            13
#define KDU_PROVIDER_DIRECTIO64         14
#define KDU_PROVIDER_GMER               15
#define KDU_PROVIDER_DBUTIL23           16
#define KDU_PROVIDER_MIMIDRV            17
#define KDU_PROVIDER_KPH                18
#define KDU_PROVIDER_PROCEXP            19
#define KDU_PROVIDER_DBUTILDRV2         20
#define KDU_PROVIDER_DBK64              21
#define KDU_PROVIDER_ASUSIO3            22
#define KDU_PROVIDER_HW64               23
#define KDU_PROVIDER_SYSDRV3S           24
#define KDU_PROVIDER_ZEMANA             25
#define KDU_PROVIDER_INPOUTX64          26
#define KDU_PROVIDER_PASSMARK_OSF       27
#define KDU_PROVIDER_ASROCK             28
#define KDU_PROVIDER_ALCPU              29
#define KDU_PROVIDER_AMD_RYZENMASTER    30
#define KDU_PROVIDER_HR_PHYSMEM         31

#define KDU_PROVIDER_DEFAULT KDU_PROVIDER_INTEL_NAL

//
// KDU provider flags
//
// No optional provider flags specified, this is default value.
//
#define KDUPROV_FLAGS_NONE                  0x00000000

//
// Provider does support HVCI security measures.
//
#define KDUPROV_FLAGS_SUPPORT_HVCI          0x00000001

//
// Provider is WHQL signed.
//
#define KDUPROV_FLAGS_SIGNATURE_WHQL        0x00000002 

//
// Provider has invalid checksum, so do not forceble check it.
// 
// Several valid signed Realtek drivers has invalid checksum set in their PE header.
// This flag will tell KDU to skip it checksum verification at loading stage.
// Note: Windows 7 does check driver checksum to be valid thus such drivers will fail to load here.
//
#define KDUPROV_FLAGS_IGNORE_CHECKSUM       0x00000004

//
// Do not set System/Admin-only security descriptor to the provider driver device.
//
#define KDUPROV_FLAGS_NO_FORCED_SD          0x00000008

//
// Do not unload, driver does not support this.
//
#define KDUPROV_FLAGS_NO_UNLOAD_SUP         0x00000010

//
// Virtual-to-physical addresses translation require low stub for PML4 query.
//
#define KDUPROV_FLAGS_PML4_FROM_LOWSTUB     0x00000020

//
// Does not need victim
//
#define KDUPROV_FLAGS_NO_VICTIM             0x00000040

//
// Provider supports only memory brute-force.
//
#define KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE  0x00000080

//
// When provider support both virtual/physical memory acccess.
//
#define KDUPROV_FLAGS_PREFER_PHYSICAL       0x00000100
#define KDUPROV_FLAGS_PREFER_VIRTUAL        0x00000200

//
// KDU shellcode support flags
//
#define KDUPROV_SC_NONE (0x000)
#define KDUPROV_SC_V1   (0x001)
#define KDUPROV_SC_V2   (0x002)
#define KDUPROV_SC_V3   (0x004)

#define KDUPROV_SC_ALL_DEFAULT (KDUPROV_SC_V1 | KDUPROV_SC_V2 | KDUPROV_SC_V3)

#define KDUPROV_SC_V4   (0x008)
