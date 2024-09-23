/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2024
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.42
*
*  DATE:        23 Sep 2024
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
#define KDU_VERSION_MINOR       4
#define KDU_VERSION_REVISION    2
#define KDU_VERSION_BUILD       2409
#define KDU_COPYRIGHT_YEAR      2024

#define KDU_MIN_NTBUILDNUMBER   0x1DB1      //Windows 7 SP1
#define KDU_MAX_NTBUILDNUMBER   0xFFFFFFFF  //Undefined

#define IPC_GET_HANDLE          0x1337

#define KDU_SYNC_MUTANT         0x2409

#define NT_REG_PREP             L"\\Registry\\Machine"
#define DRIVER_REGKEY           L"%wS\\System\\CurrentControlSet\\Services\\%wS"
#define WDAC_POLICY_FILE        L"\\systemroot\\system32\\CodeIntegrity\\driversipolicy.p7b"

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

#define ZODIACON_SYSEXP_EXE     L"SysExp.exe"
#define ZODIACON_REGEXP_EXE     L"RegExp.exe"

#define CPU_VENDOR_INTEL        "GenuineIntel"
#define CPU_VENDOR_INTEL_LENGTH sizeof(CPU_VENDOR_INTEL) - sizeof(CHAR)
#define CPU_VENDOR_AMD          "AuthenticAMD"
#define CPU_VENDOR_AMD_LENGTH   sizeof(CPU_VENDOR_AMD) - sizeof(CHAR)

#define SHELL_POOL_TAG          '  oI'

#define PROVIDER_RES_KEY        0xF62E6CE0

#define SYSTEM_PID_MAGIC        4

#define TEXT_SECTION            ".text"
#define TEXT_SECTION_LEGNTH     sizeof(TEXT_SECTION)

#define SHELLCODE_SMALL         0x200

#ifndef MAX_CLASS_NAME_LEN
#define MAX_CLASS_NAME_LEN      256
#endif

//
// Victim providers id table
//
#define KDU_VICTIM_PE1627  0
#define KDU_VICTIM_PE1702  1
#define KDU_VICTIM_MAX     2
#define KDU_VICTIM_DEFAULT KDU_VICTIM_PE1702

//
// Companion id table
//
#define KDU_COMPANION_UNDEFINED_PLACEHOLDER 0
#define KDU_COMPANION_DEFAULT KDU_COMPANION_UNDEFINED_PLACEHOLDER 

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
#define IDR_RZPNK                       104
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
#define IDR_LDD                         135
#define IDR_PCDSRVC                     136
#define IDR_MSI_WINIO                   137
#define IDR_HP_ETDSUPP                  138
#define IDR_KEXPLORE                    139
#define IDR_KOBJEXP                     140
#define IDR_KREGEXP                     141
#define IDR_PHYDMACC                    142
#define IDR_ECHODRV                     143
#define IDR_NVOCLOCK                    144
#define IDR_IREC                        145
#define IDR_AMD_PDFWKRNL                146
#define IDR_AMD_AOD215                  147
#define IDR_WNBIOS64                    148
#define IDR_EVGA_ELEETX1                149
#define IDR_ASROCKDRV2                  150
#define IDR_ASROCKAPPSHOP103            151
#define IDR_ASROCKDRV3                  152
#define IDR_ASROCKDRV4                  153
#define IDR_PMXDRV64                    154

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
#define KDU_PROVIDER_LENOVO_DD          32
#define KDU_PROVIDER_DELL_PCDOC         33
#define KDU_PROVIDER_MSI_WINIO          34
#define KDU_PROVIDER_HP_ETDSUPPORT      35
#define KDU_PROVIDER_KEXPLORE           36
#define KDU_PROVIDER_KOBJEXP            37
#define KDU_PROVIDER_KREGEXP            38
#define KDU_PROVIDER_ECHODRV            39
#define KDU_PROVIDER_NVOCLOCK           40
#define KDU_PROVIDER_BINALYZE_IREC      41
#define KDU_PROVIDER_PHYDMACC           42
#define KDU_PROVIDER_RAZER              43
#define KDU_PROVIDER_AMD_PDFWKRNL       44
#define KDU_PROVIDER_AMD_AOD215         45
#define KDU_PROVIDER_WINCOR             46
#define KDU_PROVIDER_EVGA_ELEETX1       47
#define KDU_PROVIDER_ASROCK2            48
#define KDU_PROVIDER_ASROCK3            49
#define KDU_PROVIDER_ASROCK4            50
#define KDU_PROVIDER_ASROCK5            51
#define KDU_PROVIDER_INTEL_PMXDRV       52

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
// Reserved for future use.
//
#define KDUPROV_FLAGS_COMPANION_REQUIRED    0x00000400

//
// Process with MSFT symbols.
//
#define KDUPROV_FLAGS_USE_SYMBOLS           0x00000800

//
// Provider can be used to open a handle for the specified process.
//
#define KDUPROV_FLAGS_OPENPROCESS_SUPPORTED 0x00001000

//
// KDU shellcode support flags
//
#define KDUPROV_SC_NONE (0x000)
#define KDUPROV_SC_V1   (0x001)
#define KDUPROV_SC_V2   (0x002)
#define KDUPROV_SC_V3   (0x004)

#define KDUPROV_SC_ALL_DEFAULT (KDUPROV_SC_V1 | KDUPROV_SC_V2 | KDUPROV_SC_V3)

#define KDUPROV_SC_V4   (0x008)
