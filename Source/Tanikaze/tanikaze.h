/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       TANIKAZE.H
*
*  VERSION:     1.50
*
*  DATE:        19 Jul 2026
*
*  Tanikaze helper dll (part of KDU project).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include <Windows.h>
#include "Shared/consts.h"
#include "Shared/ntos/ntbuilds.h"
#include "Shared/kdubase.h"
#include "resource.h"

#pragma once

KDU_DB_ENTRY gProvEntry[] = {
   {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_INTEL_NAL,
        KDU_PROVIDER_INTEL_NAL,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PREFER_PHYSICAL,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2015-2291",
        (LPWSTR)L"Intel NAL driver",
        (LPWSTR)L"NalDrv",
        (LPWSTR)L"Nal"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_RTCORE64,
        KDU_PROVIDER_UNWINDER_RTCORE,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-16098",
        (LPWSTR)L"MSI RTCore64 driver",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"RTCore64"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GDRV,
        KDU_PROVIDER_GIGABYTE_GDRV,
        KDU_VICTIM_DEFAULT,
        SourceBaseMapMem,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2018-19320",
        (LPWSTR)L"Gigabyte GDRV driver",
        (LPWSTR)L"Gdrv",
        (LPWSTR)L"GIO"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ATSZIO64,
        KDU_PROVIDER_ASUSTEK_ATSZIO,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ASUSTeK WinFlash",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ATSZIO"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MSIO64,
        KDU_PROVIDER_PATRIOT_MSIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-18845",
        (LPWSTR)L"MICSYS RGB driver",
        (LPWSTR)L"MsIo64",
        (LPWSTR)L"MsIo"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GLCKIO2,
        KDU_PROVIDER_GLCKIO2,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ASRock Polychrome RGB",
        (LPWSTR)L"GLCKIo2",
        (LPWSTR)L"GLCKIo2"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENEIO64,
        KDU_PROVIDER_ENEIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"G.SKILL Trident Z Lighting Control",
        (LPWSTR)L"EneIo64",
        (LPWSTR)L"EneIo"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_WINRING0,
        KDU_PROVIDER_WINRING0,
        KDU_VICTIM_PE1627,
        SourceBaseWinRing0,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"EVGA Precision X1",
        (LPWSTR)L"WinRing0x64",
        (LPWSTR)L"WinRing0_1_2_0"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64,
        KDU_PROVIDER_ENETECHIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Thermaltake TOUGHRAM Software",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PHYMEMX64,
        KDU_PROVIDER_PHYMEM64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Huawei MateBook Manager",
        (LPWSTR)L"phymemx64",
        (LPWSTR)L"PhyMem"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_RTKIO64,
        KDU_PROVIDER_RTKIO64,
        KDU_VICTIM_DEFAULT,
        SourceBasePhyMem,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Realtek Dash Client Utility",
        (LPWSTR)L"rtkio64",
        (LPWSTR)L"rtkio"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64B,
        KDU_PROVIDER_ENETECHIO64B,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"MSI Dragon Center",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_LHA,
        KDU_PROVIDER_LHA,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-8372",
        (LPWSTR)L"LG LHA driver",
        (LPWSTR)L"lha",
        (LPWSTR)L"{E8F2FF20-6AF7-4914-9398-CE2132FE170F}"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASUSIO2,
        KDU_PROVIDER_ASUSIO2,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ASUS GPU Tweak",
        (LPWSTR)L"AsIO2",
        (LPWSTR)L"Asusgio2"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DIRECTIO64,
        KDU_PROVIDER_DIRECTIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"PassMark DirectIO",
        (LPWSTR)L"DirectIo64",
        (LPWSTR)L"DIRECTIO64"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GMERDRV,
        KDU_PROVIDER_GMER,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Gmer 'Antirootkit'",
        (LPWSTR)L"gmerdrv",
        (LPWSTR)L"gmerdrv"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DBUTIL23,
        KDU_PROVIDER_DBUTIL23,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_UNLOAD_SUP,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2021-21551",
        (LPWSTR)L"Dell DBUtil 2.3 driver",
        (LPWSTR)L"DBUtil23",
        (LPWSTR)L"DBUtil_2_3"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MIMIDRV,
        KDU_PROVIDER_MIMIDRV,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Mimikatz mimidrv",
        (LPWSTR)L"mimidrv",
        (LPWSTR)L"mimidrv"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_21H2,
        IDR_KPH,
        KDU_PROVIDER_KPH,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAG_ROOT_FROM_LOWSTUB | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"KProcessHacker driver",
        (LPWSTR)L"KProcessHacker",
        (LPWSTR)L"KProcessHacker2"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_21H2,
        IDR_PROCEXP1627,
        KDU_PROVIDER_PROCEXP,
        KDU_VICTIM_PE1627,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAG_ROOT_FROM_LOWSTUB | KDUPROV_FLAGS_NO_VICTIM | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)PROCEXP1627_DESC,
        (LPWSTR)PROCEXP152,
        (LPWSTR)PROCEXP152
    },

    {
        NT_WIN10_THRESHOLD1,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DBUTILDRV2,
        KDU_PROVIDER_DBUTILDRV2,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2021-36276",
        (LPWSTR)L"Dell DBUtil 2.5 driver",
        (LPWSTR)L"DBUtilDrv2",
        (LPWSTR)L"DBUtil_2_5"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DBK64,
        KDU_PROVIDER_DBK64,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_NO_VICTIM | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_V4,
        NULL,
        (LPWSTR)L"Cheat Engine Dbk64",
        (LPWSTR)L"CEDRIVER73",
        (LPWSTR)L"CEDRIVER73"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASUSIO3,
        KDU_PROVIDER_ASUSIO3,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ASUS GPU Tweak II",
        (LPWSTR)L"AsIO3",
        (LPWSTR)L"Asusgio3"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_HW64,
        KDU_PROVIDER_HW64,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Marvin Hardware Access Driver for Windows",
        (LPWSTR)L"hw64",
        (LPWSTR)L"hw"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_SYSDRV3S,
        KDU_PROVIDER_SYSDRV3S,
        KDU_VICTIM_DEFAULT,
        SourceBaseMapMem,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB | KDUPROV_FLAGS_NO_UNLOAD_SUP,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2022-22516",
        (LPWSTR)L"CODESYS SysDrv3S driver",
        (LPWSTR)L"SysDrv3S",
        (LPWSTR)L"SysDrv3S"
    },

    {
        NT_WIN8_BLUE,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ZEMANA,
        KDU_PROVIDER_ZEMANA,
        KDU_VICTIM_PE1702,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_V4,
        (LPWSTR)L"CVE-2021-31728, CVE-2022-42045",
        (LPWSTR)L"Zemana AntiMalware driver",
        (LPWSTR)L"ZemanaAntimalware",
        (LPWSTR)L"amsdk"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_INPOUTX64,
        KDU_PROVIDER_INPOUTX64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"inpoutx64 Driver Version 1.2",
        (LPWSTR)L"inpoutx64",
        (LPWSTR)L"inpoutx64"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PASSMARK_OSF,
        KDU_PROVIDER_PASSMARK_OSF,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"PassMark OSForensics DirectIO",
        (LPWSTR)L"DirectIo64",
        (LPWSTR)L"DIRECTIO64"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASROCKDRV,
        KDU_PROVIDER_ASROCK,
        KDU_VICTIM_DEFAULT,
        SourceBaseRWEverything,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ASRock IO Driver",
        (LPWSTR)L"AsrDrv106",
        (LPWSTR)L"AsrDrv106"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ALSYSIO64,
        KDU_PROVIDER_ALCPU,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Core Temp",
        (LPWSTR)L"ALSysIO64",
        (LPWSTR)L"ALSysIO"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_AMD_RYZENMASTER,
        KDU_PROVIDER_AMD_RYZENMASTER,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"AMD Ryzen Master Service Driver",
        (LPWSTR)L"AMDRyzenMasterDriver",
        (LPWSTR)L"AMDRyzenMasterDriverV20"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PHYSMEM,
        KDU_PROVIDER_HR_PHYSMEM,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Physical Memory Access Driver",
        (LPWSTR)L"physmem",
        (LPWSTR)L"PHYSMEMVIEWER"
     },

     {
        NT_WIN10_REDSTONE4,
        KDU_MAX_NTBUILDNUMBER,
        IDR_LDD,
        KDU_PROVIDER_LENOVO_DD,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAGS_USE_SYMBOLS,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2022-3699",
        (LPWSTR)L"Lenovo Diagnostics Driver for Windows 10 and later",
        (LPWSTR)L"LenovoDiagnosticsDriver",
        (LPWSTR)L"LenovoDiagnosticsDriver"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PCDSRVC,
        KDU_PROVIDER_DELL_PCDOC,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-12280",
        (LPWSTR)L"PC-Doctor driver",
        (LPWSTR)L"pcdsrvc_x64",
        (LPWSTR)L"pcdsrvc_x64"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MSI_WINIO,
        KDU_PROVIDER_MSI_WINIO,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"MSI Foundation Service",
        (LPWSTR)L"WinIo",
        (LPWSTR)L"WinIo"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_HP_ETDSUPP,
        KDU_PROVIDER_HP_ETDSUPPORT,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_VIRTUAL,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ETDi Support Driver",
        (LPWSTR)L"EtdSupport",
        (LPWSTR)L"EtdSupport_18.0"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_KEXPLORE,
        KDU_PROVIDER_KEXPLORE,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PREFER_VIRTUAL,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Kernel Explorer Driver",
        (LPWSTR)L"KExplore",
        (LPWSTR)L"KExplore"
     },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_22H2,
        IDR_KOBJEXP,
        KDU_PROVIDER_KOBJEXP,
        KDU_VICTIM_PE1702,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAG_ROOT_FROM_LOWSTUB | KDUPROV_FLAGS_PREFER_PHYSICAL,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Kernel Object Explorer Driver",
        (LPWSTR)L"KObjExp",
        (LPWSTR)L"KObjExp"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_22H2,
        IDR_KREGEXP,
        KDU_PROVIDER_KREGEXP,
        KDU_VICTIM_PE1702,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAG_ROOT_FROM_LOWSTUB | KDUPROV_FLAGS_PREFER_PHYSICAL,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Kernel Registry Explorer Driver",
        (LPWSTR)L"KRegExp",
        (LPWSTR)L"KRegExp"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ECHODRV,
        KDU_PROVIDER_ECHODRV,
        KDU_VICTIM_PE1702,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_VIRTUAL | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Echo AntiCheat",
        (LPWSTR)L"EchoDrv",
        (LPWSTR)L"EchoDrv"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_NVOCLOCK,
        KDU_PROVIDER_NVOCLOCK,
        KDU_VICTIM_PE1702,
        SourceBaseNone,
        KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"NVidia System Utility Driver",
        (LPWSTR)L"nvoclock",
        (LPWSTR)L"NVR0Internal"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_IREC,
        KDU_PROVIDER_BINALYZE_IREC,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_VICTIM | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_NONE,
        (LPWSTR)L"CVE-2023-41444",
        (LPWSTR)L"Binalyze driver",
        (LPWSTR)L"IREC",
        (LPWSTR)L"IREC"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PHYDMACC,
        KDU_PROVIDER_PHYDMACC,
        KDU_VICTIM_PE1702,
        SourceBaseWinRing0,
        KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"SLIC ToolKit",
        (LPWSTR)L"PhyDMACC",
        (LPWSTR)L"PhyDMACC_1_2_0"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_RZPNK,
        KDU_PROVIDER_RAZER,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_VICTIM | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_NONE,
        (LPWSTR)L"CVE-2017-9769",
        (LPWSTR)L"Razer Overlay Support driver",
        (LPWSTR)L"rzpnk",
        (LPWSTR)L"47CD78C9-64C3-47C2-B80F-677B887CF095"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_AMD_PDFWKRNL,
        KDU_PROVIDER_AMD_PDFWKRNL,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_VIRTUAL,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2023-20598",
        (LPWSTR)L"AMD USB-C Power Delivery Firmware Update Utility",
        (LPWSTR)L"PdFwKrnl",
        (LPWSTR)L"PdFwKrnl"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_AMD_AOD215,
        KDU_PROVIDER_AMD_AOD215,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2020-12928",
        (LPWSTR)L"AMD OverDrive Driver",
        (LPWSTR)L"AODDriver",
        (LPWSTR)L"AODDriver"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_WNBIOS64,
        KDU_PROVIDER_WINCOR,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"WnBios Driver",
        (LPWSTR)L"wnBios64",
        (LPWSTR)L"WNBIOS"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_EVGA_ELEETX1,
        KDU_PROVIDER_EVGA_ELEETX1,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"EVGA Low Level Driver",
        (LPWSTR)L"EleetX1",
        (LPWSTR)L"EleetX1"
    },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASROCKDRV2,
        KDU_PROVIDER_ASROCK2,
        KDU_VICTIM_DEFAULT,
        SourceBaseRWEverything,
        KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"RW-Everything Read & Write Driver",
        (LPWSTR)L"AxtuDrv",
        (LPWSTR)L"AxtuDrv"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASROCKAPPSHOP103,
        KDU_PROVIDER_ASROCK3,
        KDU_VICTIM_DEFAULT,
        SourceBaseRWEverything,
        KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"AppShopDrv103 Driver",
        (LPWSTR)L"AppShopDrv103",
        (LPWSTR)L"AppShopDrv103"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASROCKDRV3,
        KDU_PROVIDER_ASROCK4,
        KDU_VICTIM_DEFAULT,
        SourceBaseRWEverything,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ASRock IO Driver",
        (LPWSTR)L"AsrDrv107n",
        (LPWSTR)L"AsrDrv107n"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASROCKDRV4,
        KDU_PROVIDER_ASROCK5,
        KDU_VICTIM_DEFAULT,
        SourceBaseRWEverything,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"ASRock IO Driver",
        (LPWSTR)L"AsrDrv107",
        (LPWSTR)L"AsrDrv107"
     },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PMXDRV64,
        KDU_PROVIDER_INTEL_PMXDRV,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Intel(R) Management Engine Tools Driver",
        (LPWSTR)L"PMxDrv",
        (LPWSTR)L"Pmxdrv"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_HWRWDRVX64,
        KDU_PROVIDER_HWRWDRVX64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinRing0,
        KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Hardware read & write driver",
        (LPWSTR)L"HwRwDrv.x64",
        (LPWSTR)L"HwRwDrv"
    },

    {
        NT_WIN10_THRESHOLD1,
        KDU_MAX_NTBUILDNUMBER,
        IDR_NEACSAFE64,
        KDU_PROVIDER_NEACSAFE64,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_FS_FILTER,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2025-45737",
        (LPWSTR)L"NeacSafe64 mini-filter driver",
        (LPWSTR)L"NeacSafe64",
        (LPWSTR)L"OWNeacSafePort"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_THROTTLESTOP,
        KDU_PROVIDER_TPUP,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2025-7771",
        (LPWSTR)L"TechPowerUp ThrottleStop",
        (LPWSTR)L"ThrottleStop",
        (LPWSTR)L"ThrottleStop"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_TPWSAV,
        KDU_PROVIDER_TOSHIBA,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Toshiba power saving driver for laptops",
        (LPWSTR)L"TPwSav",
        (LPWSTR)L"EBIoDispatch"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_LENOVOMSRIO,
        KDU_PROVIDER_LENOVOMSRIO,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinRing0,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2025-8061",
        (LPWSTR)L"Lenovo MSR I/O Driver",
        (LPWSTR)L"LnvMSRIO",
        (LPWSTR)L"WinMsrDev"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_TELEDYNE,
        KDU_PROVIDER_TELEDYNE,
        KDU_VICTIM_DEFAULT,
        SourceBaseMapMem,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Sapera Memory Manager",
        (LPWSTR)L"CORMEM",
        (LPWSTR)L"CORMEM"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_IPCTYPE,
        KDU_PROVIDER_IPCTYPE,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"IPCType Device Driver for 64bit",
        (LPWSTR)L"IPCType",
        (LPWSTR)L"IPCType"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_SHANGKE_WND,
        KDU_PROVIDER_SHANGKE_WHD,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinRing0,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Guangzhou Shangke Information Technology giveio driver",
        (LPWSTR)L"WinHwDriver",
        (LPWSTR)L"WinHwDriver"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_AMD_AFFDRIVER,
        KDU_PROVIDER_AMD_AFFDRIVER,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"AMD BIOS Flash Utility driver",
        (LPWSTR)L"affdriver",
        (LPWSTR)L"BiosToolCommonDriver"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MATROX_MTXC9CB,
        KDU_PROVIDER_MATROX_MTXC9CB,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"Matrox Graphics driver",
        (LPWSTR)L"mtxC9CB",
        (LPWSTR)L"MtxVxd"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_FLIR_PGRHOSTCONTROL,
        KDU_PROVIDER_FLIR_PGRHOSTCTRL,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAG_ROOT_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"PGRHostControl driver",
        (LPWSTR)L"PGRHostControl",
        (LPWSTR)L"PGRHostControl"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_LECOMA,
        KDU_PROVIDER_LECOMA,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PREFER_PHYSICAL | KDUPROV_FLAGS_USE_SUPERFETCH,
        KDUPROV_SC_ALL_DEFAULT,
        NULL,
        (LPWSTR)L"LECO(R) LECOMA Device Driver",
        (LPWSTR)L"LECOMAx",
        (LPWSTR)L"LECOMA64_2"
    }

};

#if defined(__cplusplus)
extern "C" {
#endif

    KDU_DB gProvTable = {
        RTL_NUMBER_OF(gProvEntry),
        gProvEntry
    };

    KDU_DB_VERSION gVersion = {
        KDU_VERSION_MAJOR,
        KDU_VERSION_MINOR,
        KDU_VERSION_REVISION,
        KDU_VERSION_BUILD
    };

#ifdef __cplusplus
}
#endif
