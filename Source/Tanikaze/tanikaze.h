/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       CONSTS.H
*
*  VERSION:     1.19
*
*  DATE:        09 Dec 2023
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
        (LPWSTR)L"NalDrv",
        (LPWSTR)L"Nal",
        (LPWSTR)L"Intel Corporation"
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
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"MICRO-STAR INTERNATIONAL CO., LTD."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GDRV,
        KDU_PROVIDER_GIGABYTE_GDRV,
        KDU_VICTIM_DEFAULT,
        SourceBaseMapMem,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2018-19320",
        (LPWSTR)L"Gdrv",
        (LPWSTR)L"GIO",
        (LPWSTR)L"Giga-Byte Technology"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ATSZIO64,
        KDU_PROVIDER_ASUSTEK_ATSZIO,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASUSTeK WinFlash",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ASUSTeK Computer Inc."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MSIO64,
        KDU_PROVIDER_PATRIOT_MSIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-18845",
        (LPWSTR)L"MsIo64",
        (LPWSTR)L"MsIo",
        (LPWSTR)L"MICSYS Technology Co., Ltd."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GLCKIO2,
        KDU_PROVIDER_GLCKIO2,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASRock Polychrome RGB, multiple CVE ids",
        (LPWSTR)L"GLCKIo2",
        (LPWSTR)L"GLCKIo2",
        (LPWSTR)L"ASUSTeK Computer Inc."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENEIO64,
        KDU_PROVIDER_ENEIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"G.SKILL Trident Z Lighting Control",
        (LPWSTR)L"EneIo64",
        (LPWSTR)L"EneIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_WINRING0,
        KDU_PROVIDER_WINRING0,
        KDU_VICTIM_PE1627,
        SourceBaseWinRing0,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"EVGA Precision X1",
        (LPWSTR)L"WinRing0x64",
        (LPWSTR)L"WinRing0_1_2_0",
        (LPWSTR)L"EVGA"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64,
        KDU_PROVIDER_ENETECHIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Thermaltake TOUGHRAM Software",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PHYMEMX64,
        KDU_PROVIDER_PHYMEM64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Huawei MateBook Manager",
        (LPWSTR)L"phymemx64",
        (LPWSTR)L"PhyMem",
        (LPWSTR)L"Huawei Technologies Co.,Ltd."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_RTKIO64,
        KDU_PROVIDER_RTKIO64,
        KDU_VICTIM_DEFAULT,
        SourceBasePhyMem,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Realtek Dash Client Utility",
        (LPWSTR)L"rtkio64",
        (LPWSTR)L"rtkio",
        (LPWSTR)L"Realtek Semiconductor Corp."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64B,
        KDU_PROVIDER_ENETECHIO64B,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"MSI Dragon Center",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_LHA,
        KDU_PROVIDER_LHA,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-8372",
        (LPWSTR)L"lha",
        (LPWSTR)L"{E8F2FF20-6AF7-4914-9398-CE2132FE170F}",
        (LPWSTR)L"LG Electronics Inc."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASUSIO2,
        KDU_PROVIDER_ASUSIO2,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASUS GPU Tweak",
        (LPWSTR)L"AsIO2",
        (LPWSTR)L"Asusgio2",
        (LPWSTR)L"ASUSTeK Computer Inc."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DIRECTIO64,
        KDU_PROVIDER_DIRECTIO64,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"PassMark DirectIO",
        (LPWSTR)L"DirectIo64",
        (LPWSTR)L"DIRECTIO64",
        (LPWSTR)L"PassMark Software Pty Ltd"
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
        (LPWSTR)L"Gmer 'Antirootkit'",
        (LPWSTR)L"gmerdrv",
        (LPWSTR)L"gmerdrv",
        (LPWSTR)L"GMEREK Systemy Komputerowe Przemyslaw Gmerek"
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
        (LPWSTR)L"DBUtil23",
        (LPWSTR)L"DBUtil_2_3",
        (LPWSTR)L"Dell Inc."
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
        (LPWSTR)L"Mimikatz mimidrv",
        (LPWSTR)L"mimidrv",
        (LPWSTR)L"mimidrv",
        (LPWSTR)L"Benjamin Delpy"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_21H2,
        IDR_KPH,
        KDU_PROVIDER_KPH,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_PML4_FROM_LOWSTUB | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"KProcessHacker",
        (LPWSTR)L"KProcessHacker",
        (LPWSTR)L"KProcessHacker2",
        (LPWSTR)L"Wen Jia Liu"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_21H2,
        IDR_PROCEXP1627,
        KDU_PROVIDER_PROCEXP,
        KDU_VICTIM_PE1627,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_PML4_FROM_LOWSTUB | KDUPROV_FLAGS_NO_VICTIM | KDUPROV_FLAGS_OPENPROCESS_SUPPORTED,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)PROCEXP1627_DESC,
        (LPWSTR)PROCEXP152,
        (LPWSTR)PROCEXP152,
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
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
        (LPWSTR)L"DBUtilDrv2",
        (LPWSTR)L"DBUtil_2_5",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
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
        (LPWSTR)L"Cheat Engine Dbk64",
        (LPWSTR)L"CEDRIVER73",
        (LPWSTR)L"CEDRIVER73",
        (LPWSTR)L"Cheat Engine"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASUSIO3,
        KDU_PROVIDER_ASUSIO3,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASUS GPU Tweak II",
        (LPWSTR)L"AsIO3",
        (LPWSTR)L"Asusgio3",
        (LPWSTR)L"ASUSTeK Computer Inc."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_HW64,
        KDU_PROVIDER_HW64,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Marvin Hardware Access Driver for Windows",
        (LPWSTR)L"hw64",
        (LPWSTR)L"hw",
        (LPWSTR)L"Marvin Test Solutions, Inc."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_SYSDRV3S,
        KDU_PROVIDER_SYSDRV3S,
        KDU_VICTIM_DEFAULT,
        SourceBaseMapMem,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB | KDUPROV_FLAGS_NO_UNLOAD_SUP,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CODESYS SysDrv3S (CVE-2022-22516)",
        (LPWSTR)L"SysDrv3S",
        (LPWSTR)L"SysDrv3S",
        (LPWSTR)L"3S-Smart Software Solutions GmbH."
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
        (LPWSTR)L"Zemana (CVE-2021-31728, CVE-2022-42045)",
        (LPWSTR)L"ZemanaAntimalware",
        (LPWSTR)L"amsdk",
        (LPWSTR)L"WATCHDOGDEVELOPMENT.COM, LLC"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_INPOUTX64,
        KDU_PROVIDER_INPOUTX64,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"inpoutx64 Driver Version 1.2",
        (LPWSTR)L"inpoutx64",
        (LPWSTR)L"inpoutx64",
        (LPWSTR)L"Red Fox UK Limited"
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PASSMARK_OSF,
        KDU_PROVIDER_PASSMARK_OSF,
        KDU_VICTIM_DEFAULT,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"PassMark OSForensics DirectIO",
        (LPWSTR)L"DirectIo64",
        (LPWSTR)L"DIRECTIO64",
        (LPWSTR)L"PassMark Software Pty Ltd"
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
        (LPWSTR)L"ASRock IO Driver",
        (LPWSTR)L"AsrDrv106",
        (LPWSTR)L"AsrDrv106",
        (LPWSTR)L"ASROCK Incorporation"
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
        (LPWSTR)L"Core Temp",
        (LPWSTR)L"ALSysIO64",
        (LPWSTR)L"ALSysIO",
        (LPWSTR)L"ALCPU (Arthur Liberman)"
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
        (LPWSTR)L"AMD Ryzen Master Service Driver",
        (LPWSTR)L"AMDRyzenMasterDriver",
        (LPWSTR)L"AMDRyzenMasterDriverV20",
        (LPWSTR)L"Advanced Micro Devices Inc."
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
        (LPWSTR)L"Physical Memory Access Driver",
        (LPWSTR)L"physmem",
        (LPWSTR)L"PHYSMEMVIEWER",
        (LPWSTR)L"Hilscher Gesellschaft fuer Systemautomation mbH"
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
        (LPWSTR)L"Lenovo Diagnostics Driver for Windows 10 and later (CVE-2022-3699)",
        (LPWSTR)L"LenovoDiagnosticsDriver",
        (LPWSTR)L"LenovoDiagnosticsDriver",
        (LPWSTR)L"Lenovo"
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
        (LPWSTR)L"PC-Doctor (CVE-2019-12280)",
        (LPWSTR)L"pcdsrvc_x64",
        (LPWSTR)L"pcdsrvc_x64",
        (LPWSTR)L"PC-Doctor, Inc."
     },

     {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MSI_WINIO,
        KDU_PROVIDER_MSI_WINIO,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"MSI Foundation Service",
        (LPWSTR)L"WinIo",
        (LPWSTR)L"WinIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
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
        (LPWSTR)L"ETDi Support Driver",
        (LPWSTR)L"EtdSupport",
        (LPWSTR)L"EtdSupport_18.0",
        (LPWSTR)L"HP Inc."
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
        (LPWSTR)L"Kernel Explorer Driver",
        (LPWSTR)L"KExplore",
        (LPWSTR)L"KExplore",
        (LPWSTR)L"Pavel Yosifovich"
     },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_22H2,
        IDR_KOBJEXP,
        KDU_PROVIDER_KOBJEXP,
        KDU_VICTIM_PE1702,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_PML4_FROM_LOWSTUB | KDUPROV_FLAGS_PREFER_PHYSICAL,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Kernel Object Explorer Driver",
        (LPWSTR)L"KObjExp",
        (LPWSTR)L"KObjExp",
        (LPWSTR)L"Pavel Yosifovich"
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_22H2,
        IDR_KREGEXP,
        KDU_PROVIDER_KREGEXP,
        KDU_VICTIM_PE1702,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_PML4_FROM_LOWSTUB | KDUPROV_FLAGS_PREFER_PHYSICAL,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Kernel Registry Explorer Driver",
        (LPWSTR)L"KRegExp",
        (LPWSTR)L"KRegExp",
        (LPWSTR)L"Pavel Yosifovich"
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
        (LPWSTR)L"Echo AntiCheat",
        (LPWSTR)L"EchoDrv",
        (LPWSTR)L"EchoDrv",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
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
        (LPWSTR)L"NVidia System Utility Driver",
        (LPWSTR)L"nvoclock",
        (LPWSTR)L"NVR0Internal",
        (LPWSTR)L"NVIDIA Corporation"
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
        (LPWSTR)L"Binalyze CVE-2023-41444",
        (LPWSTR)L"IREC",
        (LPWSTR)L"IREC",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher"
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
        (LPWSTR)L"SLIC ToolKit",
        (LPWSTR)L"PhyDMACC",
        (LPWSTR)L"PhyDMACC_1_2_0",
        (LPWSTR)L"Suzhou Ind. Park ShiSuanKeJi Co., Ltd."
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
        (LPWSTR)L"Razer Overlay Support driver CVE-2017-9769",
        (LPWSTR)L"rzpnk",
        (LPWSTR)L"47CD78C9-64C3-47C2-B80F-677B887CF095",
        (LPWSTR)L"Razer USA Ltd."
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
        (LPWSTR)L"AMD USB-C Power Delivery Firmware Update Utility CVE-2023-20598",
        (LPWSTR)L"PdFwKrnl",
        (LPWSTR)L"PdFwKrnl",
        (LPWSTR)L"Advanced Micro Devices Inc."
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
        (LPWSTR)L"AMD OverDrive Driver (same as CVE-2020-12928)",
        (LPWSTR)L"AODDriver",
        (LPWSTR)L"AODDriver",
        (LPWSTR)L"Advanced Micro Devices Inc."
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_WNBIOS64,
        KDU_PROVIDER_WINCOR,
        KDU_VICTIM_DEFAULT,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"WnBios Driver",
        (LPWSTR)L"wnBios64",
        (LPWSTR)L"WNBIOS",
        (LPWSTR)L"Wincor Nixdorf International GmbH"
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
        (LPWSTR)L"EVGA Low Level Driver",
        (LPWSTR)L"EleetX1",
        (LPWSTR)L"EleetX1",
        (LPWSTR)L"EVGA Corp."
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
        (LPWSTR)L"RW-Everything Read & Write Driver",
        (LPWSTR)L"AxtuDrv",
        (LPWSTR)L"AxtuDrv",
        (LPWSTR)L"ASROCK Incorporation"
     }

};

#if defined(__cplusplus)
extern "C" {
#endif

    KDU_DB gProvTable = {
        RTL_NUMBER_OF(gProvEntry),
        gProvEntry
    };

#ifdef __cplusplus
}
#endif