/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       KDUPLIST.H
*
*  VERSION:     1.11
*
*  DATE:        18 Apr 2021
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
        (LPWSTR)L"CVE-2015-2291",
        (LPWSTR)L"NalDrv",
        (LPWSTR)L"Nal",
        (LPWSTR)L"Intel Corporation",

        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)NalReadVirtualMemoryEx,
        (provWriteKernelVM)NalWriteVirtualMemoryEx,
        (provVirtualToPhysical)NalVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)KDUProviderStub,
        (provReadPhysicalMemory)KDUProviderStub,
        (provWritePhysicalMemory)KDUProviderStub
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_RTCORE64,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        (LPWSTR)L"CVE-2019-16098",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"MICRO-STAR INTERNATIONAL CO., LTD.",

        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)RTCoreReadVirtualMemory,
        (provWriteKernelVM)RTCoreWriteVirtualMemory,
        (provVirtualToPhysical)KDUProviderStub,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)KDUProviderStub,
        (provReadPhysicalMemory)KDUProviderStub,
        (provWritePhysicalMemory)KDUProviderStub
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GDRV,
        SourceBaseMapMem,
        KDUPROV_FLAGS_NONE,
        (LPWSTR)L"CVE-2018-19320",
        (LPWSTR)L"Gdrv",
        (LPWSTR)L"GIO",
        (LPWSTR)L"Giga-Byte Technology",

        (provRegisterDriver)MapMemRegisterDriver,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)GioReadKernelVirtualMemory,
        (provWriteKernelVM)GioWriteKernelVirtualMemory,
        (provVirtualToPhysical)GioVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)GioQueryPML4Value,
        (provReadPhysicalMemory)GioReadPhysicalMemory,
        (provWritePhysicalMemory)GioWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ATSZIO64,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        (LPWSTR)L"ASUSTeK WinFlash",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ASUSTeK Computer Inc.",

        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)AtszioReadKernelVirtualMemory,
        (provWriteKernelVM)AtszioWriteKernelVirtualMemory,
        (provVirtualToPhysical)AtszioVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)AtszioQueryPML4Value,
        (provReadPhysicalMemory)AtszioReadPhysicalMemory,
        (provWritePhysicalMemory)AtszioWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_MSIO64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"CVE-2019-18845",
        (LPWSTR)L"MsIo64",
        (LPWSTR)L"MsIo",
        (LPWSTR)L"MICSYS Technology Co., Ltd.",

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,
        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_GLCKIO2,
        SourceBaseWinIo,
        KDUPROV_FLAGS_NONE,
        (LPWSTR)L"ASRock Polychrome RGB, multiple CVE ids",
        (LPWSTR)L"GLCKIo2",
        (LPWSTR)L"GLCKIo2",
        (LPWSTR)L"ASUSTeK Computer Inc.",

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,
        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENEIO64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"G.SKILL Trident Z Lighting Control",
        (LPWSTR)L"EneIo64",
        (LPWSTR)L"EneIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,
        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_WINRING0,
        SourceBaseWinRing0,
        KDUPROV_FLAGS_NONE,
        (LPWSTR)L"EVGA Precision X1",
        (LPWSTR)L"WinRing0x64",
        (LPWSTR)L"WinRing0_1_2_0",
        (LPWSTR)L"EVGA",

        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WRZeroReadKernelVirtualMemory,
        (provWriteKernelVM)WRZeroKernelVirtualMemory,
        (provVirtualToPhysical)WRZeroVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WRZeroQueryPML4Value,
        (provReadPhysicalMemory)WRZeroReadPhysicalMemory,
        (provWritePhysicalMemory)WRZeroWritePhysicalMemory,
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"Thermaltake TOUGHRAM Software",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,
        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_PHYMEMX64,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"Huawei MateBook Manager",
        (LPWSTR)L"phymemx64",
        (LPWSTR)L"PhyMem",
        (LPWSTR)L"Huawei Technologies Co.,Ltd.",

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,
        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_RTKIO64,
        SourceBasePhyMem,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"Realtek Dash Client Utility",
        (LPWSTR)L"rtkio64",
        (LPWSTR)L"rtkio",
        (LPWSTR)L"Realtek Semiconductor Corp.",

        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)PhyMemReadKernelVirtualMemory,
        (provWriteKernelVM)PhyMemWriteKernelVirtualMemory,
        (provVirtualToPhysical)PhyMemVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)PhyMemQueryPML4Value,
        (provReadPhysicalMemory)PhyMemReadPhysicalMemory,
        (provWritePhysicalMemory)PhyMemWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ENETECHIO64B,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"MSI Dragon Center",
        (LPWSTR)L"EneTechIo64",
        (LPWSTR)L"EneTechIo",
        (LPWSTR)L"Microsoft Windows Hardware Compatibility Publisher",

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)WinIoUnregisterDriver,
        (provPreOpenDriver)WinIoPreOpen,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,
        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        NT_WIN10_REDSTONE3,
        IDR_LHA,
        SourceBaseNone,
        KDUPROV_FLAGS_NONE,
        (LPWSTR)L"CVE-2019-8372",
        (LPWSTR)L"lha",
        (LPWSTR)L"{E8F2FF20-6AF7-4914-9398-CE2132FE170F}",
        (LPWSTR)L"LG Electronics Inc.",

        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)LHAReadKernelVirtualMemory,
        (provWriteKernelVM)LHAWriteKernelVirtualMemory,
        (provVirtualToPhysical)LHAVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)LHAQueryPML4Value,
        (provReadPhysicalMemory)LHAReadPhysicalMemory,
        (provWritePhysicalMemory)LHAWritePhysicalMemory,
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_ASUSIO2,
        SourceBaseWinIo,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"ASUS GPU Tweak",
        (LPWSTR)L"AsIO2",
        (LPWSTR)L"Asusgio2",
        (LPWSTR)L"ASUSTeK Computer Inc.",

        (provRegisterDriver)WinIoRegisterDriver,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)WinIoReadKernelVirtualMemory,
        (provWriteKernelVM)WinIoWriteKernelVirtualMemory,
        (provVirtualToPhysical)WinIoVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory
    },

    {
        KDU_MIN_NTBUILDNUMBER,
        KDU_MAX_NTBUILDNUMBER,
        IDR_DIRECTIO64,
        SourceBaseNone,
        KDUPROV_FLAGS_SIGNATURE_WHQL,
        (LPWSTR)L"PassMark DirectIO",
        (LPWSTR)L"DirectIo64",
        (LPWSTR)L"DIRECTIO64",
        (LPWSTR)L"PassMark Software Pty Ltd",

        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provPreOpenDriver)KDUProviderStub,
        (provPostOpenDriver)KDUProviderPostOpen,

        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        (provReadKernelVM)DI64ReadKernelVirtualMemory,
        (provWriteKernelVM)DI64WriteKernelVirtualMemory,
        (provVirtualToPhysical)DI64VirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)DI64QueryPML4Value,
        (provReadPhysicalMemory)DI64ReadPhysicalMemory,
        (provWritePhysicalMemory)DI64WritePhysicalMemory
    }
};
