/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       KDUPLIST.H
*
*  VERSION:     1.50
*
*  DATE:        19 Jul 2026
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

#include "idrv/intel.h"
#include "idrv/rtcore.h"
#include "idrv/mapmem.h"
#include "idrv/atszio.h"
#include "idrv/winio.h"
#include "idrv/winring0.h"
#include "idrv/phymem.h"
#include "idrv/lha.h"
#include "idrv/directio64.h"
#include "idrv/gmer.h"
#include "idrv/dell.h"
#include "idrv/mimidrv.h"
#include "idrv/kph.h"
#include "idrv/procexp.h"
#include "idrv/dbk.h"
#include "idrv/marvinhw.h"
#include "idrv/zemana.h"
#include "idrv/asrdrv.h"
#include "idrv/alcpu.h"
#include "idrv/amd.h"
#include "idrv/hilscher.h"
#include "idrv/lenovo.h"
#include "idrv/hp.h"
#include "idrv/zodiacon.h"
#include "idrv/echodrv.h"
#include "idrv/nvidia.h"
#include "idrv/binalyze.h"
#include "idrv/rzpnk.h"
#include "idrv/evga.h"
#include "idrv/netease.h"
#include "idrv/tpup.h"
#include "idrv/tpw.h"
#include "idrv/ipcdec.h"
#include "idrv/matrox.h"
#include "idrv/leco.h"

//
// Victims public array.
//
static KDU_VICTIM_PROVIDER g_KDUVictims[] = {
    {
        (LPCWSTR)PROCEXP152,              // Device and driver name,
        (LPCWSTR)PROCEXP1627_DESC,        // Description
        IDR_PROCEXP1627,                  // Resource id in drivers database
        KDU_VICTIM_PE1627,                // Victim id
        SYNCHRONIZE |
        GENERIC_READ | GENERIC_WRITE,     // Desired access flags used for acquiring victim handle
        KDU_VICTIM_FLAGS_SUPPORT_RELOAD,  // Victim flags, target dependent
        VpCreateCallback,                 // Victim create callback
        VpReleaseCallback,                // Victim release callback
        VpExecuteCallback,                // Victim execute payload callback
        &g_ProcExpSig,                    // Victim dispatch bytes
        sizeof(g_ProcExpSig)              // Victim dispatch bytes size
    },

    {
        (LPCWSTR)PROCEXP152,              // Device and driver name,
        (LPCWSTR)PROCEXP1702_DESC,        // Description
        IDR_PROCEXP1702,                  // Resource id in drivers database
        KDU_VICTIM_PE1702,                // Victim id
        SYNCHRONIZE |
        GENERIC_READ | GENERIC_WRITE,     // Desired access flags used for acquiring victim handle
        KDU_VICTIM_FLAGS_SUPPORT_RELOAD,  // Victim flags, target dependent
        VpCreateCallback,                 // Victim create callback
        VpReleaseCallback,                // Victim release callback
        VpExecuteCallback,                // Victim execute payload callback
        &g_ProcExpSig,                    // Victim dispatch bytes
        sizeof(g_ProcExpSig)              // Victim dispatch bytes size
    }

};

//
// Providers public array, unsupported methods must be set to NULL.
//
static KDU_PROVIDER g_KDUProviders[] =
{
    {
        NULL,

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
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)MapMemRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)MapMemReadKernelVirtualMemory,
        (provWriteKernelVM)MapMemWriteKernelVirtualMemory,

        (provVirtualToPhysical)MapMemVirtualToPhysical,
        (provReadPhysicalMemory)MapMemReadPhysicalMemory,
        (provWritePhysicalMemory)MapMemWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)AtszioReadPhysicalMemory,
        (provWritePhysicalMemory)AtszioWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WRZeroReadPhysicalMemory,
        (provWritePhysicalMemory)WRZeroWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)PhyMemReadPhysicalMemory,
        (provWritePhysicalMemory)PhyMemWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)LHAReadPhysicalMemory,
        (provWritePhysicalMemory)LHAWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)DI64ReadPhysicalMemory,
        (provWritePhysicalMemory)DI64WritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)KphReadPhysicalMemory,
        (provWritePhysicalMemory)KphWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)KphOpenProcess
    },

    {
        NULL,

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
        (provReadPhysicalMemory)PexReadPhysicalMemory,
        (provWritePhysicalMemory)PexWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)PexOpenProcess
    },

    {
        NULL,

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
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)DbkOpenProcess
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)HwReadKernelVirtualMemory,
        (provWriteKernelVM)HwWriteKernelVirtualMemory,

        (provVirtualToPhysical)HwVirtualToPhysical,
        (provReadPhysicalMemory)HwReadPhysicalMemory,
        (provWritePhysicalMemory)HwWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)MapMemRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)MapMemReadKernelVirtualMemory,
        (provWriteKernelVM)MapMemWriteKernelVirtualMemory,

        (provVirtualToPhysical)MapMemVirtualToPhysical,
        (provReadPhysicalMemory)MapMemReadPhysicalMemory,
        (provWritePhysicalMemory)MapMemWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)ZmRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)ZmMapDriver,
        (provControlDSE)ZmControlDSE,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)ZmOpenProcess
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)DI64ReadPhysicalMemory,
        (provWritePhysicalMemory)DI64WritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)AsrReadPhysicalMemory,
        (provWritePhysicalMemory)AsrWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)AlcReadPhysicalMemory,
        (provWritePhysicalMemory)AlcWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)RmReadPhysicalMemory,
        (provWritePhysicalMemory)RmWritePhysicalMemory,

        (provValidatePrerequisites)RmValidatePrerequisites,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)PhmRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)PhmReadPhysicalMemory,
        (provWritePhysicalMemory)PhmWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)LddRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)LddControlDSE,

        (provReadKernelVM)LddReadKernelVirtualMemory,
        (provWriteKernelVM)LddWriteKernelVirtualMemory,

        (provVirtualToPhysical)LddpVirtualToPhysical,
        (provReadPhysicalMemory)LddReadWritePhysicalMemoryStub,
        (provWritePhysicalMemory)LddReadWritePhysicalMemoryStub,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)DellRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)DpdReadPhysicalMemory,
        (provWritePhysicalMemory)DpdWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)HpEtdReadVirtualMemory,
        (provWriteKernelVM)HpEtdWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)KObExpReadVirtualMemory,
        (provWriteKernelVM)KObExpWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)ZdcStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)ZdcRegisterDriver,
        (provUnregisterDriver)ZdcUnregisterDriver,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)ZdcReadKernelVirtualMemory,
        (provWriteKernelVM)ZdcWriteKernelVirtualMemory,

        (provVirtualToPhysical)ZdcVirtualToPhysical,
        (provReadPhysicalMemory)ZdcReadPhysicalMemory,
        (provWritePhysicalMemory)ZdcWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)ZdcStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)ZdcRegisterDriver,
        (provUnregisterDriver)ZdcUnregisterDriver,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)ZdcReadKernelVirtualMemory,
        (provWriteKernelVM)ZdcWriteKernelVirtualMemory,

        (provVirtualToPhysical)ZdcVirtualToPhysical,
        (provReadPhysicalMemory)ZdcReadPhysicalMemory,
        (provWritePhysicalMemory)ZdcWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)EchoDrvRegisterDriver,
        (provUnregisterDriver)EchoDrvUnregisterDriver,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)EchoDrvReadVirtualMemory,
        (provWriteKernelVM)EchoDrvWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)EchoDrvOpenProcess
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NvoReadPhysicalMemory,
        (provWritePhysicalMemory)NvoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)NULL,
        (provControlDSE)NULL,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)BeDrvOpenProcess
     },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)WRZeroReadPhysicalMemory,
        (provWritePhysicalMemory)WRZeroWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },


    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)NULL,
        (provControlDSE)NULL,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)RazerOpenProcess
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)PdFwReadVirtualMemory,
        (provWriteKernelVM)PdFwWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)RmReadPhysicalMemory,
        (provWritePhysicalMemory)RmWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)EvgaReadPhysicalMemory,
        (provWritePhysicalMemory)EvgaWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)AsrRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)RweReadPhysicalMemory,
        (provWritePhysicalMemory)RweWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)AsrReadPhysicalMemory,
        (provWritePhysicalMemory)AsrWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },


    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)AsrRegisterDriver,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)RweReadPhysicalMemory,
        (provWritePhysicalMemory)RweWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },


    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)AsrReadPhysicalMemory,
        (provWritePhysicalMemory)AsrWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)PmxDrvReadKernelVirtualMemory,
        (provWriteKernelVM)PmxDrvWriteKernelVirtualMemory,

        (provVirtualToPhysical)PmxDrvVirtualToPhysical,
        (provReadPhysicalMemory)PmxDrvReadPhysicalMemory,
        (provWritePhysicalMemory)PmxDrvWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE2,

        (provReadKernelVM)NULL,
        (provWriteKernelVM)NULL,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)WRZeroReadPhysicalMemory,
        (provWritePhysicalMemory)WRZeroWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
     },

    {
        NULL,

        (provStartVulnerableDriver)NetEaseStartVulnerableDriver,
        (provStopVulnerableDriver)NetEaseStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)NULL,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)NetEaseReadVirtualMemory,
        (provWriteKernelVM)NetEaseWriteVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)NULL,
        (provWritePhysicalMemory)NULL,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)TpupReadKernelVirtualMemory,
        (provWriteKernelVM)TpupWriteKernelVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)TpupReadPhysicalMemory,
        (provWritePhysicalMemory)TpupWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)TpwReadKernelVirtualMemory,
        (provWriteKernelVM)TpwWriteKernelVirtualMemory,

        (provVirtualToPhysical)NULL,
        (provReadPhysicalMemory)TpwReadPhysicalMemory,
        (provWritePhysicalMemory)TpwWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)LnvMsrReadKernelVirtualMemory,
        (provWriteKernelVM)LnvMsrWriteKernelVirtualMemory,

        (provVirtualToPhysical)LnvMsrVirtualToPhysical,
        (provReadPhysicalMemory)LnvMsrReadPhysicalMemory,
        (provWritePhysicalMemory)LnvMsrWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)CorMemReadKernelVirtualMemory,
        (provWriteKernelVM)CorMemWriteKernelVirtualMemory,

        (provVirtualToPhysical)CorMemVirtualToPhysical,
        (provReadPhysicalMemory)CorMemReadPhysicalMemory,
        (provWritePhysicalMemory)CorMemWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
     },

    {
        NULL,
        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,
        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)IpcReadKernelVirtualMemory,
        (provWriteKernelVM)IpcWriteKernelVirtualMemory,

        (provVirtualToPhysical)IpcVirtualToPhysical,
        (provReadPhysicalMemory)IpcReadPhysicalMemory,
        (provWritePhysicalMemory)IpcWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    },

    {
        NULL,
        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,
        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)WinHdDrvReadKernelVirtualMemory,
        (provWriteKernelVM)WinHdDrvWriteKernelVirtualMemory,

        (provVirtualToPhysical)WinHdDrvVirtualToPhysical,
        (provReadPhysicalMemory)WRZeroReadPhysicalMemory,
        (provWritePhysicalMemory)WRZeroWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)AffReadKernelVirtualMemory,
        (provWriteKernelVM)AffWriteKernelVirtualMemory,

        (provVirtualToPhysical)AffVirtualToPhysical,
        (provReadPhysicalMemory)AffReadPhysicalMemory,
        (provWritePhysicalMemory)AffWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)MatroxReadKernelVirtualMemory,
        (provWriteKernelVM)MatroxWriteKernelVirtualMemory,

        (provVirtualToPhysical)MatroxVirtualToPhysical,
        (provReadPhysicalMemory)MatroxReadPhysicalMemory,
        (provWritePhysicalMemory)MatroxWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    },

    {
        NULL,

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
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        (provWritePhysicalMemory)WinIoWritePhysicalMemory,

        (provValidatePrerequisites)NULL,

        (provOpenProcess)NULL
    },

    {
        NULL,

        (provStartVulnerableDriver)KDUProvStartVulnerableDriver,
        (provStopVulnerableDriver)KDUProvStopVulnerableDriver,

        (provRegisterDriver)NULL,
        (provUnregisterDriver)NULL,
        (provPreOpenDriver)NULL,
        (provPostOpenDriver)KDUProviderPostOpen,
        (provMapDriver)KDUMapDriver,
        (provControlDSE)KDUControlDSE,

        (provReadKernelVM)LecoReadKernelVirtualMemory,
        (provWriteKernelVM)LecoWriteKernelVirtualMemory,

        (provVirtualToPhysical)LecoVirtualToPhysical,
        (provReadPhysicalMemory)LecoReadPhysicalMemory,
        (provWritePhysicalMemory)LecoWritePhysicalMemory,

        (provValidatePrerequisites)KDUValidatePrerequisitesForSuperfetch,

        (provOpenProcess)NULL
    }

};
