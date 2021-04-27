/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       TESTS.CPP
*
*  VERSION:     1.10
*
*  DATE:        01 Apr 2021
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

VOID KDUTest()
{
    PKDU_CONTEXT Context;
    ULONG_PTR objectAddress = 0, value;

    UCHAR Buffer[4096];

    RtlSecureZeroMemory(&Buffer, sizeof(Buffer));

    Context = KDUProviderCreate(14, FALSE, 7601, KDU_SHELLCODE_V1, ActionTypeMapDriver);
    if (Context) {

        ULONG64 dummy = 0;

        KDUReadKernelVM(Context,
            0xfffff80afbbe6d18,
            &dummy,
            sizeof(dummy));

        /*if (supQueryObjectFromHandle(Context->DeviceHandle, &objectAddress)) {

            Context->Provider->Callbacks.ReadPhysicalMemory(
                Context->DeviceHandle,
                0x1000,
                &Buffer,
                0x1000);

            value = 0x1234567890ABCDEF;

            FILE_OBJECT fileObject;

            RtlSecureZeroMemory(&fileObject, sizeof(FILE_OBJECT));

            KDUReadKernelVM(Context,
                objectAddress,
                &fileObject,
                sizeof(fileObject));

            Beep(0, 0);

        }*/
        
        KDUProviderRelease(Context);
    }
}
