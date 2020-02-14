/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       TESTS.CPP
*
*  VERSION:     1.00
*
*  DATE:        02 Feb 2020
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

VOID KDUTest()
{
    PKDU_CONTEXT Context;
    ULONG_PTR objectAddress = 0, value = 0;

    UCHAR Buffer[4096];

    RtlSecureZeroMemory(&Buffer, sizeof(Buffer));

    Context = KDUProviderCreate(7, FALSE, 14393, GetModuleHandle(NULL), ActionTypeMapDriver);
    if (Context) {

        if (supQueryObjectFromHandle(Context->DeviceHandle, &objectAddress)) {

            value = 0x1234567890ABCDEF;

            FILE_OBJECT fileObject;

            RtlSecureZeroMemory(&fileObject, sizeof(FILE_OBJECT));

            objectAddress = 0xfffff8087fe36d18;

            KDUReadKernelVM(Context,
                objectAddress,
                &value,
                sizeof(value));

            ULONG_PTR newValue = 0xABCDEF0;

            KDUWriteKernelVM(Context,
                objectAddress,
                &newValue,
                sizeof(newValue));

            Beep(0, 0);

        }
        
        KDUProviderRelease(Context);
    }
}
