/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.00
*
*  DATE:        18 Apr 2021
*
*  AsIo2 "unlock" resource generator and binder.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <Windows.h>
#include <strsafe.h>

#ifdef __cplusplus
extern "C" {
#include "../../Shared/ntos/ntos.h"
#include "../../Shared/minirtl/cmdline.h"
}
#endif

/*
* supChkSum
*
* Purpose:
*
* Calculate partial checksum for given buffer.
*
*/
USHORT supChkSum(
    ULONG PartialSum,
    PUSHORT Source,
    ULONG Length
)
{
    while (Length--) {
        PartialSum += *Source++;
        PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
    }
    return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
}

/*
* supCalculateCheckSumForMappedFile
*
* Purpose:
*
* Calculate PE file checksum.
*
*/
DWORD supCalculateCheckSumForMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength
)
{
    PUSHORT AdjustSum;
    PIMAGE_NT_HEADERS NtHeaders;
    USHORT PartialSum;
    ULONG CheckSum;

    PartialSum = supChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders != NULL) {
        AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
        PartialSum -= (PartialSum < AdjustSum[0]);
        PartialSum -= AdjustSum[0];
        PartialSum -= (PartialSum < AdjustSum[1]);
        PartialSum -= AdjustSum[1];
    }
    else
    {
        PartialSum = 0;
    }
    CheckSum = (ULONG)PartialSum + FileLength;
    return CheckSum;
}

BOOL UpdateChecksum(
    _In_ LPCSTR lpFileName
)
{
    BOOL    bResult = FALSE;
    HANDLE  hFile = INVALID_HANDLE_VALUE;
    HANDLE  hFileMap = NULL;
    DWORD   FileSize;
    LPVOID  ImageBase = NULL;

    PIMAGE_OPTIONAL_HEADER32    oh32 = NULL;
    PIMAGE_OPTIONAL_HEADER64    oh64 = NULL;

    ULONG NewCheckSum;

    IMAGE_NT_HEADERS* NtHeaders = NULL;

    __try {

        hFile = CreateFileA(lpFileName, GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            printf_s("[G] Cannot open input file\n");
            __leave;
        }

        FileSize = GetFileSize(hFile, NULL);
        if (FileSize == 0) {
            printf_s("[G] Input file is empty\n");
            __leave;
        }

        hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (hFileMap == NULL) {
            printf_s("[G] CreateFileMapping failed for input file\n");
            __leave;
        }

        ImageBase = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
        if (ImageBase == NULL) {
            printf_s("[G] MapViewOfFile failed for input file\n");
            __leave;
        }

        NtHeaders = RtlImageNtHeader(ImageBase);
        if (NtHeaders == NULL) {
            printf_s("[G] RtlImageNtHeader failed for input file\n");
            __leave;
        }

        oh32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader;
        oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

        if ((NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) && (NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)) {
            printf_s("[G] Unsuported FileHeader.Machine value\n");
            __leave;
        }

        NewCheckSum = supCalculateCheckSumForMappedFile(ImageBase, FileSize);
        if (NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            oh64->CheckSum = NewCheckSum;
        }
        else {
            oh32->CheckSum = NewCheckSum;
        }

        bResult = TRUE;

    }
    __finally {
        if (ImageBase) {
            FlushViewOfFile(ImageBase, 0);
            UnmapViewOfFile(ImageBase);
        }

        if (hFileMap)
            CloseHandle(hFileMap);

        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
    }

    return bResult;
}


VOID ProcessFile(
    _In_ LPCSTR lpFileName)
{
    BOOL bUpdated = FALSE, bInit;
    ULONG seconds = 0, dwError;
    LARGE_INTEGER fileTime;

    BYTE Buffer[16];
    DWORD aKey[4] = { 0x16157EAA, 0xA6D2AE28, 0x8815F7AB, 0x3C4FCF09 };

    HCRYPTPROV hProv;
    HCRYPTKEY hKey = NULL;
    DWORD bytesIO = 0;
    DWORD dwMode;

    struct {
        BLOBHEADER hdr;
        DWORD len;
        BYTE key[16];
    } KeyBlob;

    GetSystemTimeAsFileTime((PFILETIME)&fileTime);
    RtlTimeToSecondsSince1970(&fileTime, &seconds);

    RtlSecureZeroMemory(Buffer, sizeof(Buffer));

    RtlCopyMemory(Buffer, &seconds, sizeof(DWORD));

    do {

        bInit = CryptAcquireContext(&hProv,
            NULL,
            MS_ENH_RSA_AES_PROV,
            PROV_RSA_AES,
            CRYPT_SILENT);

        if (!bInit)
        {
            if (GetLastError() == NTE_BAD_KEYSET) {

                bInit = CryptAcquireContext(&hProv,
                    NULL,
                    MS_ENH_RSA_AES_PROV,
                    PROV_RSA_AES,
                    CRYPT_NEWKEYSET);
            }

        }

        if (bInit == FALSE) {
            printf_s("[G] Failed to acquire context for Crypto API, error %lX\n", GetLastError());
            break;
        }

        printf_s("[G] CryptoAPI context acquired\n");

        KeyBlob.hdr.bType = PLAINTEXTKEYBLOB;
        KeyBlob.hdr.bVersion = CUR_BLOB_VERSION;
        KeyBlob.hdr.reserved = 0;
        KeyBlob.hdr.aiKeyAlg = CALG_AES_128;
        KeyBlob.len = sizeof(aKey);
        RtlCopyMemory(KeyBlob.key, aKey, sizeof(aKey));

        if (!CryptImportKey(hProv, (BYTE*)&KeyBlob, sizeof(KeyBlob), NULL, 0, &hKey)) {
            printf_s("[G] Failed to import key, error %lX\n", GetLastError());
            break;
        }
        else {
            printf_s("[G] AES key imported successfully\n");
        }

        dwMode = CRYPT_MODE_ECB;

        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0)) {
            printf_s("[G] Failed to set key param, error %lX\n", GetLastError());
            break;
        }
        else {
            printf_s("[G] AES ECB mode set\n");
        }

        bytesIO = sizeof(Buffer);

        if (!CryptEncrypt(hKey, NULL, FALSE, 0, (BYTE*)Buffer, &bytesIO, bytesIO)) {
            printf_s("[G] Failed to encrypt data, error %lX\n", GetLastError());
            break;
        }
        else {
            printf_s("[G] Data for driver unlocking encrypted successfully\n");
        }

    } while (FALSE);

    if (hKey) CryptDestroyKey(hKey); 
    CryptReleaseContext(hProv, 0);

    printf_s("[G] Generating AsIo2 unlock resource\n");

    HANDLE hRes = BeginUpdateResourceA(lpFileName, FALSE);
    if (hRes) {

        if (!UpdateResourceA(hRes,
            (LPCSTR)RT_RCDATA,
            "ASUSCERT",
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            Buffer,
            sizeof(Buffer)))
        {
            dwError = GetLastError();
            printf_s("[G] Could not update resources, GetLastError %lu\n", dwError);
        }
        else {
            printf_s("[G] File resources updated\n");
        }

        bUpdated = EndUpdateResource(hRes, FALSE);

    }
    else {
        dwError = GetLastError();
        printf_s("[G] Could not open %s, GetLastError %lu\n", lpFileName, dwError);
    }

    if (bUpdated) {

        printf_s("[G] Updating file checksum\n");

        if (UpdateChecksum(lpFileName)) {
            printf_s("[G] Checksum updated\n");
        }
        else {
            printf_s("[G] Could not update checksum!\n");
        }
    }
}

int main()
{
    ULONG l;
    CHAR szFileName[MAX_PATH + 1];

    l = 0;
    RtlSecureZeroMemory(szFileName, sizeof(szFileName));
    GetCommandLineParamA(GetCommandLineA(), 1, szFileName, MAX_PATH, &l);
    if (l > 0) {
        printf_s("GenAsIo2Unlock v1.0 built at %s\n[G] Processing input file %s\n", __TIMESTAMP__, szFileName);
        ProcessFile(szFileName);
    }
    else {
        printf_s("[G] Input file not specified\n");
    }
    return 0;
}
