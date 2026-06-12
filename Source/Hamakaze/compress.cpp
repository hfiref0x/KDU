/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       COMPRESS.CPP
*
*  VERSION:     1.49
*
*  DATE:        10 Jun 2026
*
*  Compression support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include <msdelta.h>

#pragma comment(lib, "msdelta.lib")

/*
* KDULookupResourceFromDatabase
*
* Purpose:
*
* Query KDU db entry by id.
*
*/
PVOID KDULookupResourceFromDatabase(
    _In_ PVOID Database,
    _In_ DWORD ResourceId,
    _In_ DWORD* Size
)
{
    RESOURCE_DB_HEADER* Header;
    RESOURCE_DB_ENTRY* Entries;

    LONG Left;
    LONG Right;

    Header = (RESOURCE_DB_HEADER*)Database;

    if (Header->Signature != RESOURCE_DB_SIGNATURE) {
        return NULL;
    }

    Entries = (RESOURCE_DB_ENTRY*)(Header + 1);

    Left = 0;
    Right = (LONG)Header->EntryCount - 1;

    while (Left <= Right) {

        LONG Mid;
        Mid = (Left + Right) / 2;
        if (Entries[Mid].Id == ResourceId) {
            if (Size)
                *Size = Entries[Mid].Size;
            return ((PBYTE)Database) + Entries[Mid].Offset;
        }

        if (Entries[Mid].Id <
            ResourceId)
        {
            Left = Mid + 1;
        }
        else
        {
            Right = Mid - 1;
        }
    }

    return NULL;
}

/*
* EncodeBuffer
*
* Purpose:
*
* Decrypt/Encrypt given buffer.
*
*/
VOID EncodeBuffer(
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _In_ ULONG Key
)
{
    ULONG k, c;
    PUCHAR ptr;

    if ((Buffer == NULL) || (BufferSize == 0))
        return;

    k = Key;
    c = BufferSize;
    ptr = (PUCHAR)Buffer;

    do {
        *ptr ^= k;
        k = _rotl(k, 1);
        ptr++;
        --c;
    } while (c != 0);
}

/*
* KDULoadResource
*
* Purpose:
*
* Access and decompress resource.
*
* N.B. Use supHeapFree to release memory allocated for the decompressed buffer.
*
*/
PVOID KDULoadResource(
    _In_ ULONG ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize,
    _In_ ULONG DecryptKey,
    _In_ BOOLEAN VerifyChecksum
)
{
    BOOL bSelf;
    PBYTE dataPtr;
    ULONG dataSize = 0;
    SIZE_T decompressedSize = 0;
    ULONG resKey;

    if (DataSize)
        *DataSize = 0;

    bSelf = DllHandle == NtCurrentPeb()->ImageBaseAddress;
    resKey = (bSelf) ? ResourceId : IDR_KDUDB;

    dataPtr = supQueryResourceData(resKey,
        DllHandle,
        &dataSize);

    if (dataPtr && dataSize) {

        if (!bSelf) {
            dataPtr = (PBYTE)KDULookupResourceFromDatabase(dataPtr, ResourceId, &dataSize);
        }

        dataPtr = (PBYTE)KDUDecompressResource(dataPtr,
            dataSize,
            &decompressedSize,
            DecryptKey,
            VerifyChecksum);

        if (DataSize)
            *DataSize = (ULONG)decompressedSize;

        return dataPtr;
    }

    return NULL;
}

/*
* KDUDecompressResource
*
* Purpose:
*
* Decompress resource and return pointer to decompressed data.
*
* N.B. Use supHeapFree to release memory allocated for the decompressed buffer.
*
*/
PVOID KDUDecompressResource(
    _In_ PVOID ResourcePtr,
    _In_ SIZE_T ResourceSize,
    _Out_ PSIZE_T DecompressedSize,
    _In_ ULONG DecryptKey,
    _In_ BOOLEAN VerifyChecksum
)
{
    BOOLEAN bValidData;
    DELTA_INPUT diDelta, diSource;
    DELTA_OUTPUT doOutput;
    PVOID resultPtr = NULL, dataBlob;

    *DecompressedSize = 0;
    if (ResourcePtr == NULL)
        return NULL;

    RtlSecureZeroMemory(&diSource, sizeof(DELTA_INPUT));
    RtlSecureZeroMemory(&diDelta, sizeof(DELTA_INPUT));
    RtlSecureZeroMemory(&doOutput, sizeof(DELTA_OUTPUT));

    dataBlob = supHeapAlloc(ResourceSize);
    if (dataBlob) {
        RtlCopyMemory(dataBlob, ResourcePtr, ResourceSize);
        EncodeBuffer(dataBlob, (ULONG)ResourceSize, DecryptKey);

        diDelta.Editable = FALSE;
        diDelta.lpcStart = dataBlob;
        diDelta.uSize = ResourceSize;

        if (ApplyDeltaB(DELTA_FILE_TYPE_RAW, diSource, diDelta, &doOutput)) {
            
            SIZE_T newSize = doOutput.uSize;
            PVOID decomPtr = doOutput.lpStart;

            bValidData = TRUE;

            if (VerifyChecksum) {

                ULONG headerSum = 0, calcSum = 0;

                bValidData = supVerifyMappedImageMatchesChecksum(decomPtr,
                    (ULONG)newSize,
                    &headerSum,
                    &calcSum);

                if (bValidData == FALSE) {
                    
                    supPrintfEvent(kduEventError, 
                        "[!] Error data checksum mismatch! Header sum 0x%lx, calculated sum 0x%lx\r\n",
                        headerSum, 
                        calcSum);

                }
            }
            else {
                printf_s("[+] Checksum verification skipped\r\n");
            }

            if (bValidData) {
                resultPtr = (PVOID)supHeapAlloc(newSize);
                if (resultPtr) {
                    RtlCopyMemory(resultPtr, decomPtr, newSize);
                    *DecompressedSize = newSize;
                }
            }

            DeltaFree(doOutput.lpStart);

        }
        else {
            
            supShowWin32Error("[!] Error while decompressing resource", GetLastError());

        }

        supHeapFree(dataBlob);
    }

    return resultPtr;
}
