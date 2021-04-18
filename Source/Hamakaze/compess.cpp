/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       COMPRESS.CPP
*
*  VERSION:     1.10
*
*  DATE:        15 Apr 2021
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
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize,
    _In_ ULONG DecryptKey,
    _In_ BOOLEAN VerifyChecksum
)
{
    PBYTE dataPtr;
    ULONG dataSize = 0;
    SIZE_T decompressedSize = 0;

    if (DataSize)
        *DataSize = 0;

    dataPtr = supQueryResourceData(ResourceId,
        DllHandle,
        &dataSize);

    if (dataPtr && dataSize) {

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
    BOOLEAN bValidData = FALSE;
    DELTA_INPUT diDelta, diSource;
    DELTA_OUTPUT doOutput;
    PVOID resultPtr = NULL, dataBlob;

    ULONG headerSum = 0, calcSum = 0;

    *DecompressedSize = 0;

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

            bValidData = supVerifyMappedImageMatchesChecksum(decomPtr,
                (ULONG)newSize,
                &headerSum,
                &calcSum);

            if (VerifyChecksum) {

                if (bValidData == FALSE) {
                    
                    supPrintfEvent(kduEventError, 
                        "[!] Error data checksum mismatch! Header sum 0x%lx, calculated sum 0x%lx\r\n",
                        headerSum, 
                        calcSum);

                }
            }
            else {

                if (bValidData == FALSE) {
                    printf_s("[~] Data checksum mismatch, header sum 0x%lx, calculated sum 0x%lx, trying to continue\r\n",
                        headerSum, calcSum);
                }

                bValidData = TRUE; //ignore
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
            
            supPrintfEvent(kduEventError, 
                "[!] Error decompressing resource, GetLastError %lu\r\n", GetLastError());

        }

        supHeapFree(dataBlob);
    }

    return resultPtr;
}

/*
* KDUCompressResource
*
* Purpose:
*
* Compress resource and write it to the disk into new file with same name and .bin extension.
*
*/
VOID KDUCompressResource(
    _In_ LPWSTR lpFileName,
    _In_ ULONG ulCompressKey
)
{
    DWORD fileSize = 0;
    PBYTE fileBuffer;

    DELTA_INPUT d_in, d_target, s_op, t_op, g_op;
    DELTA_OUTPUT d_out;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    printf_s("[+] Reading %wS\r\n", lpFileName);
    fileBuffer = supReadFileToBuffer(lpFileName, &fileSize);

    if (fileBuffer) {

        printf_s("[+] %lu bytes read\r\n", fileSize);

        PWSTR newFileName;
        SIZE_T sz = _strlen(lpFileName) + (2 * MAX_PATH);

        newFileName = (PWSTR)supHeapAlloc(sz);
        if (newFileName == NULL) {

            supPrintfEvent(kduEventError, 
                "[!] Could not allocate memory for filename\r\n");

        }
        else {

            _filename_noext(newFileName, lpFileName);

            RtlSecureZeroMemory(&d_in, sizeof(DELTA_INPUT));
            d_target.lpcStart = fileBuffer;
            d_target.uSize = fileSize;
            d_target.Editable = FALSE;

            RtlSecureZeroMemory(&s_op, sizeof(DELTA_INPUT));
            RtlSecureZeroMemory(&t_op, sizeof(DELTA_INPUT));
            RtlSecureZeroMemory(&g_op, sizeof(DELTA_INPUT));

            if (CreateDeltaB(DELTA_FILE_TYPE_RAW,
                DELTA_FLAG_NONE,
                DELTA_FLAG_NONE,
                d_in,
                d_target,
                s_op,
                t_op,
                g_op,
                NULL,
                0,
                &d_out))
            {
                SIZE_T writeSize = d_out.uSize;
                PVOID dataBlob = supHeapAlloc(writeSize);
                if (dataBlob) {

                    RtlCopyMemory(dataBlob, d_out.lpStart, writeSize);
                    EncodeBuffer(dataBlob, (ULONG)writeSize, ulCompressKey);

                    _strcat(newFileName, L".bin");

                    printf_s("[+] Saving resource as %wS with new size %llu bytes\r\n",
                        newFileName, writeSize);

                    if (supWriteBufferToFile(newFileName,
                        dataBlob,
                        writeSize,
                        TRUE,
                        FALSE,
                        NULL) != writeSize)
                    {
                        
                        supPrintfEvent(kduEventError, 
                            "[!] Error writing to file\r\n");

                    }

                    supHeapFree(dataBlob);
                }

                DeltaFree(d_out.lpStart);
            }
            else {

                supPrintfEvent(kduEventError, 
                    "[!] Error compressing resource, GetLastError %lu\r\n", GetLastError());

            }

            supHeapFree(newFileName);
        }

        supHeapFree(fileBuffer);

    }
    else {

        supPrintfEvent(kduEventError, 
            "[!] Could not read input file\r\n");

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
}
