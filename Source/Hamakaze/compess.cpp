/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020 gruf0x
*
*  TITLE:       COMPRESS.CPP
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
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
#include <compressapi.h>

#pragma comment(lib, "msdelta.lib")

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
    _Out_ PSIZE_T DecompressedSize
)
{
    DELTA_INPUT diDelta, diSource;
    DELTA_OUTPUT doOutput;
    PVOID resultPtr = NULL;

    *DecompressedSize = 0;

    RtlSecureZeroMemory(&diSource, sizeof(DELTA_INPUT));
    RtlSecureZeroMemory(&diDelta, sizeof(DELTA_INPUT));
    RtlSecureZeroMemory(&doOutput, sizeof(DELTA_OUTPUT));

    diDelta.Editable = FALSE;
    diDelta.lpcStart = ResourcePtr;
    diDelta.uSize = ResourceSize;

    if (ApplyDeltaB(DELTA_FILE_TYPE_RAW, diSource, diDelta, &doOutput)) {

        SIZE_T newSize = (DWORD)doOutput.uSize;
        PVOID decomPtr = doOutput.lpStart;

        if (supVerifyMappedImageMatchesChecksum(decomPtr,
            (ULONG)newSize))
        {
            resultPtr = (PVOID)supHeapAlloc(newSize);
            if (resultPtr) {
                RtlCopyMemory(resultPtr, decomPtr, newSize);
                *DecompressedSize = newSize;
            }
        }
        else {
            printf_s("[!] Error data checksum mismatch!\r\n");
        }

        DeltaFree(doOutput.lpStart);

    }
    else {
        printf_s("[!] Error decompressing resource, GetLastError %lu\r\n", GetLastError());
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
    _In_ LPWSTR lpFileName)
{
    DWORD fileSize = 0;
    PBYTE fileBuffer;

    DELTA_INPUT d_in, d_target, s_op, t_op, g_op;
    DELTA_OUTPUT d_out;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    printf_s("[+] Reading %wS\r\n", lpFileName);
    fileBuffer = supReadFileToBuffer(lpFileName, &fileSize);

    if (fileBuffer) {

        printf_s("[+] %lu bytes read\r\n", fileSize);

        PWSTR newFileName;
        SIZE_T sz = _strlen(lpFileName) + (2 * MAX_PATH);

        newFileName = (PWSTR)supHeapAlloc(sz);
        if (newFileName == NULL) {
            printf_s("[!] Could not allocate memory for filename\r\n");
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
                PVOID dataBlob = d_out.lpStart;

                _strcat(newFileName, L".bin");

                printf_s("[+] Saving compressed resource as %wS with new size %llu bytes\r\n",
                    newFileName, writeSize);

                if (supWriteBufferToFile(newFileName,
                    dataBlob,
                    writeSize,
                    TRUE,
                    FALSE,
                    NULL) != writeSize)
                {
                    printf_s("[!] Error writing to file\r\n");
                }

                DeltaFree(d_out.lpStart);
            }
            else {

                printf_s("[!] Error compressing resource, GetLastError %lu\r\n", GetLastError());
            }

            supHeapFree(newFileName);
        }

        supHeapFree(fileBuffer);

    }
    else {
        printf_s("[!] Could not read input file\r\n");
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
}
