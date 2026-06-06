/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       HASH.CPP
*
*  VERSION:     1.49
*
*  DATE:        06 Jun 2026
*
*  In-memory hash support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "hash.h"

#define DEFAULT_ALIGN_BYTES 8

typedef struct _KDU_EXCLUDE_DATA {
    ULONG ChecksumOffset;
    ULONG SecurityOffset;
    PIMAGE_DATA_DIRECTORY SecurityDirectory;
} KDU_EXCLUDE_DATA, * PKDU_EXCLUDE_DATA;

typedef struct _KDU_MEMORY_VIEW_INFO {
    PVOID ViewBase;
    ULONG FileSize;
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG LastError;
    KDU_EXCLUDE_DATA ExcludeData;
} KDU_MEMORY_VIEW_INFO, * PKDU_MEMORY_VIEW_INFO;

typedef struct _KDU_CNG_CTX {
    BCRYPT_ALG_HANDLE AlgHandle;
    BCRYPT_HASH_HANDLE HashHandle;
    PVOID HashObject;
    ULONG HashObjectSize;
    PVOID Hash;
    ULONG HashSize;
} KDU_CNG_CTX, * PKDU_CNG_CTX;

/*
* HashpAddPad
*
* Purpose:
*
* Calculate hash for pad bytes.
*
*/
NTSTATUS HashpAddPad(
    _In_ ULONG PaddingSize,
    _In_ PKDU_CNG_CTX HashContext)
{
    static const UCHAR zeroPad[DEFAULT_ALIGN_BYTES] = { 0 };
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG remainingPad;
    ULONG blockSize;

    remainingPad = PaddingSize;

    if (PaddingSize == 0)
        return STATUS_SUCCESS;

    while (remainingPad > 0) {
        blockSize = min(remainingPad, DEFAULT_ALIGN_BYTES);
        ntStatus = BCryptHashData(HashContext->HashHandle,
            (PUCHAR)zeroPad,
            blockSize,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        remainingPad -= blockSize;
    }

    return ntStatus;
}

/*
* HashpGetSizeOfHeaders
*
* Purpose:
*
* Return PE OptionalHeader size of headers.
*
*/
DWORD HashpGetSizeOfHeaders(
    _In_ PIMAGE_NT_HEADERS NtHeaders
)
{
    switch (NtHeaders->OptionalHeader.Magic) {
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        return ((PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader)->SizeOfHeaders;
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        return ((PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader)->SizeOfHeaders;
    default:
        return 0;
    }
}

/*
* HashpGetExcludeRange
*
* Purpose:
*
* Retrieve data and offsets to be skipped during hash calculation.
*
*/
BOOLEAN HashpGetExcludeRange(
    _Inout_ PKDU_MEMORY_VIEW_INFO ViewInformation
)
{
    ULONG securityOffset;
    ULONG checksumOffset;
    ULONG endOfLastSection;
    ULONG numberOfSections;
    PIMAGE_DATA_DIRECTORY dataDirectory;
    PIMAGE_SECTION_HEADER sectionTableEntry;
    PIMAGE_OPTIONAL_HEADER64 opt64;
    PIMAGE_OPTIONAL_HEADER32 opt32;
    PIMAGE_DOS_HEADER dosHeader;

    securityOffset = 0;
    checksumOffset = 0;
    endOfLastSection = 0;
    numberOfSections = 0;
    dataDirectory = NULL;
    sectionTableEntry = NULL;
    opt64 = NULL;
    opt32 = NULL;
    dosHeader = (PIMAGE_DOS_HEADER)ViewInformation->ViewBase;

    switch (ViewInformation->NtHeaders->OptionalHeader.Magic) {

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:

        checksumOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.CheckSum);
        securityOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        opt64 = (PIMAGE_OPTIONAL_HEADER64)&ViewInformation->NtHeaders->OptionalHeader;
        dataDirectory = &opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        break;

    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:

        checksumOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.CheckSum);
        securityOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        opt32 = (PIMAGE_OPTIONAL_HEADER32)&ViewInformation->NtHeaders->OptionalHeader;
        dataDirectory = &opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        break;

    default:
        return FALSE;
    }

    if (dataDirectory->VirtualAddress) {

        numberOfSections = ViewInformation->NtHeaders->FileHeader.NumberOfSections;
        if (numberOfSections == 0)
            return FALSE;

        sectionTableEntry = IMAGE_FIRST_SECTION(ViewInformation->NtHeaders);
        endOfLastSection = sectionTableEntry[numberOfSections - 1].PointerToRawData +
            sectionTableEntry[numberOfSections - 1].SizeOfRawData;

        if (dataDirectory->VirtualAddress < endOfLastSection)
            return FALSE;

        if (dataDirectory->VirtualAddress >= ViewInformation->FileSize)
            return FALSE;

        if (dataDirectory->Size > (ViewInformation->FileSize - dataDirectory->VirtualAddress))
            return FALSE;
    }

    ViewInformation->ExcludeData.ChecksumOffset = checksumOffset;
    ViewInformation->ExcludeData.SecurityOffset = securityOffset;
    ViewInformation->ExcludeData.SecurityDirectory = dataDirectory;

    return TRUE;
}

/*
* HashpCreateContext
*
* Purpose:
*
* Allocate CNG context for given algorithm.
*
*/
NTSTATUS HashpCreateContext(
    _In_ PCWSTR AlgId,
    _Out_ PKDU_CNG_CTX* Context
)
{
    NTSTATUS ntStatus;
    ULONG cbResult;
    PKDU_CNG_CTX context;

    *Context = NULL;
    cbResult = 0;

    context = (PKDU_CNG_CTX)supHeapAlloc(sizeof(KDU_CNG_CTX));
    if (context == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlSecureZeroMemory(context, sizeof(KDU_CNG_CTX));

    do {

        ntStatus = BCryptOpenAlgorithmProvider(&context->AlgHandle,
            AlgId,
            NULL,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = BCryptGetProperty(context->AlgHandle,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&context->HashObjectSize,
            sizeof(ULONG),
            &cbResult,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = BCryptGetProperty(context->AlgHandle,
            BCRYPT_HASH_LENGTH,
            (PUCHAR)&context->HashSize,
            sizeof(ULONG),
            &cbResult,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        context->HashObject = supHeapAlloc(context->HashObjectSize);
        if (context->HashObject == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        context->Hash = supHeapAlloc(context->HashSize);
        if (context->Hash == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ntStatus = BCryptCreateHash(context->AlgHandle,
            &context->HashHandle,
            (PUCHAR)context->HashObject,
            context->HashObjectSize,
            NULL,
            0,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        *Context = context;
        return STATUS_SUCCESS;

    } while (FALSE);

    if (context->HashHandle) BCryptDestroyHash(context->HashHandle);
    if (context->Hash) supHeapFree(context->Hash);
    if (context->HashObject) supHeapFree(context->HashObject);
    if (context->AlgHandle) BCryptCloseAlgorithmProvider(context->AlgHandle, 0);
    supHeapFree(context);

    return ntStatus;
}

/*
* HashpDestroyContext
*
* Purpose:
*
* Release CNG context.
*
*/
VOID HashpDestroyContext(
    _In_ PKDU_CNG_CTX Context
)
{
    if (Context == NULL)
        return;

    if (Context->HashHandle)
        BCryptDestroyHash(Context->HashHandle);
    if (Context->AlgHandle)
        BCryptCloseAlgorithmProvider(Context->AlgHandle, 0);
    if (Context->Hash)
        supHeapFree(Context->Hash);
    if (Context->HashObject)
        supHeapFree(Context->HashObject);

    supHeapFree(Context);
}

/*
* HashpCalcFileHash
*
* Purpose:
*
* Calculate raw image file hash.
*
*/
BOOLEAN HashpCalcFileHash(
    _In_ PKDU_MEMORY_VIEW_INFO ViewInformation,
    _In_ PCWSTR AlgId,
    _Out_writes_bytes_(HashSize) PBYTE Hash,
    _In_ ULONG HashSize)
{
    BOOLEAN bResult;
    NTSTATUS ntStatus;
    PKDU_CNG_CTX hashContext;

    bResult = FALSE;
    hashContext = NULL;

    ntStatus = HashpCreateContext(AlgId, &hashContext);
    if (!NT_SUCCESS(ntStatus))
        return FALSE;

    ntStatus = BCryptHashData(hashContext->HashHandle,
        (PUCHAR)ViewInformation->ViewBase,
        ViewInformation->FileSize,
        0);

    if (NT_SUCCESS(ntStatus)) {
        ntStatus = BCryptFinishHash(hashContext->HashHandle,
            (PUCHAR)hashContext->Hash,
            hashContext->HashSize,
            0);

        if (NT_SUCCESS(ntStatus) && hashContext->HashSize == HashSize) {
            RtlCopyMemory(Hash, hashContext->Hash, HashSize);
            bResult = TRUE;
        }
    }

    HashpDestroyContext(hashContext);
    return bResult;
}

/*
* HashpCalcAuthenticodeHash
*
* Purpose:
*
* Compute authenticode hash for image file.
*
*/
BOOLEAN HashpCalcAuthenticodeHash(
    _In_ PKDU_MEMORY_VIEW_INFO ViewInformation,
    _In_ PCWSTR AlgId,
    _Out_writes_bytes_(HashSize) PBYTE Hash,
    _In_ ULONG HashSize)
{
    BOOLEAN bResult;
    NTSTATUS ntStatus;
    ULONG securityOffset;
    ULONG checksumOffset;
    ULONG paddingSize;
    ULONG fileOffset;
    ULONG dataSize;
    PVOID imageBase;
    PIMAGE_DATA_DIRECTORY dataDirectory;
    PKDU_CNG_CTX hashContext;

    bResult = FALSE;
    hashContext = NULL;
    fileOffset = 0;

    ntStatus = HashpCreateContext(AlgId, &hashContext);
    if (!NT_SUCCESS(ntStatus))
        return FALSE;

    __try {
        imageBase = ViewInformation->ViewBase;
        checksumOffset = ViewInformation->ExcludeData.ChecksumOffset;
        securityOffset = ViewInformation->ExcludeData.SecurityOffset;
        dataDirectory = ViewInformation->ExcludeData.SecurityDirectory;

        ntStatus = BCryptHashData(hashContext->HashHandle,
            (PUCHAR)imageBase,
            checksumOffset,
            0);

        if (NT_SUCCESS(ntStatus)) {

            fileOffset = checksumOffset + RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER, CheckSum);

            dataSize = securityOffset - fileOffset;
            ntStatus = BCryptHashData(hashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(imageBase, fileOffset),
                dataSize,
                0);

            if (NT_SUCCESS(ntStatus)) {

                fileOffset = securityOffset + sizeof(IMAGE_DATA_DIRECTORY);

                if (dataDirectory->VirtualAddress == 0) {
                    dataSize = ViewInformation->FileSize - fileOffset;
                }
                else {
                    dataSize = dataDirectory->VirtualAddress - fileOffset;
                }

                ntStatus = BCryptHashData(hashContext->HashHandle,
                    (PUCHAR)RtlOffsetToPointer(imageBase, fileOffset),
                    dataSize,
                    0);

                if (NT_SUCCESS(ntStatus)) {

                    paddingSize = (dataSize % DEFAULT_ALIGN_BYTES);
                    if (paddingSize) {
                        paddingSize = (DEFAULT_ALIGN_BYTES - paddingSize);
                        ntStatus = HashpAddPad(paddingSize, hashContext);
                    }

                    if (NT_SUCCESS(ntStatus)) {
                        ntStatus = BCryptFinishHash(hashContext->HashHandle,
                            (PUCHAR)hashContext->Hash,
                            hashContext->HashSize,
                            0);

                        if (NT_SUCCESS(ntStatus) && hashContext->HashSize == HashSize) {
                            RtlCopyMemory(Hash, hashContext->Hash, HashSize);
                            bResult = TRUE;
                        }
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        bResult = FALSE;
    }

    HashpDestroyContext(hashContext);
    return bResult;
}

/*
* HashpCalcFirstPageHash
*
* Purpose:
*
* Compute first page hash for PE headers.
*
*/
BOOLEAN HashpCalcFirstPageHash(
    _In_ ULONG PageSize,
    _In_ PKDU_MEMORY_VIEW_INFO ViewInformation,
    _In_ PCWSTR AlgId,
    _Out_writes_bytes_(HashSize) PBYTE Hash,
    _In_ ULONG HashSize)
{
    BOOLEAN bResult;
    NTSTATUS ntStatus;
    ULONG offset;
    ULONG sizeOfHeaders;
    PVOID pvImage;
    PKDU_CNG_CTX hashContext;

    bResult = FALSE;
    hashContext = NULL;
    sizeOfHeaders = HashpGetSizeOfHeaders(ViewInformation->NtHeaders);
    pvImage = ViewInformation->ViewBase;

    ntStatus = HashpCreateContext(AlgId, &hashContext);
    if (!NT_SUCCESS(ntStatus))
        return FALSE;

    __try {

        offset = 0;

        while (offset < PageSize) {

            if (offset == ViewInformation->ExcludeData.ChecksumOffset)
                offset += RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER, CheckSum);
            else if (offset == ViewInformation->ExcludeData.SecurityOffset)
                offset += sizeof(IMAGE_DATA_DIRECTORY);

            if (offset >= sizeOfHeaders)
                break;

            ntStatus = BCryptHashData(hashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(pvImage, offset),
                sizeof(BYTE),
                0);

            if (!NT_SUCCESS(ntStatus))
                __leave;

            offset += 1;
        }

        if (offset < PageSize) {
            ntStatus = HashpAddPad(PageSize - offset, hashContext);
            if (!NT_SUCCESS(ntStatus))
                __leave;
        }

        ntStatus = BCryptFinishHash(hashContext->HashHandle,
            (PUCHAR)hashContext->Hash,
            hashContext->HashSize,
            0);

        if (NT_SUCCESS(ntStatus) && hashContext->HashSize == HashSize) {
            RtlCopyMemory(Hash, hashContext->Hash, HashSize);
            bResult = TRUE;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        bResult = FALSE;
    }

    HashpDestroyContext(hashContext);
    return bResult;
}

/*
* KDUCalcImageHashes
*
* Purpose:
*
* Calculate hashes for a decompressed PE image in memory.
*
*/
_Success_(return != FALSE)
BOOL KDUCalcImageHashes(
    _In_reads_bytes_(ImageSize) PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKDU_IMAGE_HASH_INFO HashInfo)
{
    KDU_MEMORY_VIEW_INFO viewInfo;
    PIMAGE_DOS_HEADER dosHeader;

    if (ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER) || HashInfo == NULL)
        return FALSE;

    RtlSecureZeroMemory(&viewInfo, sizeof(viewInfo));
    RtlSecureZeroMemory(HashInfo, sizeof(KDU_IMAGE_HASH_INFO));

    viewInfo.ViewBase = ImageBase;
    viewInfo.FileSize = ImageSize;

    __try {

        dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return FALSE;

        viewInfo.NtHeaders = RtlImageNtHeader(ImageBase);
        if (viewInfo.NtHeaders == NULL)
            return FALSE;

        if (!HashpGetExcludeRange(&viewInfo))
            return FALSE;

        HashInfo->FileHashSha1Valid = HashpCalcFileHash(&viewInfo,
            BCRYPT_SHA1_ALGORITHM,
            HashInfo->FileHashSha1,
            sizeof(HashInfo->FileHashSha1));

        HashInfo->AuthenticodeHashSha1Valid = HashpCalcAuthenticodeHash(&viewInfo,
            BCRYPT_SHA1_ALGORITHM,
            HashInfo->AuthenticodeHashSha1,
            sizeof(HashInfo->AuthenticodeHashSha1));

        HashInfo->PageHashSha1Valid = HashpCalcFirstPageHash(PAGE_SIZE,
            &viewInfo,
            BCRYPT_SHA1_ALGORITHM,
            HashInfo->PageHashSha1,
            sizeof(HashInfo->PageHashSha1));

        HashInfo->PageHashSha256Valid = HashpCalcFirstPageHash(PAGE_SIZE,
            &viewInfo,
            BCRYPT_SHA256_ALGORITHM,
            HashInfo->PageHashSha256,
            sizeof(HashInfo->PageHashSha256));

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return TRUE;
}

/*
* KDUPrintHashValue
*
* Purpose:
*
* Print binary hash as hex string.
*
*/
VOID KDUPrintHashValue(
    _In_reads_bytes_(HashSize) PBYTE Hash,
    _In_ ULONG HashSize)
{
    ULONG i;

    for (i = 0; i < HashSize; i++) {
        printf_s("%02X", Hash[i]);
    }
}
