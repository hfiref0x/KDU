/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       SIGCHECK.CPP
*
*  VERSION:     1.49
*
*  DATE:        07 Jun 2026
*
*  In-memory signature parsing support.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "sigcheck.h"

/*
* KDUStringContainsAny
*
* Purpose:
*
* Returns TRUE if String contains any of the provided wide-string patterns.
* Comparison is case-insensitive.
*
*/
BOOL KDUStringContainsAny(
    _In_opt_ LPCWSTR String,
    _In_reads_(NumberOfPatterns) LPCWSTR* Patterns,
    _In_ ULONG NumberOfPatterns
)
{
    ULONG i;

    if (String == NULL || *String == 0 || Patterns == NULL || NumberOfPatterns == 0)
        return FALSE;

    for (i = 0; i < NumberOfPatterns; i++) {
        if (_strstri(String, Patterns[i]) != NULL)
            return TRUE;
    }

    return FALSE;
}

/*
* KDUIsTestCertificateSubject
*
* Purpose:
*
* Returns TRUE if SubjectName identifies a WDK test certificate.
*
*/
BOOL KDUIsTestCertificateSubject(
    _In_opt_ LPCWSTR SubjectName
)
{
    // Test-signed drivers carry this in CN, never trusted on production systems.
    static LPCWSTR TestPatterns[] = {
        L"WDKTestCert"
    };

    return KDUStringContainsAny(SubjectName,
        TestPatterns,
        RTL_NUMBER_OF(TestPatterns));
}

/*
* KDUIsPreferredPublisherSubject
*
* Purpose:
*
* Returns TRUE if SubjectName identifies a Windows Hardware Compatibility
* Publisher, granting it elevated priority during subject selection.
*
*/
BOOL KDUIsPreferredPublisherSubject(
    _In_opt_ LPCWSTR SubjectName
)
{
    // WHCP cross-signed drivers get elevated trust in the selection logic below.
    static LPCWSTR PreferredPatterns[] = {
        L"Microsoft Windows Hardware Compatibility Publisher"
    };

    return KDUStringContainsAny(SubjectName,
        PreferredPatterns,
        RTL_NUMBER_OF(PreferredPatterns));
}

/*
* KDUIsTimestampCertificateSubject
*
* Purpose:
*
* Returns TRUE if SubjectName belongs to a countersigning timestamp authority
* rather than a code signing entity.
*
*/
BOOL KDUIsTimestampCertificateSubject(
    _In_opt_ LPCWSTR SubjectName
)
{
    // Countersigning TSA certs are not code signers; skip as a subject candidate.
    static LPCWSTR TimestampPatterns[] = {
        L"Time-Stamp"
    };

    return KDUStringContainsAny(SubjectName,
        TimestampPatterns,
        RTL_NUMBER_OF(TimestampPatterns));
}

/*
* KDUIsRootOrCaCertificateSubject
*
* Purpose:
*
* Returns TRUE if SubjectName identifies a root or intermediate CA certificate.
* Such subjects are excluded from publisher identity candidates.
*
*/
BOOL KDUIsRootOrCaCertificateSubject(
    _In_opt_ LPCWSTR SubjectName
)
{
    static LPCWSTR RootOrCaPatterns[] = {
        L"Root Certificate Authority",
        L"Third Party Component CA",
        L" PCA ",
        L"Certificate Authority"
    };

    return KDUStringContainsAny(SubjectName,
        RootOrCaPatterns,
        RTL_NUMBER_OF(RootOrCaPatterns));
}

/*
* KDUDuplicateString
*
* Purpose:
*
* Allocate a heap copy of Source. Caller is responsible for freeing
* the returned buffer via supHeapFree.
*
*/
LPWSTR KDUDuplicateString(
    _In_opt_ LPCWSTR Source
)
{
    SIZE_T cchSource = 0;
    LPWSTR duplicate = NULL;

    if (Source == NULL)
        return NULL;

    cchSource = _strlen(Source) + 1;
    duplicate = (LPWSTR)supHeapAlloc(cchSource * sizeof(WCHAR));
    if (duplicate == NULL)
        return NULL;

    RtlCopyMemory(duplicate, Source, cchSource * sizeof(WCHAR));
    return duplicate;
}

/*
* KDUQueryCertificateSubjectName
*
* Purpose:
*
* Retrieve the simple display subject name from a certificate context.
* Caller is responsible for freeing the returned string via supHeapFree.
*
*/
LPWSTR KDUQueryCertificateSubjectName(
    _In_ PCCERT_CONTEXT CertificateContext
)
{
    DWORD cchSubject = 0;
    LPWSTR subjectName = NULL;

    cchSubject = CertGetNameString(CertificateContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        NULL,
        0);

    if (cchSubject == 0)
        return NULL;

    subjectName = (LPWSTR)supHeapAlloc(cchSubject * sizeof(WCHAR));
    if (subjectName == NULL)
        return NULL;

    if (CertGetNameString(CertificateContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        subjectName,
        cchSubject) == 0)
    {
        supHeapFree(subjectName);
        subjectName = NULL;
    }

    return subjectName;
}

/*
* KDUFindSignerCertContext
*
* Purpose:
*
* Locate the leaf certificate context within CertificateStore that matches
* the issuer and serial number recorded in SignerInfo.
*
*/
PCCERT_CONTEXT KDUFindSignerCertContext(
    _In_ HCERTSTORE CertificateStore,
    _In_ PCMSG_SIGNER_INFO SignerInfo
)
{
    CERT_INFO certInfo = { 0 };

    // Issuer + serial uniquely identifies the leaf cert within the embedded store.
    certInfo.Issuer = SignerInfo->Issuer;
    certInfo.SerialNumber = SignerInfo->SerialNumber;

    return CertFindCertificateInStore(CertificateStore,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &certInfo,
        NULL);
}

/*
* KDUQueryPrimarySignerName
*
* Purpose:
*
* Extract the subject name of the primary signer (index 0) from a decoded
* PKCS#7 message. Resolves the signer info to its certificate context within
* CertificateStore before querying the name.
* Caller is responsible for freeing *SignerName via supHeapFree on success.
*
*/
BOOL KDUQueryPrimarySignerName(
    _In_ HCERTSTORE CertificateStore,
    _In_ HCRYPTMSG CryptMessage,
    _Out_ LPWSTR* SignerName
)
{
    BOOL bResult = FALSE;
    DWORD cbSignerInfo = 0;
    PCCERT_CONTEXT certContext = NULL;
    PCMSG_SIGNER_INFO signerInfo = NULL;
    LPWSTR subjectName = NULL;

    *SignerName = NULL;

    do {

        // Size query first, signer index 0 is the primary (outer) signature.
        if (!CryptMsgGetParam(CryptMessage,
            CMSG_SIGNER_INFO_PARAM,
            0,
            NULL,
            &cbSignerInfo))
        {
            break;
        }

        signerInfo = (PCMSG_SIGNER_INFO)supHeapAlloc(cbSignerInfo);
        if (signerInfo == NULL)
            break;

        if (!CryptMsgGetParam(CryptMessage,
            CMSG_SIGNER_INFO_PARAM,
            0,
            signerInfo,
            &cbSignerInfo))
        {
            break;
        }

        certContext = KDUFindSignerCertContext(CertificateStore, signerInfo);
        if (certContext == NULL)
            break;

        subjectName = KDUQueryCertificateSubjectName(certContext);
        if (subjectName == NULL)
            break;

        *SignerName = subjectName;
        subjectName = NULL;
        bResult = TRUE;

    } while (FALSE);

    if (subjectName)
        supHeapFree(subjectName);

    if (certContext)
        CertFreeCertificateContext(certContext);

    if (signerInfo)
        supHeapFree(signerInfo);

    return bResult;
}

/*
* KDUAsn1ReadLength
*
* Purpose:
*
* Parse a BER/DER length field starting at Data[1], supporting both short
* (single-byte) and long (multi-byte) forms. Returns the total header size
* and the encoded value length.
*
*/
BOOL KDUAsn1ReadLength(
    _In_ PBYTE Data,
    _In_ ULONG DataSize,
    _Out_ PULONG HeaderSize,
    _Out_ PULONG ValueSize
)
{
    BYTE first = 0;
    ULONG cbLength = 0, lengthValue = 0, i;

    *HeaderSize = 0;
    *ValueSize = 0;

    if (Data == NULL || DataSize < 2)
        return FALSE;

    first = Data[1];

    // Short form: high bit clear, lower 7 bits are the length directly.
    if ((first & 0x80) == 0) {
        *HeaderSize = 2;
        *ValueSize = first;
        return (*HeaderSize + *ValueSize <= DataSize);
    }

    // Long form: lower 7 bits of first byte encode how many octets follow for the length.
    cbLength = first & 0x7F;
    cbLength = first & 0x7F;
    if (cbLength == 0 || cbLength > sizeof(ULONG))
        return FALSE;

    if (2 + cbLength > DataSize)
        return FALSE;

    for (i = 0; i < cbLength; i++) {
        lengthValue <<= 8;
        lengthValue |= Data[2 + i];
    }

    *HeaderSize = 2 + cbLength;
    *ValueSize = lengthValue;

    return (*HeaderSize + *ValueSize <= DataSize);
}

/*
* KDUUpdateBestSubjectCandidate
*
* Purpose:
*
* Slot SubjectName into the highest available priority bucket:
* PreferredSubject for WHCP publishers, GeneralSubject for ordinary leaf
* certs, timestamp, and CA certificates.
* Only the first candidate per bucket is retained.
*
*/
VOID KDUUpdateBestSubjectCandidate(
    _In_ LPCWSTR SubjectName,
    _Inout_ LPWSTR* PreferredSubject,
    _Inout_ LPWSTR* GeneralSubject
)
{
    LPWSTR copy = NULL;

    if (SubjectName == NULL || *SubjectName == 0)
        return;

    copy = KDUDuplicateString(SubjectName);
    if (copy == NULL)
        return;

    // Priority: WHCP publisher > any non-noise leaf > timestamps/roots/test certs.
    // Only the first match per tier is kept; subsequent finds are discarded.
    if (KDUIsPreferredPublisherSubject(copy)) {
        if (*PreferredSubject == NULL) {
            *PreferredSubject = copy;
            return;
        }
    }
    else if (!KDUIsTestCertificateSubject(copy) &&
        !KDUIsTimestampCertificateSubject(copy) &&
        !KDUIsRootOrCaCertificateSubject(copy))
    {
        if (*GeneralSubject == NULL) {
            *GeneralSubject = copy;
            return;
        }
    }

    supHeapFree(copy);
}

/*
* KDUEnumerateEmbeddedCertSubjectsRaw
*
* Purpose:
*
* Scan a raw PKCS#7 blob for embedded X.509 certificates by walking
* ASN.1 SEQUENCE tags and attempting to construct a certificate context
* at each candidate offset. 
*
*/
VOID KDUEnumerateEmbeddedCertSubjectsRaw(
    _In_reads_bytes_(BlobSize) PBYTE Blob,
    _In_ ULONG BlobSize,
    _Out_ LPWSTR* PreferredSubject,
    _Out_ LPWSTR* GeneralSubject
)
{
    ULONG i = 0, headerSize = 0, valueSize = 0, totalSize = 0;
    PCCERT_CONTEXT certContext = NULL;
    LPWSTR subjectName = NULL;

    *PreferredSubject = NULL;
    *GeneralSubject = NULL;

    while (i + 2 < BlobSize) {

        // 0x30 is the ASN.1 SEQUENCE tag, all X.509 certificates start with one.
        if (Blob[i] != 0x30) {
            i++;
            continue;
        }

        if (!KDUAsn1ReadLength(&Blob[i],
            BlobSize - i,
            &headerSize,
            &valueSize))
        {
            i++;
            continue;
        }

        totalSize = headerSize + valueSize;
        // Certificates below 256 bytes cannot carry a meaningful subject.
        if (totalSize < 0x100) {
            i++;
            continue;
        }

        certContext = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &Blob[i],
            totalSize);

        if (certContext) {

            subjectName = KDUQueryCertificateSubjectName(certContext);
            if (subjectName) {
                KDUUpdateBestSubjectCandidate(subjectName,
                    PreferredSubject,
                    GeneralSubject);

                supHeapFree(subjectName);
                subjectName = NULL;
            }

            CertFreeCertificateContext(certContext);
            certContext = NULL;

            // Preferred candidate found.
            if (*PreferredSubject != NULL)
                return;
        }

        i++;
    }
}

/*
* KDUQueryImageSignInfo
*
* Purpose:
*
* Query embedded signature information from PE image in memory.
*
*/
_Success_(return != FALSE)
BOOL KDUQueryImageSignInfo(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKDU_SIGN_INFO SignInfo)
{
    BOOL bResult = FALSE;
    DWORD certBlobSize = 0;
    PBYTE certBlob = NULL;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    LPWSTR signerName = NULL, preferredSubject = NULL;
    LPWSTR generalSubject = NULL, selectedSubject = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY secDir = NULL;
    LPWIN_CERTIFICATE winCert = NULL;

    if (SignInfo == NULL || ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    SignInfo->State = KduSignInfoUnavailable;
    SignInfo->SignerName = NULL;

    do {

        ntHeaders = RtlImageNtHeader(ImageBase);
        if (ntHeaders == NULL)
            break;

        switch (ntHeaders->OptionalHeader.Magic) {
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            secDir = &((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            break;
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            secDir = &((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            break;
        default:
            break;
        }

        if (secDir == NULL)
            break;

        if (secDir->VirtualAddress == 0 || secDir->Size < sizeof(WIN_CERTIFICATE))
            break;

        // Security directory RVA is a raw file offset, not a virtual address.
        if (secDir->VirtualAddress >= ImageSize ||
            secDir->Size > (ImageSize - secDir->VirtualAddress))
        {
            break;
        }

        winCert = (LPWIN_CERTIFICATE)RtlOffsetToPointer(ImageBase, secDir->VirtualAddress);

        if (winCert->dwLength < sizeof(WIN_CERTIFICATE) ||
            winCert->dwLength > secDir->Size)
        {
            break;
        }

        // Only PKCS#7 signatures are handled, skip catalog-based or other types.
        if (winCert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
            break;

        certBlob = (PBYTE)winCert->bCertificate;
        certBlobSize = winCert->dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);

        hMsg = CryptMsgOpenToDecode(
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            0,
            0,
            NULL,
            NULL);

        if (hMsg == NULL)
            break;

        if (!CryptMsgUpdate(hMsg, certBlob, certBlobSize, TRUE))
            break;

        // Build an in-memory cert store from the message to enable cert lookups.
        hStore = CertOpenStore(CERT_STORE_PROV_MSG,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            0,
            hMsg);

        if (hStore == NULL)
            break;

        if (!KDUQueryPrimarySignerName(hStore, hMsg, &signerName))
            break;

        if (!KDUIsTestCertificateSubject(signerName)) {
            selectedSubject = signerName;
            signerName = NULL;
        }
        else {
            // WDK test cert as the primary signer: walk the raw blob to recover
            // the real publisher from the embedded certificate chain.
            KDUEnumerateEmbeddedCertSubjectsRaw(certBlob,
                certBlobSize,
                &preferredSubject,
                &generalSubject);

            if (preferredSubject) {
                selectedSubject = preferredSubject;
                preferredSubject = NULL;
            }
            else if (generalSubject) {
                selectedSubject = generalSubject;
                generalSubject = NULL;
            }
            else {
                selectedSubject = signerName;
                signerName = NULL;
            }
        }

        if (selectedSubject == NULL)
            break;

        SignInfo->SignerName = selectedSubject;
        selectedSubject = NULL;
        SignInfo->State = KduSignInfoSigned;
        bResult = TRUE;

    } while (FALSE);

    if (selectedSubject)
        supHeapFree(selectedSubject);
    if (generalSubject)
        supHeapFree(generalSubject);
    if (preferredSubject)
        supHeapFree(preferredSubject);
    if (signerName)
        supHeapFree(signerName);
    if (hStore)
        CertCloseStore(hStore, 0);
    if (hMsg)
        CryptMsgClose(hMsg);

    return bResult;
}

/*
* KDUFreeImageSignInfo
*
* Purpose:
*
* Release image signature information resources.
*
*/
VOID KDUFreeImageSignInfo(
    _In_ PKDU_SIGN_INFO SignInfo)
{
    if (SignInfo == NULL)
        return;

    if (SignInfo->SignerName) {
        supHeapFree(SignInfo->SignerName);
        SignInfo->SignerName = NULL;
    }

    SignInfo->State = KduSignInfoUnavailable;
}
