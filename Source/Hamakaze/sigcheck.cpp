/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       SIGCHECK.CPP
*
*  VERSION:     1.49
*
*  DATE:        06 Jun 2026
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
* KDUQueryImageSignInfo
*
* Purpose:
*
* Query embedded signature information from PE image in memory.
*
*/
_Success_(return != FALSE)
BOOL KDUQueryImageSignInfo(
    _In_reads_bytes_(ImageSize) PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKDU_SIGN_INFO SignInfo)
{
    BOOL bResult = FALSE;
    DWORD cbSignerInfo = 0;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    CERT_INFO certInfo;
    DWORD cchSubject;
    LPWSTR signerName;

    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_DATA_DIRECTORY secDir;
    LPWIN_CERTIFICATE winCert;
    PBYTE certBlob;
    DWORD certBlobSize;

    if (SignInfo == NULL || ImageBase == NULL || ImageSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    RtlSecureZeroMemory(SignInfo, sizeof(KDU_SIGN_INFO));
    SignInfo->State = KduSignInfoUnavailable;

    signerName = NULL;

    __try {

        ntHeaders = RtlImageNtHeader(ImageBase);
        if (ntHeaders == NULL)
            return FALSE;

        switch (ntHeaders->OptionalHeader.Magic) {
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            secDir = &((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            break;
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            secDir = &((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            break;
        default:
            return FALSE;
        }

        //
        // IMAGE_DIRECTORY_ENTRY_SECURITY.VirtualAddress is file offset.
        //
        if (secDir->VirtualAddress == 0 || secDir->Size < sizeof(WIN_CERTIFICATE)) {
            __leave;
        }

        if (secDir->VirtualAddress >= ImageSize ||
            secDir->Size > (ImageSize - secDir->VirtualAddress))
        {
            __leave;
        }

        winCert = (LPWIN_CERTIFICATE)RtlOffsetToPointer(ImageBase, secDir->VirtualAddress);

        if (winCert->dwLength < sizeof(WIN_CERTIFICATE) ||
            winCert->dwLength > secDir->Size)
        {
            __leave;
        }

        if (winCert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
            __leave;

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
            __leave;

        if (!CryptMsgUpdate(hMsg, certBlob, certBlobSize, TRUE))
            __leave;

        if (!CryptMsgGetParam(hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            NULL,
            &cbSignerInfo))
        {
            __leave;
        }

        pSignerInfo = (PCMSG_SIGNER_INFO)supHeapAlloc(cbSignerInfo);
        if (pSignerInfo == NULL)
            __leave;

        if (!CryptMsgGetParam(hMsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            pSignerInfo,
            &cbSignerInfo))
        {
            __leave;
        }

        hStore = CertOpenStore(CERT_STORE_PROV_MSG,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            0,
            hMsg);

        if (hStore == NULL)
            __leave;

        certInfo.Issuer = pSignerInfo->Issuer;
        certInfo.SerialNumber = pSignerInfo->SerialNumber;

        pCertContext = CertFindCertificateInStore(hStore,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            &certInfo,
            NULL);

        if (pCertContext == NULL)
            __leave;

        cchSubject = CertGetNameString(pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            NULL,
            0);

        if (cchSubject == 0)
            __leave;

        signerName = (LPWSTR)supHeapAlloc(cchSubject * sizeof(WCHAR));
        if (signerName == NULL)
            __leave;

        if (CertGetNameString(pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            signerName,
            cchSubject) == 0)
        {
            supHeapFree(signerName);
            signerName = NULL;
            __leave;
        }

        SignInfo->SignerName = signerName;
        SignInfo->State = KduSignInfoSigned;
        bResult = TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        bResult = FALSE;
    }

    if (pCertContext)
        CertFreeCertificateContext(pCertContext);

    if (pSignerInfo)
        supHeapFree(pSignerInfo);

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
