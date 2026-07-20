/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       PROVLIST.CPP
*
*  VERSION:     1.50
*
*  DATE:        19 Jul 2026
*
*  Provider list output support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "provlist.h"
#include "hash.h"
#include "sigcheck.h"

typedef struct _KDU_CSV_OUTPUT {
    HANDLE FileHandle;
    BOOL UseStdOut;
} KDU_CSV_OUTPUT, * PKDU_CSV_OUTPUT;

typedef struct _KDU_PROV_FLAG_DESC {
    ULONG Mask;
    LPCSTR Text;
} KDU_PROV_FLAG_DESC, * PKDU_PROV_FLAG_DESC;

static const KDU_PROV_FLAG_DESC g_KduProvFlagDescs[] = {
    { KDUPROV_FLAGS_SIGNATURE_WHQL,        "\t\t->Driver is WHQL signed.\r\n" },
    { KDUPROV_FLAGS_IGNORE_CHECKSUM,       "\t\t->Ignore invalid image checksum.\r\n" },
    { KDUPROV_FLAGS_NO_UNLOAD_SUP,         "\t\t->Driver does not support unload procedure.\r\n" },
    { KDUPROV_FLAG_ROOT_FROM_LOWSTUB,     "\t\t->Virtual to physical address translation requires CR3 query from low stub.\r\n" },
    { KDUPROV_FLAGS_NO_VICTIM,             "\t\t->No victim required.\r\n" },
    { KDUPROV_FLAGS_PHYSICAL_BRUTE_FORCE,  "\t\t->Provider supports only physical memory brute-force.\r\n" },
    { KDUPROV_FLAGS_PREFER_PHYSICAL,       "\t\t->Physical memory access is preferred.\r\n" },
    { KDUPROV_FLAGS_PREFER_VIRTUAL,        "\t\t->Virtual memory access is preferred.\r\n" },
    { KDUPROV_FLAGS_COMPANION_REQUIRED,    "\t\t->Provider expects companion to be loaded.\r\n" },
    { KDUPROV_FLAGS_USE_SYMBOLS,           "\t\t->MS symbols are required to query internal information.\r\n" },
    { KDUPROV_FLAGS_OPENPROCESS_SUPPORTED, "\t\t->Driver can be used to open a handle for the specified process.\r\n" },
    { KDUPROV_FLAGS_FS_FILTER,             "\t\t->Driver is file system filter.\r\n" },
    { KDUPROV_FLAGS_USE_SUPERFETCH,        "\t\t->Driver can be used with Superfetch for memory translation.\r\n" }
};

BOOL KDUProvWriteConsoleWide(
    _In_opt_ LPCWSTR Text
)
{
    BOOL bResult;
    DWORD charsWritten;
    DWORD bytesWritten = 0;
    HANDLE hOutput;
    DWORD fileType;
    INT cbUtf8;
    PCHAR utf8Buffer;
    SIZE_T cchText;

    if (Text == NULL)
        return TRUE;

    hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOutput == NULL || hOutput == INVALID_HANDLE_VALUE)
        return FALSE;

    cchText = _strlen(Text);
    if (cchText == 0)
        return TRUE;

    fileType = GetFileType(hOutput);
    if (fileType == FILE_TYPE_CHAR) {
        return WriteConsole(hOutput,
            Text,
            (DWORD)cchText,
            &charsWritten,
            NULL);
    }

    cbUtf8 = WideCharToMultiByte(CP_UTF8,
        0,
        Text,
        (INT)cchText,
        NULL,
        0,
        NULL,
        NULL);

    if (cbUtf8 <= 0)
        return FALSE;

    utf8Buffer = (PCHAR)supHeapAlloc(cbUtf8);
    if (utf8Buffer == NULL)
        return FALSE;

    bResult = FALSE;

    if (WideCharToMultiByte(CP_UTF8,
        0,
        Text,
        (INT)cchText,
        utf8Buffer,
        cbUtf8,
        NULL,
        NULL) == cbUtf8)
    {
        bResult = WriteFile(hOutput,
            utf8Buffer,
            cbUtf8,
            &bytesWritten,
            NULL) && (bytesWritten == (DWORD)cbUtf8);
    }

    supHeapFree(utf8Buffer);
    return bResult;
}

/*
* KDUProvDumpCapabilities
*
* Purpose:
*
* Output provider capabilities as text.
*
*/
VOID KDUProvDumpCapabilities(
    _In_ KDU_DB_ENTRY* Entry
)
{
    ULONG i;

    if (Entry->Flags == KDUPROV_FLAGS_NONE)
        return;

    printf_s("\tProvider capabilities: \r\n");

    for (i = 0; i < RTL_NUMBER_OF(g_KduProvFlagDescs); i++) {
        if (Entry->Flags & g_KduProvFlagDescs[i].Mask) {
            printf_s("%s", g_KduProvFlagDescs[i].Text);
        }
    }
}

/*
* KDUProvSourceBaseToString
*
* Purpose:
*
* Convert source base enum to text.
*
*/
LPCSTR KDUProvSourceBaseToString(
    _In_ KDU_SOURCEBASE SourceBase
)
{
    switch (SourceBase) {
    case SourceBaseWinIo:
        return "WinIo";
    case SourceBaseWinRing0:
        return "WinRing0";
    case SourceBasePhyMem:
        return "PhyMem";
    case SourceBaseMapMem:
        return "MapMem";
    case SourceBaseRWEverything:
        return "RWEverything";
    case SourceBaseNone:
    default:
        return "None";
    }
}

/*
* KDUProvFormatHex
*
* Purpose:
*
* Format binary buffer as hex string.
*
*/
VOID KDUProvFormatHex(
    _In_ PBYTE Data,
    _In_ ULONG DataSize,
    _Out_writes_bytes_(OutputBufferChars) PCHAR OutputBuffer,
    _In_ ULONG OutputBufferChars
)
{
    ULONG i;
    ULONG cchRequired;

    if (OutputBuffer == NULL || OutputBufferChars == 0)
        return;

    OutputBuffer[0] = 0;

    if (Data == NULL || DataSize == 0)
        return;

    cchRequired = (DataSize * 2) + 1;
    if (OutputBufferChars < cchRequired)
        return;

    for (i = 0; i < DataSize; i++) {
        _snprintf_s(&OutputBuffer[i * 2],
            OutputBufferChars - (i * 2),
            _TRUNCATE,
            "%02X",
            Data[i]);
    }
}

/*
* KDUProvCsvWriteA
*
* Purpose:
*
* Write ANSI/UTF-8 bytes to output.
*
*/
BOOL KDUProvCsvWriteA(
    _In_ PKDU_CSV_OUTPUT Output,
    _In_ LPCSTR Text,
    _In_ ULONG Length
)
{
    DWORD bytesWritten;

    if (Output->UseStdOut) {
        return (printf_s("%.*s", Length, Text) >= 0);
    }

    bytesWritten = 0;
    return WriteFile(Output->FileHandle,
        Text,
        Length,
        &bytesWritten,
        NULL) && (bytesWritten == Length);
}

/*
* KDUProvCsvWriteStringA
*
* Purpose:
*
* Write null-terminated ANSI string.
*
*/
BOOL KDUProvCsvWriteStringA(
    _In_ PKDU_CSV_OUTPUT Output,
    _In_opt_ LPCSTR Text
)
{
    SIZE_T length;

    if (Text == NULL)
        return TRUE;

    length = _strlen_a(Text);
    if (length == 0)
        return TRUE;

    return KDUProvCsvWriteA(Output, Text, (ULONG)length);
}

/*
* KDUProvCsvWriteW
*
* Purpose:
*
* Write wide string as UTF-8.
*
*/
BOOL KDUProvCsvWriteW(
    _In_ PKDU_CSV_OUTPUT Output,
    _In_ LPCWSTR Text,
    _In_ ULONG Length
)
{
    BOOL bResult = FALSE;
    INT cbUtf8;
    PCHAR utf8Buffer;

    if (Length == 0)
        return TRUE;

    cbUtf8 = WideCharToMultiByte(CP_UTF8,
        0,
        Text,
        Length,
        NULL,
        0,
        NULL,
        NULL);

    if (cbUtf8 <= 0)
        return FALSE;

    utf8Buffer = (PCHAR)supHeapAlloc(cbUtf8);
    if (utf8Buffer == NULL)
        return FALSE;

    if (WideCharToMultiByte(CP_UTF8,
        0,
        Text,
        Length,
        utf8Buffer,
        cbUtf8,
        NULL,
        NULL) == cbUtf8)
    {
        bResult = KDUProvCsvWriteA(Output, utf8Buffer, (ULONG)cbUtf8);
    }

    supHeapFree(utf8Buffer);
    return bResult;
}

/*
* KDUProvCsvWriteCsvStringW
*
* Purpose:
*
* Write quoted CSV wide string.
*
*/
BOOL KDUProvCsvWriteCsvStringW(
    _In_ PKDU_CSV_OUTPUT Output,
    _In_opt_ LPCWSTR String
)
{
    WCHAR ch;
    LPCWSTR ptr;

    if (!KDUProvCsvWriteStringA(Output, "\""))
        return FALSE;

    if (String) {
        ptr = String;
        while ((ch = *ptr++) != 0) {
            if (ch == L'"') {
                if (!KDUProvCsvWriteStringA(Output, "\"\""))
                    return FALSE;
            }
            else {
                if (!KDUProvCsvWriteW(Output, &ch, 1))
                    return FALSE;
            }
        }
    }

    return KDUProvCsvWriteStringA(Output, "\"");
}

/*
* KDUProvCsvWriteCsvStringA
*
* Purpose:
*
* Write quoted CSV ANSI string.
*
*/
BOOL KDUProvCsvWriteCsvStringA(
    _In_ PKDU_CSV_OUTPUT Output,
    _In_opt_ LPCSTR String
)
{
    CHAR ch;
    LPCSTR ptr;

    if (!KDUProvCsvWriteStringA(Output, "\""))
        return FALSE;

    if (String) {
        ptr = String;
        while ((ch = *ptr++) != 0) {
            if (ch == '"') {
                if (!KDUProvCsvWriteStringA(Output, "\"\""))
                    return FALSE;
            }
            else {
                if (!KDUProvCsvWriteA(Output, &ch, 1))
                    return FALSE;
            }
        }
    }

    return KDUProvCsvWriteStringA(Output, "\"");
}

/*
* KDUProvCsvWriteLineA
*
* Purpose:
*
* Write text and CRLF.
*
*/
BOOL KDUProvCsvWriteLineA(
    _In_ PKDU_CSV_OUTPUT Output,
    _In_opt_ LPCSTR Text
)
{
    if (Text) {
        if (!KDUProvCsvWriteStringA(Output, Text))
            return FALSE;
    }

    return KDUProvCsvWriteStringA(Output, "\r\n");
}

/*
* KDUProvList
*
* Purpose:
*
* Output available providers.
*
*/
VOID KDUProvList()
{
    KDU_DB_ENTRY* provData;
    CONST CHAR* pszDesc;
    HINSTANCE hProv;
    PKDU_DB provTable;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    hProv = KDUProviderLoadDB();
    if (hProv == NULL)
        return;

    provTable = KDUReferenceLoadDB();

    for (ULONG i = 0; i < provTable->NumberOfEntries; i++) {

        ULONG resourceSize;
        PBYTE drvBuffer;
        KDU_IMAGE_HASH_INFO hashInfo;
        KDU_SIGN_INFO signInfo;

        provData = &provTable->Entries[i];
        resourceSize = 0;
        drvBuffer = NULL;

        RtlSecureZeroMemory(&hashInfo, sizeof(hashInfo));
        RtlSecureZeroMemory(&signInfo, sizeof(signInfo));

        printf_s("Provider # %lu, ResourceId # %lu\r\n\t%ws, DriverName \"%ws\", DeviceName \"%ws\"\r\n",
            provData->ProviderId,
            provData->ResourceId,
            provData->Description,
            provData->DriverName,
            provData->DeviceName);

        //
        // MITRE CVE advisory id if present.
        //
        if (provData->AdvisoryId) {
            printf_s("\tAdvisory: \"%ws\"\r\n",
                provData->AdvisoryId);
        }

        //
        // Show image size, hashes and signer.
        //
        drvBuffer = (PBYTE)KDULoadResource(provData->ResourceId,
            hProv,
            &resourceSize,
            PROVIDER_RES_KEY,
            provData->IgnoreChecksum ? FALSE : TRUE);

        if (drvBuffer) {

            KDUCalcImageHashes(drvBuffer, resourceSize, &hashInfo);
            KDUQueryImageSignInfo(drvBuffer, resourceSize, &signInfo);

            KDUProvWriteConsoleWide(L"\tSigner: \"");
            KDUProvWriteConsoleWide(signInfo.SignerName ? signInfo.SignerName : L"Unavailable");
            KDUProvWriteConsoleWide(L"\"\r\n");

            printf_s("\tImage size: %lu bytes\r\n", resourceSize);

            if (hashInfo.FileHashSha1Valid) {
                printf_s("\tFile hash (SHA1): ");
                KDUPrintHashValue(hashInfo.FileHashSha1, sizeof(hashInfo.FileHashSha1));
                printf_s("\r\n");
            }

            if (hashInfo.AuthenticodeHashSha1Valid) {
                printf_s("\tAuthenticode hash (SHA1): ");
                KDUPrintHashValue(hashInfo.AuthenticodeHashSha1, sizeof(hashInfo.AuthenticodeHashSha1));
                printf_s("\r\n");
            }

            if (hashInfo.PageHashSha1Valid) {
                printf_s("\tPage hash (SHA1): ");
                KDUPrintHashValue(hashInfo.PageHashSha1, sizeof(hashInfo.PageHashSha1));
                printf_s("\r\n");
            }

            if (hashInfo.PageHashSha256Valid) {
                printf_s("\tPage hash (SHA256): ");
                KDUPrintHashValue(hashInfo.PageHashSha256, sizeof(hashInfo.PageHashSha256));
                printf_s("\r\n");
            }

            supHeapFree(drvBuffer);
            KDUFreeImageSignInfo(&signInfo);

        }
        else {
            printf_s("\tSigned by: \"Unavailable\"\r\n");
            printf_s("\tImage size: unavailable\r\n");
            printf_s("\tHashes: resource load failed\r\n");
        }

        printf_s("\tShellcode support mask: 0x%08x\r\n", provData->SupportedShellFlags);

        //
        // List provider flags.
        //
        KDUProvDumpCapabilities(provData);

        //
        // List "based" flags.
        //
        if (provData->DrvSourceBase != SourceBaseNone)
        {
            switch (provData->DrvSourceBase) {
            case SourceBaseWinIo:
                pszDesc = WINIO_BASE_DESC;
                break;
            case SourceBaseWinRing0:
                pszDesc = WINRING0_BASE_DESC;
                break;
            case SourceBasePhyMem:
                pszDesc = PHYMEM_BASE_DESC;
                break;
            case SourceBaseMapMem:
                pszDesc = MAPMEM_BASE_DESC;
                break;
            case SourceBaseRWEverything:
                pszDesc = RWEVERYTHING_BASE_DESC;
                break;
            default:
                pszDesc = "Unknown";
                break;
            }

            printf_s("\tBased on: %s\r\n", pszDesc);
        }

        //
        // Minimum/Maximum support Windows build.
        //
        printf_s("\tMinimum supported Windows build: %lu\r\n",
            provData->MinNtBuildNumberSupport);

        if (provData->MaxNtBuildNumberSupport == KDU_MAX_NTBUILDNUMBER) {
            printf_s("\tMaximum Windows build undefined, no restrictions\r\n");
        }
        else {
            printf_s("\tMaximum supported Windows build: %lu\r\n",
                provData->MaxNtBuildNumberSupport);
        }

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
}

/*
* KDUProvListCsv
*
* Purpose:
*
* Output available providers in CSV format to stdout or file.
*
*/
BOOL KDUProvListCsv(
    _In_opt_ LPCWSTR OutputFileName
)
{
    BOOL bResult = FALSE;
    KDU_DB_ENTRY* provData;
    PKDU_DB provTable;
    HINSTANCE hProv;
    ULONG i;
    KDU_CSV_OUTPUT csvOutput;
    BYTE utf8Bom[] = { 0xEF, 0xBB, 0xBF };

    FUNCTION_ENTER_MSG(__FUNCTION__);

    RtlSecureZeroMemory(&csvOutput, sizeof(csvOutput));
    csvOutput.UseStdOut = (OutputFileName == NULL);
    csvOutput.FileHandle = NULL;

    do {

        if (!csvOutput.UseStdOut) {
            csvOutput.FileHandle = CreateFile(OutputFileName,
                GENERIC_WRITE,
                FILE_SHARE_READ,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            if (csvOutput.FileHandle == INVALID_HANDLE_VALUE) {
                csvOutput.FileHandle = NULL;
                break;
            }

#pragma warning(push)
#pragma warning(disable:6054)
            if (!KDUProvCsvWriteA(&csvOutput, (LPCSTR)utf8Bom, sizeof(utf8Bom))) {
                break;
            }
        }
#pragma warning(pop)

        hProv = KDUProviderLoadDB();
        if (hProv == NULL)
            break;

        provTable = KDUReferenceLoadDB();
        if (provTable == NULL)
            break;

        if (!KDUProvCsvWriteLineA(&csvOutput,
            "ProviderId,ResourceId,DriverName,DeviceName,Description,AdvisoryId,SignerName,SourceBase,MinNtBuild,MaxNtBuild,Flags,ShellcodeMask,ImageSize,FileSHA1,AuthenticodeSHA1,PageHashSHA1,PageHashSHA256"))
        {
            break;
        }

        bResult = TRUE;

        for (i = 0; i < provTable->NumberOfEntries; i++) {

            BOOL rowResult = FALSE;
            ULONG resourceSize;
            PBYTE drvBuffer;
            KDU_IMAGE_HASH_INFO hashInfo;
            KDU_SIGN_INFO signInfo;
            CHAR rowBuffer[512] = { 0 };
            CHAR fileHash[41] = { 0 };
            CHAR authHash[41] = { 0 };
            CHAR pageHash1[41] = { 0 };
            CHAR pageHash256[65] = { 0 };

            provData = &provTable->Entries[i];
            resourceSize = 0;
            drvBuffer = NULL;

            RtlSecureZeroMemory(&hashInfo, sizeof(hashInfo));
            RtlSecureZeroMemory(&signInfo, sizeof(signInfo));

            do {

                drvBuffer = (PBYTE)KDULoadResource(provData->ResourceId,
                    hProv,
                    &resourceSize,
                    PROVIDER_RES_KEY,
                    provData->IgnoreChecksum ? FALSE : TRUE);

                if (drvBuffer) {
                    KDUCalcImageHashes(drvBuffer, resourceSize, &hashInfo);
                    KDUQueryImageSignInfo(drvBuffer, resourceSize, &signInfo);

                    if (hashInfo.FileHashSha1Valid) {
                        KDUProvFormatHex(hashInfo.FileHashSha1,
                            sizeof(hashInfo.FileHashSha1),
                            fileHash,
                            sizeof(fileHash));
                    }

                    if (hashInfo.AuthenticodeHashSha1Valid) {
                        KDUProvFormatHex(hashInfo.AuthenticodeHashSha1,
                            sizeof(hashInfo.AuthenticodeHashSha1),
                            authHash,
                            sizeof(authHash));
                    }

                    if (hashInfo.PageHashSha1Valid) {
                        KDUProvFormatHex(hashInfo.PageHashSha1,
                            sizeof(hashInfo.PageHashSha1),
                            pageHash1,
                            sizeof(pageHash1));
                    }

                    if (hashInfo.PageHashSha256Valid) {
                        KDUProvFormatHex(hashInfo.PageHashSha256,
                            sizeof(hashInfo.PageHashSha256),
                            pageHash256,
                            sizeof(pageHash256));
                    }
                }

                _snprintf_s(rowBuffer,
                    sizeof(rowBuffer),
                    _TRUNCATE,
                    "%lu,%lu,",
                    provData->ProviderId,
                    provData->ResourceId);

                if (!KDUProvCsvWriteStringA(&csvOutput, rowBuffer)) 
                    break;
                if (!KDUProvCsvWriteCsvStringW(&csvOutput, provData->DriverName)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringW(&csvOutput, provData->DeviceName)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringW(&csvOutput, provData->Description)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringW(&csvOutput, provData->AdvisoryId)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringW(&csvOutput, signInfo.SignerName)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringA(&csvOutput, KDUProvSourceBaseToString(provData->DrvSourceBase))) 
                    break;

                if (provData->MaxNtBuildNumberSupport == KDU_MAX_NTBUILDNUMBER) {

                    _snprintf_s(rowBuffer,
                        sizeof(rowBuffer),
                        _TRUNCATE,
                        ",%lu,ANY,0x%08lx,0x%08lx,%lu,",
                        provData->MinNtBuildNumberSupport,
                        provData->Flags,
                        provData->SupportedShellFlags,
                        resourceSize);

                }
                else {

                    _snprintf_s(rowBuffer,
                        sizeof(rowBuffer),
                        _TRUNCATE,
                        ",%lu,%lu,0x%08lx,0x%08lx,%lu,",
                        provData->MinNtBuildNumberSupport,
                        provData->MaxNtBuildNumberSupport,
                        provData->Flags,
                        provData->SupportedShellFlags,
                        resourceSize);

                }

                if (!KDUProvCsvWriteStringA(&csvOutput, rowBuffer)) 
                    break;
                if (!KDUProvCsvWriteCsvStringA(&csvOutput, fileHash)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringA(&csvOutput, authHash)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringA(&csvOutput, pageHash1)) 
                    break;
                if (!KDUProvCsvWriteStringA(&csvOutput, ",")) 
                    break;
                if (!KDUProvCsvWriteCsvStringA(&csvOutput, pageHash256)) 
                    break;
                if (!KDUProvCsvWriteLineA(&csvOutput, NULL)) 
                    break;

                rowResult = TRUE;

            } while (FALSE);

            if (drvBuffer)
                supHeapFree(drvBuffer);

            KDUFreeImageSignInfo(&signInfo);

            if (!rowResult) {
                bResult = FALSE;
                break;
            }
        }

    } while (FALSE);

    if (!csvOutput.UseStdOut && csvOutput.FileHandle) {
        CloseHandle(csvOutput.FileHandle);
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bResult;
}
