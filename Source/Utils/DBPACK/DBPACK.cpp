/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       DBPACK.CPP
*
*  VERSION:     1.06
*
*  DATE:        08 Nov 2026
*
*  DBPACK - KDU's Provider Database packager.
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
#include "../../Shared/minirtl/minirtl.h"
#include "../../Shared/minirtl/cmdline.h"
#include "../../Shared/minirtl/_filename.h"
#include "../../Shared/kdubase.h"
}
#endif

__declspec(thread) static PACK_ITEM g_Items[MAX_PACK_ITEMS];
__declspec(thread) static RESOURCE_DB_ENTRY g_Entries[MAX_PACK_ITEMS];
__declspec(thread) static BYTE g_CopyBuffer[65536];

BOOL StringToDword(
    LPCSTR String,
    DWORD* Value
)
{
    DWORD Result = 0;

    if (!String || !*String || !Value)
        return FALSE;

    while (*String) {

        CHAR Ch = *String++;
        DWORD Digit;

        if (Ch < '0' || Ch > '9')
            return FALSE;

        Digit = (DWORD)(Ch - '0');

        if (Result > (MAXDWORD - Digit) / 10)
            return FALSE;

        Result = Result * 10 + Digit;
    }

    *Value = Result;
    return TRUE;
}

BOOL ParseManifestLine(
    LPSTR Line,
    PACK_ITEM* Item
)
{
    LPSTR Equal;
    LPSTR Quote1;
    LPSTR Quote2;

    DWORD Id;

    Equal = Line;

    while (*Equal && *Equal != '=')
        Equal++;

    if (*Equal != '=')
        return FALSE;

    *Equal = 0;

    if (!StringToDword(Line, &Id))
        return FALSE;

    Quote1 = Equal + 1;

    if (*Quote1 != '"')
        return FALSE;

    Quote1++;

    Quote2 = Quote1;

    while (*Quote2 && *Quote2 != '"')
        Quote2++;

    if (*Quote2 != '"')
        return FALSE;

    *Quote2 = 0;

    if (FAILED(StringCchCopyA(
        Item->Path,
        ARRAYSIZE(Item->Path),
        Quote1)))
    {
        return FALSE;
    }

    Item->Id = Id;

    return TRUE;
}

BOOL LoadManifest(
    LPCSTR FileName,
    PACK_ITEM* Items,
    DWORD* CountOut
)
{
    DWORD Count = 0;
    DWORD FileSize, FileSizeHigh;
    DWORD ReadBytes, TotalRead;
    LPSTR Buffer, Current;
    HANDLE hFile;

    hFile = CreateFileA(
        FileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    FileSize = GetFileSize(hFile, &FileSizeHigh);
    if (FileSize == INVALID_FILE_SIZE || FileSizeHigh != 0 || FileSize >= 0x7FFFFFFF) {
        CloseHandle(hFile);
        return FALSE;
    }

    Buffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize + 1);
    if (!Buffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    TotalRead = 0;
    while (TotalRead < FileSize) {
        if (!ReadFile(hFile, Buffer + TotalRead,
            FileSize - TotalRead, &ReadBytes, NULL) ||
            ReadBytes == 0)
        {
            HeapFree(GetProcessHeap(), 0, Buffer);
            CloseHandle(hFile);
            return FALSE;
        }
        TotalRead += ReadBytes;
    }

    CloseHandle(hFile);
    Buffer[FileSize] = 0;

    Current = Buffer;
    while (*Current) {

        LPSTR End;

        End = Current;

        while (*End &&
            *End != '\r' &&
            *End != '\n')
        {
            End++;
        }

        if (*End) {
            *End = 0;
            End++;

            if (*End == '\n')
                End++;
        }

        if (*Current) {
            if (Count >= MAX_PACK_ITEMS) {
                HeapFree(GetProcessHeap(), 0, Buffer);
                return FALSE;
            }

            if (!ParseManifestLine(Current, &Items[Count])) {
                HeapFree(GetProcessHeap(), 0, Buffer);
                return FALSE;
            }

            Count++;
        }

        Current = End;
    }

    HeapFree(GetProcessHeap(), 0, Buffer);
    *CountOut = Count;
    return TRUE;
}

VOID SortItems(
    PACK_ITEM* Items,
    DWORD Count
)
{
    DWORD i;

    for (i = 1; i < Count; i++) {
        DWORD j;
        PACK_ITEM Temp;

        Temp = Items[i];

        j = i;

        while (j > 0 &&
            Items[j - 1].Id > Temp.Id)
        {
            Items[j] =
                Items[j - 1];

            j--;
        }

        Items[j] = Temp;
    }
}

BOOL GetFileSize32(
    LPCSTR Path,
    DWORD* SizeOut
)
{
    HANDLE hFile;
    LARGE_INTEGER Size;

    hFile = CreateFileA(
        Path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    if (!GetFileSizeEx(hFile, &Size)) {
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    if (Size.QuadPart > MAXDWORD)
        return FALSE;

    *SizeOut = (DWORD)Size.QuadPart;

    return TRUE;
}

BOOL WriteData(HANDLE hFile, LPCVOID Data, DWORD Size)
{
    DWORD Written;
    while (Size > 0) {
        if (!WriteFile(hFile, Data, Size, &Written, NULL) || Written == 0)
            return FALSE;
        Data = (LPCBYTE)Data + Written;
        Size -= Written;
    }
    return TRUE;
}

BOOL BuildDatabase(
    LPCSTR ManifestFile,
    LPCSTR OutputFile
)
{
    BOOL bResult = FALSE;
    DWORD i, Count, CurrentOffset;
    HANDLE hOut = INVALID_HANDLE_VALUE, hIn;
    RESOURCE_DB_HEADER Header;

    do {
        // 1. Load and sort
        if (!LoadManifest(ManifestFile, g_Items, &Count))
            break;

        SortItems(g_Items, Count);

        // 2. Check for duplicate IDs
        for (i = 1; i < Count; i++) {
            if (g_Items[i].Id == g_Items[i - 1].Id) {
                OutputDebugStringA("Duplicate resource ID\n");
                break;
            }
        }
        if (i < Count)
            break;

        // 3. Compute offsets and validate total size
        CurrentOffset = sizeof(Header) + Count * sizeof(RESOURCE_DB_ENTRY);

        for (i = 0; i < Count; i++) {
            if (!GetFileSize32(g_Items[i].Path, &g_Items[i].Size))
                break;

            if (g_Items[i].Size > MAXDWORD - CurrentOffset) {
                OutputDebugStringA("Total payload size exceeds 4 GB\n");
                break;
            }

            g_Items[i].Offset = CurrentOffset;

            g_Entries[i].Id = g_Items[i].Id;
            g_Entries[i].Offset = CurrentOffset;
            g_Entries[i].Size = g_Items[i].Size;

            CurrentOffset += g_Items[i].Size;
        }
        if (i < Count)
            break;

        // 4. Populate header
        Header.Signature = RESOURCE_DB_SIGNATURE;
        Header.Version = RESOURCE_DB_VERSION;
        Header.EntryCount = Count;

        // 5. Create output file
        hOut = CreateFileA(
            OutputFile,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hOut == INVALID_HANDLE_VALUE)
            break;

        // 6. Write header and directory
        if (!WriteData(hOut, &Header, sizeof(Header)))
            break;

        if (!WriteData(hOut, g_Entries, Count * sizeof(RESOURCE_DB_ENTRY)))
            break;

        // 7. Append file data
        for (i = 0; i < Count; i++) {
            BOOL bCopyOk = TRUE;
            DWORD ReadBytes;

            hIn = CreateFileA(
                g_Items[i].Path,
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            if (hIn == INVALID_HANDLE_VALUE) {
                bCopyOk = FALSE;
            }
            else {
                while (ReadFile(hIn, g_CopyBuffer, sizeof(g_CopyBuffer), &ReadBytes, NULL) && ReadBytes) {
                    if (!WriteData(hOut, g_CopyBuffer, ReadBytes)) {
                        bCopyOk = FALSE;
                        break;
                    }
                }
                CloseHandle(hIn);
            }

            if (!bCopyOk)
                break;
        }
        if (i < Count)
            break;

        // Success path
        bResult = TRUE;

    } while (FALSE);

    // Cleanup
    if (hOut != INVALID_HANDLE_VALUE)
        CloseHandle(hOut);

    if (!bResult)
        DeleteFileA(OutputFile);

    return bResult;
}

/*
* main
*
* Purpose:
*
* Program entrypoint.
*
*/
int main()
{
    if (!BuildDatabase(
        "dbmanifest.txt",
        "kdu.db"))
    {
        printf_s("Error during building KDU external database file\n");
        return 1;
    }

    printf_s("Successfully built KDU external database file\n");
    return 0;
}
