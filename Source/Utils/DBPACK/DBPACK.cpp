/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       DBPACK.CPP
*
*  VERSION:     1.05
*
*  DATE:        12 Jun 2026
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

BOOL StringToDword(
    LPCSTR String,
    DWORD* Value
)
{
    DWORD Result = 0;

    if (!String || !*String)
        return FALSE;

    while (*String)
    {
        CHAR Ch = *String++;

        if (Ch < '0' || Ch > '9')
            return FALSE;

        Result =
            Result * 10 +
            (DWORD)(Ch - '0');
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
    HANDLE hFile;

    DWORD FileSize;
    DWORD ReadBytes;

    LPSTR Buffer;
    LPSTR Current;

    DWORD Count = 0;

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

    FileSize = GetFileSize(hFile, NULL);
    Buffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize + 1);
    if (!Buffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(
        hFile,
        Buffer,
        FileSize,
        &ReadBytes,
        NULL))
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

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

            if (!ParseManifestLine(
                Current,
                &Items[Count]))
            {
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

BOOL BuildDatabase(
    LPCSTR ManifestFile,
    LPCSTR OutputFile
)
{
    PACK_ITEM Items[MAX_PACK_ITEMS];
    RESOURCE_DB_ENTRY Entries[MAX_PACK_ITEMS];

    RESOURCE_DB_HEADER Header;

    HANDLE hOut;

    DWORD Count;
    DWORD i;
    DWORD Written;

    DWORD CurrentOffset;

    if (!LoadManifest(
        ManifestFile,
        Items,
        &Count))
    {
        return FALSE;
    }

    SortItems(
        Items,
        Count);

    for (i = 1; i < Count; i++) {
        if (Items[i].Id ==
            Items[i - 1].Id)
        {
            OutputDebugStringA("Duplicate resource ID\n");
            return FALSE;
        }
    }

    CurrentOffset = sizeof(Header) + Count * sizeof(RESOURCE_DB_ENTRY);

    for (i = 0; i < Count; i++) {
        if (!GetFileSize32(
            Items[i].Path,
            &Items[i].Size))
        {
            return FALSE;
        }

        Items[i].Offset =
            CurrentOffset;

        Entries[i].Id =
            Items[i].Id;

        Entries[i].Offset =
            CurrentOffset;

        Entries[i].Size =
            Items[i].Size;

        CurrentOffset +=
            Items[i].Size;
    }

    Header.Signature = RESOURCE_DB_SIGNATURE;
    Header.Version = RESOURCE_DB_VERSION;
    Header.EntryCount = Count;

    hOut = CreateFileA(
        OutputFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hOut == INVALID_HANDLE_VALUE)
        return FALSE;

    WriteFile(
        hOut,
        &Header,
        sizeof(Header),
        &Written,
        NULL);

    WriteFile(
        hOut,
        Entries,
        Count * sizeof(RESOURCE_DB_ENTRY),
        &Written,
        NULL);

    for (i = 0; i < Count; i++) {
        HANDLE hIn;

        BYTE Buffer[65536];

        DWORD ReadBytes;

        hIn = CreateFileA(
            Items[i].Path,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hIn == INVALID_HANDLE_VALUE) {
            CloseHandle(hOut);
            return FALSE;
        }

        while (ReadFile(
            hIn,
            Buffer,
            sizeof(Buffer),
            &ReadBytes,
            NULL) &&
            ReadBytes)
        {
            WriteFile(
                hOut,
                Buffer,
                ReadBytes,
                &Written,
                NULL);
        }

        CloseHandle(hIn);
    }

    CloseHandle(hOut);

    return TRUE;
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
        return 1;
    }

    return 0;
}
