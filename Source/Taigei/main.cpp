/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  Taigei helper dll (part of KDU project).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* StubFunc
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI StubFunc(
    VOID
)
{

}

#ifdef _WIN64

/*
* DllMain
*
* Purpose:
*
* Dummy dll entry point.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);

    return TRUE;
}

#else

#define TEXT_SECTION ".text"
#define TEXT_SECTION_LENGTH sizeof(TEXT_SECTION)
#define TARGET_IMAGE_BASE 0x00400000
#define TARGET_LINK TEXT("\\\\.\\CEDRIVER73")

PVOID LoadExecutableRaw()
{
    WCHAR szFileName[MAX_PATH * 2];

    DWORD cch = GetModuleFileName(NULL, (LPWSTR)&szFileName, MAX_PATH);
    if (cch == 0 || cch >= MAX_PATH)
        return NULL;

    HANDLE hFile = CreateFile(szFileName,
        GENERIC_READ,
        FILE_SHARE_VALID_FLAGS,
        NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    LARGE_INTEGER fs;
    GetFileSizeEx(hFile, &fs);

    PVOID lpBuffer = (PVOID)LocalAlloc(LPTR, (SIZE_T)fs.LowPart);
    if (lpBuffer == NULL) {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesIO;
    if (!ReadFile(hFile, lpBuffer, fs.LowPart, &bytesIO, NULL)) {
        LocalFree((HLOCAL)lpBuffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);

    return lpBuffer;
}

VOID UnlockCheatEngineDriver(
    _In_ PVOID ImageBase
)
{
    PVOID lpFileBuffer = LoadExecutableRaw();
    if (lpFileBuffer == NULL) {
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(ImageBase);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(ntHeaders);
    BOOLEAN bReady = FALSE;

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, pSection++) {

        if (_strncmpi_a((CHAR*)pSection->Name, TEXT_SECTION, TEXT_SECTION_LENGTH) == 0) {

            PCHAR targetAddress = RtlOffsetToPointer(TARGET_IMAGE_BASE, pSection->VirtualAddress);
            PCHAR rawAddress = RtlOffsetToPointer(lpFileBuffer, pSection->PointerToRawData);
            ULONG size = pSection->SizeOfRawData;

            DWORD oldProtect = 0;
            if (VirtualProtect(targetAddress, size, PAGE_READWRITE, &oldProtect)) {
                RtlCopyMemory(targetAddress, rawAddress, size);
                VirtualProtect(targetAddress, size, oldProtect, &oldProtect);
                bReady = TRUE;
            }

            break;
        }

    }

    if (bReady) {

        HANDLE driverHandle = CreateFile(TARGET_LINK,
            GENERIC_ALL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0, NULL);

        if (driverHandle != INVALID_HANDLE_VALUE) {

            IpcSendHandleToServer(driverHandle);

            while (TRUE) {
                Sleep(1000);
            }
        }

    }

}

#pragma comment(linker, "/ENTRY:DllMainUnlockDBK")

/*
* DllMainUnlockDBK
*
* Purpose:
*
* Entry point invoking Cheat Engine's provider unlocking procedure.
* Note: target is always x86-32, so this dll will always be 32bit.
*
*/
BOOL WINAPI DllMainUnlockDBK(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        UnlockCheatEngineDriver(GetModuleHandle(NULL));
    }

    return TRUE;
}

#endif
