/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2026
*
*  TITLE:       MAIN.CPP
*
*  VERSION:     1.49
*
*  DATE:        04 Jun 2026
*
*  Tanikaze helper dll (part of KDU project).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "tanikaze.h"

/*
* Nothing
* 
* WARNING, THIS DLL MUST BE BUILD IN RELEASE CONFIGURATION, ALWAYS.
* The below dll entry point is used only during internal tests.
* 
*/

#ifdef DEBUG
#pragma comment(linker, "/ENTRY:DllMain")

/*
* DllMain
*
* Purpose:
*
* Dll entry point.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }

    return TRUE;
}

#endif
