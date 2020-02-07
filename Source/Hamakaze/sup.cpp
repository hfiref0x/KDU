/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       SUP.CPP
*
*  VERSION:     1.00
*
*  DATE:        02 Feb 2020
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
* Wrapper for RtlAllocateHeap with WinObjEx heap.
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
* Wrapper for RtlFreeHeap with WinObjEx heap.
*
*/
BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
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
* supVerifyMappedImageMatchesChecksum
*
* Purpose:
*
* Calculate PE file checksum and compare it with checksum in PE header.
*
*/
BOOLEAN supVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength
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
    _In_ LPWSTR lpSubKey)
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
    _In_ LPWSTR lpSubKey)
{
    WCHAR szKeyName[MAX_PATH * 2];
    RtlSecureZeroMemory(szKeyName, sizeof(szKeyName));
    _strncpy(szKeyName, MAX_PATH * 2, lpSubKey, MAX_PATH);
    return supxDeleteKeyRecursive(hKeyRoot, szKeyName);
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return NTSTATUS value.
*
*/
NTSTATUS supEnablePrivilege(
    _In_ DWORD Privilege,
    _In_ BOOL Enable
)
{
    ULONG Length;
    NTSTATUS Status;
    HANDLE TokenHandle;
    LUID LuidPrivilege;

    PTOKEN_PRIVILEGES NewState;
    UCHAR Buffer[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];

    Status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &TokenHandle);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    NewState = (PTOKEN_PRIVILEGES)Buffer;

    LuidPrivilege = RtlConvertUlongToLuid(Privilege);

    NewState->PrivilegeCount = 1;
    NewState->Privileges[0].Luid = LuidPrivilege;
    NewState->Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

    Status = NtAdjustPrivilegesToken(TokenHandle,
        FALSE,
        NewState,
        sizeof(Buffer),
        NULL,
        &Length);

    if (Status == STATUS_NOT_ALL_ASSIGNED) {
        Status = STATUS_PRIVILEGE_NOT_HELD;
    }

    NtClose(TokenHandle);
    return Status;
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
* supOpenDriver
*
* Purpose:
*
* Open handle for helper driver.
*
*/
NTSTATUS supOpenDriver(
    _In_ LPCWSTR DriverName,
    _Out_ PHANDLE DeviceHandle
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING usDeviceLink;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;

    TCHAR szDeviceLink[MAX_PATH + 1];

    // assume failure
    if (DeviceHandle)
        *DeviceHandle = NULL;
    else
        return STATUS_INVALID_PARAMETER_2;

    if (DriverName) {

        RtlSecureZeroMemory(szDeviceLink, sizeof(szDeviceLink));

        if (FAILED(StringCchPrintf(szDeviceLink,
            MAX_PATH,
            TEXT("\\DosDevices\\%wS"),
            DriverName)))
        {
            return STATUS_INVALID_PARAMETER_1;
        }

        RtlInitUnicodeString(&usDeviceLink, szDeviceLink);
        InitializeObjectAttributes(&obja, &usDeviceLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtCreateFile(DeviceHandle,
            GENERIC_READ | GENERIC_WRITE,
            &obja,
            &iost,
            NULL,
            0,
            0,
            FILE_OPEN,
            0,
            NULL,
            0);

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
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT         c = 0;
    PVOID       Buffer = NULL;
    ULONG		Size = 0x1000;
    NTSTATUS    status;
    ULONG       memIO;

    do {
        Buffer = supHeapAlloc((SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            supHeapFree(Buffer);
            Buffer = NULL;
            Size *= 2;
            c++;
            if (c > 100) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        supHeapFree(Buffer);
    }
    return NULL;
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

    miSpace = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (miSpace) {
        NtOsBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, miSpace);
    }
    return NtOsBase;
}

/*
* supQueryResourceData
*
* Purpose:
*
* Load resource by given id and decompress it.
*
* N.B. Use supHeapFree to release memory allocated for the decompressed buffer.
*
*/
PBYTE supQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
)
{
    NTSTATUS                   status;
    SIZE_T                     decompressedSize = 0;
    ULONG_PTR                  IdPath[3];
    IMAGE_RESOURCE_DATA_ENTRY* DataEntry;
    PBYTE                      Data = NULL;
    ULONG                      SizeOfData = 0;

    if (DllHandle != NULL) {

        IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
        IdPath[1] = ResourceId;           //id
        IdPath[2] = 0;                    //lang

        status = LdrFindResource_U(DllHandle, (ULONG_PTR*)&IdPath, 3, &DataEntry);
        if (NT_SUCCESS(status)) {
            status = LdrAccessResource(DllHandle, DataEntry, (PVOID*)&Data, &SizeOfData);
            if (NT_SUCCESS(status)) {

                Data = (PBYTE)KDUDecompressResource(Data,
                    SizeOfData,
                    &decompressedSize);

                if (DataSize) {
                    *DataSize = (ULONG)decompressedSize;
                }
            }
        }
    }
    return Data;
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file (or open existing) and write (append) buffer to it.
*
*/
SIZE_T supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append,
    _Out_opt_ NTSTATUS* Result
)
{
    NTSTATUS           Status = STATUS_UNSUCCESSFUL;
    DWORD              dwFlag;
    HANDLE             hFile = NULL;
    OBJECT_ATTRIBUTES  attr;
    UNICODE_STRING     NtFileName;
    IO_STATUS_BLOCK    IoStatus;
    LARGE_INTEGER      Position;
    ACCESS_MASK        DesiredAccess;
    PLARGE_INTEGER     pPosition = NULL;
    ULONG_PTR          nBlocks, BlockIndex;
    ULONG              BlockSize, RemainingSize;
    PBYTE              ptr = (PBYTE)Buffer;
    SIZE_T             BytesWritten = 0;

    if (Result)
        *Result = STATUS_UNSUCCESSFUL;

    if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE) {
        if (Result)
            *Result = STATUS_INVALID_PARAMETER_1;
        return 0;
    }

    DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
    dwFlag = FILE_OVERWRITE_IF;

    if (Append != FALSE) {
        DesiredAccess |= FILE_READ_ACCESS;
        dwFlag = FILE_OPEN_IF;
    }

    InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    __try {
        Status = NtCreateFile(&hFile, DesiredAccess, &attr,
            &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(Status))
            __leave;

        pPosition = NULL;

        if (Append != FALSE) {
            Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
            Position.HighPart = -1;
            pPosition = &Position;
        }

        if (Size < 0x80000000) {
            BlockSize = (ULONG)Size;
            Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
            if (!NT_SUCCESS(Status))
                __leave;

            BytesWritten += IoStatus.Information;
        }
        else {
            BlockSize = 0x7FFFFFFF;
            nBlocks = (Size / BlockSize);
            for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;

                ptr += BlockSize;
                BytesWritten += IoStatus.Information;
            }
            RemainingSize = (ULONG)(Size % BlockSize);
            if (RemainingSize != 0) {
                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;
                BytesWritten += IoStatus.Information;
            }
        }
    }
    __finally {
        if (hFile != NULL) {
            if (Flush != FALSE) NtFlushBuffersFile(hFile, &IoStatus);
            NtClose(hFile);
        }
        RtlFreeUnicodeString(&NtFileName);
        if (Result) *Result = Status;
    }
    return BytesWritten;
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
void supResolveKernelImport(
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
* supDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supDetectObjectCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

    if (Entry == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CallbackParam == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Param->Buffer == NULL || Param->BufferSize == 0) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    if (Entry->Name.Buffer) {
        if (_strcmpi_w(Entry->Name.Buffer, Param->Buffer) == 0) {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_UNSUCCESSFUL;
}

/*
* supEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supEnumSystemObjects(
    _In_opt_ LPWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam
)
{
    ULONG               ctx, rlen;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    NTSTATUS            CallbackStatus;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      sname;

    POBJECT_DIRECTORY_INFORMATION    objinf;

    if (CallbackProc == NULL) {
        return STATUS_INVALID_PARAMETER_4;
    }

    status = STATUS_UNSUCCESSFUL;

    __try {

        // We can use root directory.
        if (pwszRootDirectory != NULL) {
            RtlSecureZeroMemory(&sname, sizeof(sname));
            RtlInitUnicodeString(&sname, pwszRootDirectory);
            InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        else {
            if (hRootDirectory == NULL) {
                return STATUS_INVALID_PARAMETER_2;
            }
            hDirectory = hRootDirectory;
        }

        // Enumerate objects in directory.
        ctx = 0;
        do {

            rlen = 0;
            status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
            if (status != STATUS_BUFFER_TOO_SMALL)
                break;

            objinf = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc(rlen);
            if (objinf == NULL)
                break;

            status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
            if (!NT_SUCCESS(status)) {
                supHeapFree(objinf);
                break;
            }

            CallbackStatus = CallbackProc(objinf, CallbackParam);

            supHeapFree(objinf);

            if (NT_SUCCESS(CallbackStatus)) {
                status = STATUS_SUCCESS;
                break;
            }

        } while (TRUE);

        if (hDirectory != NULL) {
            NtClose(hDirectory);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*
* supIsObjectExists
*
* Purpose:
*
* Return TRUE if the given object exists, FALSE otherwise.
*
*/
BOOLEAN supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName
)
{
    OBJSCANPARAM Param;

    if (ObjectName == NULL) {
        return FALSE;
    }

    Param.Buffer = ObjectName;
    Param.BufferSize = (ULONG)_strlen(ObjectName);

    return NT_SUCCESS(supEnumSystemObjects(RootDirectory, NULL, supDetectObjectCallback, &Param));
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
    _Out_writes_opt_z_(ValueSize) LPTSTR OptionValue,
    _In_ ULONG ValueSize
)
{
    LPTSTR  cmdline = GetCommandLine();
    TCHAR   Param[MAX_PATH + 1];
    ULONG   rlen;
    int     i = 0;

    RtlSecureZeroMemory(Param, sizeof(Param));
    while (GetCommandLineParam(cmdline, i, Param, MAX_PATH, &rlen))
    {
        if (rlen == 0)
            break;

        if (_strcmp(Param, OptionName) == 0)
        {
            if (IsParametric)
                return GetCommandLineParam(cmdline, i + 1, OptionValue, ValueSize, &rlen);

            return TRUE;
        }
        ++i;
    }

    return 0;
}

/*
* supQueryHVCIState
*
* Purpose:
*
* Query HVCI/IUM state.
*
*/
BOOLEAN supQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled
)
{
    BOOLEAN hvciEnabled;
    ULONG ReturnLength;
    SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrity;

    if (pbHVCIEnabled) *pbHVCIEnabled = FALSE;
    if (pbHVCIStrictMode) *pbHVCIStrictMode = FALSE;
    if (pbHVCIIUMEnabled) *pbHVCIIUMEnabled = FALSE;

    CodeIntegrity.Length = sizeof(CodeIntegrity);
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &CodeIntegrity,
        sizeof(CodeIntegrity),
        &ReturnLength)))
    {
        hvciEnabled = ((CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) &&
            (CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED));

        *pbHVCIEnabled = hvciEnabled;

        *pbHVCIStrictMode = hvciEnabled &&
            (CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED);

        *pbHVCIIUMEnabled = (CodeIntegrity.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) > 0;

        return TRUE;
    }

    return FALSE;
}

/*
* supExpandEnvironmentStrings
*
* Purpose:
*
* Reimplemented ExpandEnvironmentStrings.
*
*/
DWORD supExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize
)
{
    NTSTATUS Status;
    SIZE_T SrcLength = 0, ReturnLength = 0, DstLength = (SIZE_T)nSize;

    if (lpSrc) {
        SrcLength = _strlen(lpSrc);
    }

    Status = RtlExpandEnvironmentStrings(
        NULL,
        (PWSTR)lpSrc,
        SrcLength,
        (PWSTR)lpDst,
        DstLength,
        &ReturnLength);

    if ((NT_SUCCESS(Status)) || (Status == STATUS_BUFFER_TOO_SMALL)) {

        if (ReturnLength <= MAXDWORD32)
            return (DWORD)ReturnLength;

        Status = STATUS_UNSUCCESSFUL;
    }
    RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
    return 0;
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
    HANDLE      hFile = NULL, hRoot = NULL;
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

        InitializeObjectAttributes(&attr, &usName, OBJ_CASE_INSENSITIVE, hRoot, NULL);

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

    if (hRoot != NULL) {
        NtClose(hRoot);
    }

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
