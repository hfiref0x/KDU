/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2011 - 2025 UGN/HE
*
*  TITLE:       NTSUP.C
*
*  VERSION:     2.25
*
*  DATE:        17 Aug 2025
*
*  Native API support functions.
*
*  Only ntdll-bound import.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "ntsup.h"

#pragma warning(push)
#pragma warning(disable: 26812) // Prefer 'enum class' over 'enum'
#pragma warning(disable: 6320) // exception may mask

/*
* 
* SHA256 algo (used by Ronova so keep it here).
* 
*/

typedef struct _NTSUP_SHA256_CTX {
    ULONG State[8];
    ULONG64 BitCount;
    UCHAR Buffer[64];
} NTSUP_SHA256_CTX, * PNTSUP_SHA256_CTX;

#define NTSUP_ROTR32(v,b) _rotr(v,b)
#define NTSUP_CH(x,y,z)   (((x) & (y)) ^ ((~x) & (z)))
#define NTSUP_MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define NTSUP_BSIG0(x)    (NTSUP_ROTR32(x,2) ^ NTSUP_ROTR32(x,13) ^ NTSUP_ROTR32(x,22))
#define NTSUP_BSIG1(x)    (NTSUP_ROTR32(x,6) ^ NTSUP_ROTR32(x,11) ^ NTSUP_ROTR32(x,25))
#define NTSUP_SSIG0(x)    (NTSUP_ROTR32(x,7) ^ NTSUP_ROTR32(x,18) ^ ((x) >> 3))
#define NTSUP_SSIG1(x)    (NTSUP_ROTR32(x,17) ^ NTSUP_ROTR32(x,19) ^ ((x) >> 10))

static const ULONG ntsupSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

VOID ntsupSha256Transform(
    _Inout_ PNTSUP_SHA256_CTX Ctx,
    _In_reads_bytes_(64) const UCHAR Block[64]
)
{
    ULONG W[64];
    ULONG a, b, c, d, e, f, g, h, t1, t2;
    ULONG i;
    for (i = 0; i < 16; i++) {
        W[i] = (Block[i * 4] << 24) |
            (Block[i * 4 + 1] << 16) |
            (Block[i * 4 + 2] << 8) |
            (Block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = NTSUP_SSIG1(W[i - 2]) + W[i - 7] + NTSUP_SSIG0(W[i - 15]) + W[i - 16];
    }

    a = Ctx->State[0];
    b = Ctx->State[1];
    c = Ctx->State[2];
    d = Ctx->State[3];
    e = Ctx->State[4];
    f = Ctx->State[5];
    g = Ctx->State[6];
    h = Ctx->State[7];

    for (i = 0; i < 64; i++) {
        t1 = h + NTSUP_BSIG1(e) + NTSUP_CH(e, f, g) + ntsupSha256K[i] + W[i];
        t2 = NTSUP_BSIG0(a) + NTSUP_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    Ctx->State[0] += a;
    Ctx->State[1] += b;
    Ctx->State[2] += c;
    Ctx->State[3] += d;
    Ctx->State[4] += e;
    Ctx->State[5] += f;
    Ctx->State[6] += g;
    Ctx->State[7] += h;

    RtlSecureZeroMemory(W, sizeof(W));
}

VOID ntsupSha256Init(
    _Out_ PNTSUP_SHA256_CTX Ctx
)
{
    RtlSecureZeroMemory(Ctx, sizeof(NTSUP_SHA256_CTX));
    Ctx->State[0] = 0x6A09E667;
    Ctx->State[1] = 0xBB67AE85;
    Ctx->State[2] = 0x3C6EF372;
    Ctx->State[3] = 0xA54FF53A;
    Ctx->State[4] = 0x510E527F;
    Ctx->State[5] = 0x9B05688C;
    Ctx->State[6] = 0x1F83D9AB;
    Ctx->State[7] = 0x5BE0CD19;
}

VOID ntsupSha256Update(
    _Inout_ PNTSUP_SHA256_CTX Ctx,
    _In_reads_bytes_(Length) const UCHAR* Data,
    _In_ SIZE_T Length
)
{
    SIZE_T have, need;
    SIZE_T off;
    const UCHAR* p;

    if (Length == 0) return;

    have = (SIZE_T)((Ctx->BitCount >> 3) & 0x3F);
    need = 64 - have;
    Ctx->BitCount += (ULONG64)Length * 8;
    p = Data;
    off = 0;

    if (have && Length >= need) {
        RtlCopyMemory(Ctx->Buffer + have, p, need);
        ntsupSha256Transform(Ctx, Ctx->Buffer);
        off += need;
        have = 0;
    }

    while (off + 64 <= Length) {
#pragma warning(push)
#pragma warning(disable: 6385)
        ntsupSha256Transform(Ctx, p + off);
#pragma warning(pop)
        off += 64;
    }

    if (off < Length) {
        RtlCopyMemory(Ctx->Buffer + have, p + off, Length - off);
    }
}

VOID ntsupSha256Final(
    _Inout_ PNTSUP_SHA256_CTX Ctx,
    _Out_writes_bytes_all_(32) UCHAR Digest[32]
)
{
    UCHAR pad[64];
    UCHAR len[8];
    SIZE_T padLen;
    SIZE_T i;
    ULONG64 bitCount;

    bitCount = Ctx->BitCount;

    for (i = 0; i < 8; i++) {
        len[7 - i] = (UCHAR)(bitCount >> (i * 8));
    }

    pad[0] = 0x80;
    RtlSecureZeroMemory(pad + 1, 63);

    padLen = 64 - ((bitCount >> 3) & 0x3f);
    if (padLen < 9) padLen += 64;

    ntsupSha256Update(Ctx, pad, padLen - 8);
    ntsupSha256Update(Ctx, len, 8);

    for (i = 0; i < 8; i++) {
        Digest[i * 4 + 0] = (UCHAR)(Ctx->State[i] >> 24);
        Digest[i * 4 + 1] = (UCHAR)(Ctx->State[i] >> 16);
        Digest[i * 4 + 2] = (UCHAR)(Ctx->State[i] >> 8);
        Digest[i * 4 + 3] = (UCHAR)(Ctx->State[i]);
    }

    RtlSecureZeroMemory(Ctx, sizeof(NTSUP_SHA256_CTX));
    RtlSecureZeroMemory(pad, sizeof(pad));
    RtlSecureZeroMemory(len, sizeof(len));
}

/*
* ntsupHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with process heap.
*
*/
PVOID ntsupHeapAlloc(
    _In_ SIZE_T Size
)
{
    return RtlAllocateHeap(ntsupProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

/*
* ntsupHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with process heap.
*
*/
VOID ntsupHeapFree(
    _In_ PVOID BaseAddress
)
{
    RtlFreeHeap(ntsupProcessHeap(), 0, BaseAddress);
}

/*
* ntsupVirtualAllocEx
*
* Purpose:
*
* Wrapper for ntsupVirtualAllocEx with standard parameters.
*
*/
PVOID ntsupVirtualAllocEx(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect)
{
    NTSTATUS ntStatus;
    PVOID bufferPtr = NULL;
    SIZE_T bufferSize;

    bufferSize = Size;
    ntStatus = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &bufferPtr,
        0,
        &bufferSize,
        AllocationType,
        Protect);

    if (NT_SUCCESS(ntStatus)) {
        return bufferPtr;
    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return NULL;
}

/*
* ntsupVirtualAlloc
*
* Purpose:
*
* Wrapper for supVirtualAllocEx.
*
*/
PVOID ntsupVirtualAlloc(
    _In_ SIZE_T Size)
{
    return ntsupVirtualAllocEx(Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

/*
* ntsupVirtualLock
*
* Purpose:
*
* Wrapper for NtLockVirtualMemory.
*
*/
BOOL ntsupVirtualLock(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize
)
{
    return (NT_SUCCESS(NtLockVirtualMemory(NtCurrentProcess(),
        &lpAddress,
        &dwSize,
        MAP_PROCESS)));
}

/*
* ntsupVirtualUnlock
*
* Purpose:
*
* Wrapper for NtUnlockVirtualMemory.
*
*/
BOOL ntsupVirtualUnlock(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize
)
{
    return (NT_SUCCESS(NtUnlockVirtualMemory(NtCurrentProcess(),
        &lpAddress,
        &dwSize,
        MAP_PROCESS)));
}

/*
* ntsupVirtualFree
*
* Purpose:
*
* Wrapper for NtFreeVirtualMemory.
*
*/
BOOL ntsupVirtualFree(
    _In_ PVOID Memory)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    SIZE_T sizeDummy = 0;

    if (Memory) {
        ntStatus = NtFreeVirtualMemory(
            NtCurrentProcess(),
            &Memory,
            &sizeDummy,
            MEM_RELEASE);
    }
    else {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return NT_SUCCESS(ntStatus);
}

/*
* ntsupWriteBufferToFile
*
* Purpose:
*
* Create new file (or open existing) and write buffer to it.
*
*/
SIZE_T ntsupWriteBufferToFile(
    _In_ PCWSTR FileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append,
    _Out_opt_ NTSTATUS* Result
)
{
    NTSTATUS           ntStatus = STATUS_UNSUCCESSFUL;
    ACCESS_MASK        desiredAccess = FILE_WRITE_DATA | SYNCHRONIZE;
    DWORD              dwFlag = FILE_OVERWRITE_IF;
    ULONG              blockSize, remainingSize;
    HANDLE             hFile = NULL;
    ULONG_PTR          nBlocks, blockIndex;
    SIZE_T             bytesWritten = 0;
    PBYTE              ptr = (PBYTE)Buffer;
    LARGE_INTEGER      filePosition;
    PLARGE_INTEGER     pPosition = NULL;
    OBJECT_ATTRIBUTES  attr;
    UNICODE_STRING     ntFileName;
    IO_STATUS_BLOCK    ioStatus;

    if (Result)
        *Result = STATUS_UNSUCCESSFUL;

    if (RtlDosPathNameToNtPathName_U(FileName, &ntFileName, NULL, NULL) == FALSE) {
        if (Result)
            *Result = STATUS_INVALID_PARAMETER_1;
        return 0;
    }

    if (Append) {
        desiredAccess |= FILE_READ_DATA | FILE_APPEND_DATA;
        dwFlag = FILE_OPEN_IF;
    }

    InitializeObjectAttributes(&attr, &ntFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    __try {
        ntStatus = NtCreateFile(&hFile, desiredAccess, &attr,
            &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        if (Append) {
            filePosition.LowPart = FILE_WRITE_TO_END_OF_FILE;
            filePosition.HighPart = -1;
            pPosition = &filePosition;
        }

        if (Size < 0x80000000) {
            blockSize = (ULONG)Size;
            ntStatus = NtWriteFile(hFile, 0, NULL, NULL, &ioStatus, ptr, blockSize, pPosition, NULL);
            if (!NT_SUCCESS(ntStatus))
                __leave;

            bytesWritten += ioStatus.Information;
            if (Append)
                pPosition = NULL;
        }
        else {
            blockSize = MAX_NTSUP_WRITE_CHUNK;
            nBlocks = (Size / blockSize);
            for (blockIndex = 0; blockIndex < nBlocks; blockIndex++) {

                ntStatus = NtWriteFile(hFile, 0, NULL, NULL, &ioStatus, ptr, blockSize, pPosition, NULL);
                if (!NT_SUCCESS(ntStatus))
                    __leave;

                ptr += blockSize;
                bytesWritten += ioStatus.Information;
                if (Append && blockIndex == 0)
                    pPosition = NULL;
            }
            remainingSize = (ULONG)(Size % blockSize);
            if (remainingSize) {
                ntStatus = NtWriteFile(hFile, 0, NULL, NULL, &ioStatus, ptr, remainingSize, pPosition, NULL);
                if (!NT_SUCCESS(ntStatus))
                    __leave;
                bytesWritten += ioStatus.Information;
            }
        }
    }
    __finally {
        if (hFile) {

            if (Flush)
                NtFlushBuffersFile(hFile, &ioStatus);

            NtClose(hFile);
        }
        RtlFreeUnicodeString(&ntFileName);
        if (Result) *Result = ntStatus;
    }
    return bytesWritten;
}

/*
* ntsupFindModuleEntryByName
*
* Purpose:
*
* Find Module entry for given name.
*
*/
PVOID ntsupFindModuleEntryByName(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ LPCSTR ModuleName
)
{
    ULONG i, modulesCount = ModulesList->NumberOfModules, fnameOffset;
    LPSTR entryName;
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry;

    for (i = 0; i < modulesCount; i++) {

        moduleEntry = &ModulesList->Modules[i];
        fnameOffset = moduleEntry->OffsetToFileName;
        entryName = (LPSTR)&moduleEntry->FullPathName[fnameOffset];
        if (_strcmpi_a(entryName, ModuleName) == 0)
            return moduleEntry;
    }

    return NULL;
}

/*
* ntsupFindModuleEntryByName_U
*
* Purpose:
*
* Find Module entry for given name.
*
*/
PVOID ntsupFindModuleEntryByName_U(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ LPCWSTR ModuleName
)
{
    ULONG i, modulesCount = ModulesList->NumberOfModules, fnameOffset;
    LPSTR entryName;
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry, result = NULL;

    UNICODE_STRING usString;
    ANSI_STRING moduleName;

    if (NT_SUCCESS(RtlInitUnicodeStringEx(&usString, ModuleName))) {
        moduleName.Buffer = NULL;
        moduleName.Length = moduleName.MaximumLength = 0;
        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&moduleName, &usString, TRUE))) {

            for (i = 0; i < modulesCount; i++) {

                moduleEntry = &ModulesList->Modules[i];
                fnameOffset = moduleEntry->OffsetToFileName;
                entryName = (LPSTR)&moduleEntry->FullPathName[fnameOffset];
                if (_strcmpi_a(entryName, moduleName.Buffer) == 0) {
                    result = moduleEntry;
                    break;
                }
            }

            RtlFreeAnsiString(&moduleName);
        }
    }
    return result;
}

/*
* ntsupFindModuleEntryByAddress
*
* Purpose:
*
* Find Module Name for given Address and copy it to the supplied buffer.
*
* Returns module entry if found, NULL otherwise.
*
*/
BOOL ntsupFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ PVOID Address,
    _Out_ PULONG ModuleIndex
)
{
    ULONG i, modulesCount = ModulesList->NumberOfModules;

    *ModuleIndex = 0;

    for (i = 0; i < modulesCount; i++) {
        if (IN_REGION(Address,
            ModulesList->Modules[i].ImageBase,
            ModulesList->Modules[i].ImageSize))
        {
            *ModuleIndex = i;
            return TRUE;
        }
    }
    return FALSE;
}

/*
* ntsupGetModuleEntryByAddress
*
* Purpose:
*
* Get Module Entry for given Address.
*
*/
PVOID ntsupGetModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ PVOID Address
)
{
    ULONG i, modulesCount = ModulesList->NumberOfModules;

    for (i = 0; i < modulesCount; i++) {
        if (IN_REGION(Address,
            ModulesList->Modules[i].ImageBase,
            ModulesList->Modules[i].ImageSize))
        {           
            return &ModulesList->Modules[i];
        }
    }
    return NULL;
}

/*
* ntsupFindModuleNameByAddress
*
* Purpose:
*
* Find Module Name for given Address.
*
*/
PVOID ntsupFindModuleNameByAddress(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    ULONG i, modulesCount;
    NTSTATUS ntStatus;
    SIZE_T copyLength;
    UNICODE_STRING usConvertedName;
    PRTL_PROCESS_MODULE_INFORMATION moduleEntry;

    if ((Buffer == NULL) || (ccBuffer == 0)) {
        return NULL;
    }

    modulesCount = ModulesList->NumberOfModules;

    for (i = 0; i < modulesCount; i++) {
        if (IN_REGION(Address,
            ModulesList->Modules[i].ImageBase,
            ModulesList->Modules[i].ImageSize))
        {
            moduleEntry = &ModulesList->Modules[i];

            RtlInitEmptyUnicodeString(&usConvertedName, NULL, 0);
            ntStatus = ntsupConvertToUnicode(
                (LPSTR)&moduleEntry->FullPathName[moduleEntry->OffsetToFileName],
                &usConvertedName);

            if (NT_SUCCESS(ntStatus)) {

                copyLength = usConvertedName.Length / sizeof(WCHAR);
                if (copyLength > (SIZE_T)(ccBuffer - 1))
                    copyLength = ccBuffer - 1;

                _strncpy(
                    Buffer,
                    ccBuffer,
                    usConvertedName.Buffer,
                    copyLength);

                RtlFreeUnicodeString(&usConvertedName);

                return &ModulesList->Modules[i];
            }
            else {
                return NULL;
            }
        }
    }
    return NULL;
}

/*
* ntsupConvertToUnicode
*
* Purpose:
*
* Convert ANSI string to UNICODE string.
*
* N.B.
* If function succeeded - use RtlFreeUnicodeString to release allocated string.
*
*/
NTSTATUS ntsupConvertToUnicode(
    _In_ LPCSTR AnsiString,
    _Inout_ PUNICODE_STRING UnicodeString)
{
    ANSI_STRING ansiString;

    RtlInitString(&ansiString, AnsiString);
    return RtlAnsiStringToUnicodeString(UnicodeString, &ansiString, TRUE);
}

/*
* ntsupConvertToAnsi
*
* Purpose:
*
* Convert UNICODE string to ANSI string.
*
* N.B.
* If function succeeded - use RtlFreeAnsiString to release allocated string.
*
*/
NTSTATUS ntsupConvertToAnsi(
    _In_ LPCWSTR UnicodeString,
    _Inout_ PANSI_STRING AnsiString)
{
    UNICODE_STRING unicodeString;

    RtlInitUnicodeString(&unicodeString, UnicodeString);
    return RtlUnicodeStringToAnsiString(AnsiString, &unicodeString, TRUE);
}

/*
* ntsupEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOLEAN ntsupEnablePrivilege(
    _In_ DWORD Privilege,
    _In_ BOOLEAN Enable
)
{
    ULONG returnLength;
    NTSTATUS ntStatus;
    HANDLE tokenHandle;

    PTOKEN_PRIVILEGES newState;
    UCHAR rawBuffer[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];

    ntStatus = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &tokenHandle);

    if (NT_SUCCESS(ntStatus)) {

        newState = (PTOKEN_PRIVILEGES)rawBuffer;

        newState->PrivilegeCount = 1;
        newState->Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
        newState->Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

        ntStatus = NtAdjustPrivilegesToken(
            tokenHandle,
            FALSE,
            newState,
            sizeof(rawBuffer),
            NULL,
            &returnLength);

        if (ntStatus == STATUS_NOT_ALL_ASSIGNED) {
            ntStatus = STATUS_PRIVILEGE_NOT_HELD;
        }

        NtClose(tokenHandle);

    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return NT_SUCCESS(ntStatus);
}

/*
* ntsupGetCurrentProcessToken
*
* Purpose:
*
* Return current process token value with TOKEN_QUERY access right.
*
*/
HANDLE ntsupGetCurrentProcessToken(
    VOID)
{
    HANDLE tokenHandle = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle)))
    {
        return tokenHandle;
    }
    return NULL;
}

/*
* ntsupQuerySystemRangeStart
*
* Purpose:
*
* Return MmSystemRangeStart value.
*
*/
ULONG_PTR ntsupQuerySystemRangeStart(
    VOID
)
{
    NTSTATUS  ntStatus;
    ULONG_PTR systemRangeStart = 0;
    ULONG     memIO = 0;

    ntStatus = NtQuerySystemInformation(
        SystemRangeStartInformation,
        (PVOID)&systemRangeStart,
        sizeof(ULONG_PTR),
        &memIO);

    if (!NT_SUCCESS(ntStatus)) {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }
    return systemRangeStart;
}

/*
* ntsupQueryUserModeAccessibleRange
*
* Purpose:
*
* Return user mode applications accessible address range.
*
*/
BOOLEAN ntsupQueryUserModeAccessibleRange(
    _Out_ PULONG_PTR MinimumUserModeAddress,
    _Out_ PULONG_PTR MaximumUserModeAddress
)
{
    NTSTATUS  ntStatus;
    ULONG     memIO = 0;
    SYSTEM_BASIC_INFORMATION sysBasicInfo;

    RtlSecureZeroMemory(&sysBasicInfo, sizeof(sysBasicInfo));

    ntStatus = NtQuerySystemInformation(
        SystemBasicInformation,
        (PVOID)&sysBasicInfo,
        sizeof(sysBasicInfo),
        &memIO);

    if (NT_SUCCESS(ntStatus)) {

        *MinimumUserModeAddress = sysBasicInfo.MinimumUserModeAddress;
        *MaximumUserModeAddress = sysBasicInfo.MaximumUserModeAddress;

        return TRUE;
    }
    else {

        *MinimumUserModeAddress = 0;
        *MaximumUserModeAddress = 0;

    }

    return FALSE;
}

/*
* ntsupIsKdEnabled
*
* Purpose:
*
* Perform check if the kernel debugger active.
*
*/
BOOLEAN ntsupIsKdEnabled(
    _Out_opt_ PBOOLEAN DebuggerAllowed,
    _Out_opt_ PBOOLEAN DebuggerNotPresent
)
{
    BOOLEAN bResult = FALSE;
    NTSTATUS ntStatus;
    ULONG returnLength = 0;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION kdInfo;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX kdInfoEx;

    if (DebuggerAllowed)
        *DebuggerAllowed = FALSE;
    if (DebuggerNotPresent)
        *DebuggerNotPresent = FALSE;

    RtlSecureZeroMemory(&kdInfo, sizeof(kdInfo));

    ntStatus = NtQuerySystemInformation(
        SystemKernelDebuggerInformation,
        &kdInfo,
        sizeof(kdInfo),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {

        if (DebuggerNotPresent)
            *DebuggerNotPresent = kdInfo.KernelDebuggerNotPresent;

        bResult = kdInfo.KernelDebuggerEnabled;
    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
        return FALSE;
    }

    if (DebuggerAllowed) {

        RtlSecureZeroMemory(&kdInfoEx, sizeof(kdInfoEx));

        ntStatus = NtQuerySystemInformation(
            SystemKernelDebuggerInformationEx,
            &kdInfoEx,
            sizeof(kdInfoEx),
            &returnLength);

        if (NT_SUCCESS(ntStatus)) {
            *DebuggerAllowed = kdInfoEx.DebuggerAllowed;
        }
        else {
            *DebuggerAllowed = FALSE;
            RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
        }

    }

    return bResult;
}

/*
* ntsupIsProcess32bit
*
* Purpose:
*
* Return TRUE if process is wow64.
*
*/
BOOL ntsupIsProcess32bit(
    _In_ HANDLE hProcess
)
{
    ULONG                              returnLength;
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;

    RtlSecureZeroMemory(&pebi, sizeof(pebi));
    pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

    if (NT_SUCCESS(NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pebi,
        sizeof(pebi),
        &returnLength)))
    {
        return (pebi.IsWow64Process == 1);
    }

    return FALSE;
}

/*
* ntsupGetLoadedModulesListEx
*
* Purpose:
*
* Read list of loaded kernel modules.
*
*/
PVOID ntsupGetLoadedModulesListEx(
    _In_ BOOL ExtendedOutput,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem
)
{
    NTSTATUS    ntStatus;
    PVOID       buffer;
    ULONG       bufferSize = PAGE_SIZE;

    PRTL_PROCESS_MODULES pvModules;
    SYSTEM_INFORMATION_CLASS infoClass;

    if (ReturnLength)
        *ReturnLength = 0;

    infoClass = ExtendedOutput ? SystemModuleInformationEx : SystemModuleInformation;

    buffer = AllocMem((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    ntStatus = NtQuerySystemInformation(
        infoClass,
        buffer,
        bufferSize,
        &bufferSize);

    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {

        FreeMem(buffer);
        if (bufferSize == 0 || bufferSize > MAX_NTSUP_BUFFER_SIZE)
            return NULL;

        buffer = AllocMem((SIZE_T)bufferSize);
        if (buffer == NULL)
            return NULL;

        ntStatus = NtQuerySystemInformation(
            infoClass,
            buffer,
            bufferSize,
            &bufferSize);
    }

    if (ReturnLength)
        *ReturnLength = bufferSize;

    //
    // Handle special case:
    // If driver image path exceeds structure field size, 
    // RtlUnicodeStringToAnsiString will throw STATUS_BUFFER_OVERFLOW.
    // If this is the last driver in enumeration, service will return 
    // valid data but with STATUS_BUFFER_OVERFLOW result.
    //
    if (ntStatus == STATUS_BUFFER_OVERFLOW) {

        //
        // Force ignore this status if list is not empty.
        //
        pvModules = (PRTL_PROCESS_MODULES)buffer;
        if (pvModules->NumberOfModules != 0)
            return buffer;
    }

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    FreeMem(buffer);
    return NULL;
}

/*
* ntsupGetLoadedModulesList
*
* Purpose:
*
* Read list of loaded kernel modules.
*
* Returned buffer must be freed with ntsupHeapFree after usage.
*
*/
PVOID ntsupGetLoadedModulesList(
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetLoadedModulesListEx(
        FALSE,
        ReturnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);
}

/*
* ntsupGetLoadedModulesList2
*
* Purpose:
*
* Read list of loaded kernel modules.
*
* Returned buffer must be freed with ntsupHeapFree after usage.
*
*/
PVOID ntsupGetLoadedModulesList2(
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetLoadedModulesListEx(
        TRUE,
        ReturnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);
}

/*
* ntsupGetSystemInfoEx
*
* Purpose:
*
* Returns buffer with system information by given SystemInformationClass.
*
* Returned buffer must be freed with FreeMem function after usage.
*
*/
PVOID ntsupGetSystemInfoEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem
)
{
    PVOID       buffer = NULL;
    ULONG       bufferSize = PAGE_SIZE;
    NTSTATUS    ntStatus;
    ULONG       returnedLength = 0;

    if (ReturnLength)
        *ReturnLength = 0;

    buffer = AllocMem((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQuerySystemInformation(
        SystemInformationClass,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        FreeMem(buffer);
        bufferSize <<= 1;

        if (bufferSize > MAX_NTSUP_BUFFER_SIZE)
            return NULL;

        buffer = AllocMem((SIZE_T)bufferSize);
        if (buffer == NULL)
            return NULL;
    }

    if (ReturnLength)
        *ReturnLength = returnedLength;

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    FreeMem(buffer);
    return NULL;
}

/*
* ntsupGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given SystemInformationClass.
*
* Returned buffer must be freed with ntsupHeapFree after usage.
*
*/
PVOID ntsupGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetSystemInfoEx(
        SystemInformationClass,
        ReturnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);
}

/*
* ntsupResolveSymbolicLink
*
* Purpose:
*
* Resolve symbolic link target and copy it to the supplied buffer.
*
* Return FALSE on any error.
*
*/
BOOL ntsupResolveSymbolicLink(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING LinkName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cbBuffer //size of buffer in bytes
)
{
    BOOL                bResult = FALSE;
    HANDLE              linkHandle = NULL;
    DWORD               cLength = 0;
    NTSTATUS            ntStatus;
    UNICODE_STRING      infoUString;
    OBJECT_ATTRIBUTES   objectAttr;

    if ((cbBuffer == 0) || (Buffer == NULL)) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return bResult;
    }

    InitializeObjectAttributes(&objectAttr,
        LinkName, OBJ_CASE_INSENSITIVE, RootDirectoryHandle, NULL);

    ntStatus = NtOpenSymbolicLinkObject(&linkHandle,
        SYMBOLIC_LINK_QUERY,
        &objectAttr);

    if (!NT_SUCCESS(ntStatus) || (linkHandle == NULL)) {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
        return bResult;
    }

    cLength = (DWORD)(cbBuffer - sizeof(UNICODE_NULL));
    if (cLength >= MAX_USTRING) {
        cLength = MAX_USTRING - sizeof(UNICODE_NULL);
    }

    infoUString.Buffer = Buffer;
    infoUString.Length = (USHORT)cLength;
    infoUString.MaximumLength = (USHORT)(cLength + sizeof(UNICODE_NULL));

    ntStatus = NtQuerySymbolicLinkObject(linkHandle,
        &infoUString,
        NULL);

    bResult = (NT_SUCCESS(ntStatus));
    NtClose(linkHandle);
    return bResult;
}

/*
* ntsupQueryThreadWin32StartAddress
*
* Purpose:
*
* Lookups thread win32 start address.
*
*/
BOOL ntsupQueryThreadWin32StartAddress(
    _In_ HANDLE ThreadHandle,
    _Out_ PULONG_PTR Win32StartAddress
)
{
    ULONG returnLength;
    NTSTATUS ntStatus;
    ULONG_PTR win32StartAddress = 0;

    ntStatus = NtQueryInformationThread(
        ThreadHandle,
        ThreadQuerySetWin32StartAddress,
        &win32StartAddress,
        sizeof(ULONG_PTR),
        &returnLength);

    if (Win32StartAddress)
        *Win32StartAddress = win32StartAddress;

    return NT_SUCCESS(ntStatus);
}

/*
* ntsupOpenDirectoryEx
*
* Purpose:
*
* Open directory handle with DIRECTORY_QUERY access, with root directory support.
*
*/
_Success_(return)
NTSTATUS ntsupOpenDirectoryEx(
    _Out_ PHANDLE DirectoryHandle,
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING DirectoryName,
    _In_ ACCESS_MASK DesiredAccess
)
{
    NTSTATUS          ntStatus;
    HANDLE            directoryHandle = NULL;
    OBJECT_ATTRIBUTES objectAttrbutes;

    InitializeObjectAttributes(&objectAttrbutes,
        DirectoryName, OBJ_CASE_INSENSITIVE, RootDirectoryHandle, NULL);

    ntStatus = NtOpenDirectoryObject(&directoryHandle,
        DesiredAccess,
        &objectAttrbutes);

    *DirectoryHandle = directoryHandle;

    return ntStatus;
}

/*
* ntsupOpenDirectory
*
* Purpose:
*
* Open directory handle with DIRECTORY_QUERY access, with root directory support.
*
*/
NTSTATUS ntsupOpenDirectory(
    _Out_ PHANDLE DirectoryHandle,
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ LPCWSTR DirectoryName,
    _In_ ACCESS_MASK DesiredAccess
)
{
    UNICODE_STRING usName;

    RtlInitUnicodeString(&usName, DirectoryName);
    return ntsupOpenDirectoryEx(DirectoryHandle, RootDirectoryHandle, &usName, DesiredAccess);
}

/*
* ntsupQueryProcessName
*
* Purpose:
*
* Lookups process name by given process ID.
*
* If nothing found return FALSE.
*
*/
BOOL ntsupQueryProcessName(
    _In_ ULONG_PTR dwProcessId,
    _In_ PVOID ProcessList,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    ULONG NextEntryDelta = 0, iteration = 0;

    union {
        PSYSTEM_PROCESS_INFORMATION Process;
        PBYTE ListRef;
    } List;

    List.ListRef = (PBYTE)ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        if ((ULONG_PTR)List.Process->UniqueProcessId == dwProcessId) {

            _strncpy(
                Buffer,
                ccBuffer,
                List.Process->ImageName.Buffer,
                List.Process->ImageName.Length / sizeof(WCHAR));

            return TRUE;
        }

        NextEntryDelta = List.Process->NextEntryDelta;
        if (++iteration > MAX_NTSUP_PROCESS_ENUM_ITER)
            break;

    } while (NextEntryDelta);

    return FALSE;
}

/*
* ntsupQueryProcessEntryById
*
* Purpose:
*
* Lookups process entry by given process id.
*
* If nothing found return FALSE.
*
*/
BOOL ntsupQueryProcessEntryById(
    _In_ HANDLE UniqueProcessId,
    _In_ PVOID ProcessList,
    _Out_ PSYSTEM_PROCESS_INFORMATION* Entry
)
{
    ULONG NextEntryDelta = 0, iteration = 0;

    union {
        PSYSTEM_PROCESS_INFORMATION Process;
        PBYTE ListRef;
    } List;

    List.ListRef = (PBYTE)ProcessList;

    *Entry = NULL;

    do {

        List.ListRef += NextEntryDelta;

        if (List.Process->UniqueProcessId == UniqueProcessId) {
            *Entry = List.Process;
            return TRUE;
        }

        NextEntryDelta = List.Process->NextEntryDelta;
        if (++iteration > MAX_NTSUP_PROCESS_ENUM_ITER)
            break;

    } while (NextEntryDelta);

    return FALSE;
}

/*
* ntsupQueryProcessImageFileNameByProcessId
*
* Purpose:
*
* Query image path for given process id in NT format.
*
* Use FreeMem to release allocated buffer.
*
*/
NTSTATUS ntsupQueryProcessImageFileNameByProcessId(
    _In_ HANDLE UniqueProcessId,
    _Out_ PUNICODE_STRING ProcessImageFileName,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem
)
{
    NTSTATUS ntStatus;
    SYSTEM_PROCESS_ID_INFORMATION processData;

    processData.ProcessId = UniqueProcessId;
    processData.ImageName.Length = 0;
    processData.ImageName.MaximumLength = 256;

    do {

        processData.ImageName.Buffer = (PWSTR)AllocMem(processData.ImageName.MaximumLength);
        if (processData.ImageName.Buffer == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        ntStatus = NtQuerySystemInformation(SystemProcessIdInformation,
            (PVOID)&processData,
            sizeof(SYSTEM_PROCESS_ID_INFORMATION),
            NULL);

        if (!NT_SUCCESS(ntStatus))
            FreeMem(processData.ImageName.Buffer);

    } while (ntStatus == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    *ProcessImageFileName = processData.ImageName;

    return ntStatus;
}

/*
* ntsupQuerySystemObjectInformationVariableSize
*
* Purpose:
*
* Generic object information query routine.
*
* Use FreeMem to release allocated buffer.
*
*/
NTSTATUS ntsupQuerySystemObjectInformationVariableSize(
    _In_ PFN_NTQUERYROUTINE QueryRoutine,
    _In_opt_ HANDLE ObjectHandle,
    _In_ DWORD InformationClass,
    _Out_ PVOID* Buffer,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem
)
{
    NTSTATUS ntStatus;
    PVOID queryBuffer;
    ULONG returnLengthLocal = 0;

    *Buffer = NULL;
    if (ReturnLength) *ReturnLength = 0;

    ntStatus = QueryRoutine(ObjectHandle,
        InformationClass,
        NULL,
        0,
        &returnLengthLocal);

    //
    // Test all possible acceptable failures.
    //
    if (ntStatus != STATUS_BUFFER_OVERFLOW &&
        ntStatus != STATUS_BUFFER_TOO_SMALL &&
        ntStatus != STATUS_INFO_LENGTH_MISMATCH)
    {
        return ntStatus;
    }

    if (returnLengthLocal == 0 || returnLengthLocal > MAX_NTSUP_BUFFER_SIZE)
        return STATUS_INVALID_BUFFER_SIZE;

    queryBuffer = AllocMem(returnLengthLocal);
    if (queryBuffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    ntStatus = QueryRoutine(ObjectHandle,
        InformationClass,
        queryBuffer,
        returnLengthLocal,
        &returnLengthLocal);

    if (NT_SUCCESS(ntStatus)) {
        *Buffer = queryBuffer;
        if (ReturnLength) *ReturnLength = returnLengthLocal;
    }
    else {
        FreeMem(queryBuffer);
    }

    return ntStatus;
}

/*
* ntsupQueryVsmProtectionInformation
*
* Purpose:
*
* Query VSM protection information.
*
*/
BOOLEAN ntsupQueryVsmProtectionInformation(
    _Out_ PBOOLEAN pbDmaProtectionsAvailable,
    _Out_ PBOOLEAN pbDmaProtectionsInUse,
    _Out_ PBOOLEAN pbHardwareMbecAvailable,
    _Out_ PBOOLEAN pbApicVirtualizationAvailable
)
{
    NTSTATUS ntStatus;
    ULONG returnLength;
    SYSTEM_VSM_PROTECTION_INFORMATION svpi;

    if (pbDmaProtectionsAvailable) *pbDmaProtectionsAvailable = FALSE;
    if (pbDmaProtectionsInUse) *pbDmaProtectionsInUse = FALSE;
    if (pbHardwareMbecAvailable) *pbHardwareMbecAvailable = FALSE;
    if (pbApicVirtualizationAvailable) *pbApicVirtualizationAvailable = FALSE;

    RtlSecureZeroMemory(&svpi, sizeof(SYSTEM_VSM_PROTECTION_INFORMATION));

    ntStatus = NtQuerySystemInformation(
        SystemVsmProtectionInformation,
        &svpi,
        sizeof(SYSTEM_VSM_PROTECTION_INFORMATION),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {
        if (pbDmaProtectionsAvailable) *pbDmaProtectionsAvailable = svpi.DmaProtectionsAvailable;
        if (pbDmaProtectionsInUse) *pbDmaProtectionsInUse = svpi.DmaProtectionsInUse;
        if (pbHardwareMbecAvailable) *pbHardwareMbecAvailable = svpi.HardwareMbecAvailable;
        if (pbApicVirtualizationAvailable) *pbApicVirtualizationAvailable = svpi.ApicVirtualizationAvailable;
        return TRUE;
    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }

    return FALSE;
}

/*
* ntsupQueryHVCIState
*
* Purpose:
*
* Query HVCI/IUM state.
*
*/
BOOLEAN ntsupQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled
)
{
    BOOLEAN hvciEnabled;
    ULONG returnLength;
    NTSTATUS ntStatus;
    SYSTEM_CODEINTEGRITY_INFORMATION ci;

    if (pbHVCIEnabled) *pbHVCIEnabled = FALSE;
    if (pbHVCIStrictMode) *pbHVCIStrictMode = FALSE;
    if (pbHVCIIUMEnabled) *pbHVCIIUMEnabled = FALSE;

    ci.Length = sizeof(ci);

    ntStatus = NtQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &ci,
        sizeof(ci),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {

        hvciEnabled = ((ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) &&
            (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED));

        if (pbHVCIEnabled)
            *pbHVCIEnabled = hvciEnabled;

        if (pbHVCIStrictMode)
            *pbHVCIStrictMode = (hvciEnabled == TRUE) &&
            (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED);

        if (pbHVCIIUMEnabled)
            *pbHVCIIUMEnabled = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) > 0;

        return TRUE;
    }
    else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    }

    return FALSE;
}

/*
* ntsupLookupImageSectionByName
*
* Purpose:
*
* Lookup section pointer and size for section name.
*
*/
PVOID ntsupLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize
)
{
    BOOLEAN bFound = FALSE;
    ULONG i;
    PVOID Section;
    IMAGE_NT_HEADERS* NtHeaders = RtlImageNtHeader(DllBase);
    IMAGE_SECTION_HEADER* SectionTableEntry;

    //
    // Assume failure.
    //
    if (SectionSize)
        *SectionSize = 0;

    if (NtHeaders == NULL)
        return NULL;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    //
    // Locate section.
    //
    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {

        if (_strncmp_a(
            (CHAR*)SectionTableEntry->Name,
            SectionName,
            SectionNameLength) == 0)
        {
            bFound = TRUE;
            break;
        }

        i -= 1;
        SectionTableEntry += 1;
    }

    //
    // Section not found, abort scan.
    //
    if (!bFound)
        return NULL;

    Section = (PVOID)((ULONG_PTR)DllBase + SectionTableEntry->VirtualAddress);
    if (SectionSize)
        *SectionSize = SectionTableEntry->Misc.VirtualSize;

    return Section;
}

/*
* ntsupFindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID ntsupFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize
)
{
    PBYTE p0 = Buffer, pnext;

    if (PatternSize == 0)
        return NULL;

    if (BufferSize < PatternSize)
        return NULL;

    do {
        pnext = (PBYTE)memchr(p0, Pattern[0], BufferSize);
        if (pnext == NULL)
            break;

        BufferSize -= (ULONG_PTR)(pnext - p0);

        if (BufferSize < PatternSize)
            return NULL;

        if (memcmp(pnext, Pattern, PatternSize) == 0)
            return pnext;

        p0 = pnext + 1;
        --BufferSize;
    } while (BufferSize > 0);

    return NULL;
}

/*
* ntsupFindPatternEx
*
* Purpose:
*
* Lookup pattern in buffer with specified mask.
*
*/
DWORD ntsupFindPatternEx(
    _In_ PATTERN_SEARCH_PARAMS* SearchParams
)
{
    PBYTE   p;
    DWORD   c, i, n;
    BOOLEAN found;
    BYTE    low, high;

    DWORD   bufferSize;

    if (SearchParams == NULL)
        return 0;

    if ((SearchParams->PatternSize == 0) || (SearchParams->PatternSize > SearchParams->BufferSize))
        return 0;

    bufferSize = SearchParams->BufferSize - SearchParams->PatternSize;

    for (n = 0, p = SearchParams->Buffer, c = 0; c <= bufferSize; ++p, ++c)
    {
        found = 1;
        for (i = 0; i < SearchParams->PatternSize; ++i)
        {
            low = p[i] & 0x0f;
            high = p[i] & 0xf0;

            if (SearchParams->Mask[i] & 0xf0)
            {
                if (high != (SearchParams->Pattern[i] & 0xf0))
                {
                    found = 0;
                    break;
                }
            }

            if (SearchParams->Mask[i] & 0x0f)
            {
                if (low != (SearchParams->Pattern[i] & 0x0f))
                {
                    found = 0;
                    break;
                }
            }

        }

        if (found) {

            if (SearchParams->Callback(p,
                SearchParams->PatternSize,
                SearchParams->CallbackContext))
            {
                return n + 1;
            }

            n++;
        }
    }

    return n;
}

/*
* ntsupOpenProcess
*
* Purpose:
*
* NtOpenProcess wrapper.
*
*/
NTSTATUS ntsupOpenProcess(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    NTSTATUS ntStatus;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);
    CLIENT_ID ClientId;

    ClientId.UniqueProcess = UniqueProcessId;
    ClientId.UniqueThread = NULL;

    ntStatus = NtOpenProcess(
        &processHandle,
        DesiredAccess,
        &objectAttributes,
        &ClientId);

    if (NT_SUCCESS(ntStatus)) {
        *ProcessHandle = processHandle;
    }

    return ntStatus;
}

/*
* ntsupOpenThread
*
* Purpose:
*
* NtOpenThread wrapper.
*
*/
NTSTATUS ntsupOpenThread(
    _In_ PCLIENT_ID ClientId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ThreadHandle
)
{
    NTSTATUS ntStatus;
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    ntStatus = NtOpenThread(
        &threadHandle,
        DesiredAccess,
        &objectAttributes,
        ClientId);

    if (NT_SUCCESS(ntStatus)) {
        *ThreadHandle = threadHandle;
    }

    return ntStatus;
}

/*
* ntsupCICustomKernelSignersAllowed
*
* Purpose:
*
* Return license state if present (EnterpriseG).
*
*/
NTSTATUS ntsupCICustomKernelSignersAllowed(
    _Out_ PBOOLEAN bAllowed)
{
    NTSTATUS ntStatus;
    ULONG uLicense = 0, dataSize;
    UNICODE_STRING usLicenseValue = RTL_CONSTANT_STRING(L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners");

    *bAllowed = FALSE;

    ntStatus = NtQueryLicenseValue(
        &usLicenseValue,
        NULL,
        (PVOID)&uLicense,
        sizeof(DWORD),
        &dataSize);

    if (NT_SUCCESS(ntStatus)) {
        *bAllowed = (uLicense != 0);
    }
    return ntStatus;
}

/*
* ntsupPrivilegeEnabled
*
* Purpose:
*
* Tests if the given token has the given privilege enabled/enabled by default.
*
*/
NTSTATUS ntsupPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ LPBOOL pfResult
)
{
    NTSTATUS status;
    PRIVILEGE_SET Privs;
    BOOLEAN bResult = FALSE;

    Privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privs.PrivilegeCount = 1;
    Privs.Privilege[0].Luid.LowPart = Privilege;
    Privs.Privilege[0].Luid.HighPart = 0;
    Privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;

    status = NtPrivilegeCheck(ClientToken, &Privs, &bResult);

    *pfResult = bResult;

    return status;
}

/*
* ntsupQueryEnvironmentVariableOffset
*
* Purpose:
*
* Return offset to the given environment variable.
*
*/
LPWSTR ntsupQueryEnvironmentVariableOffset(
    _In_ PUNICODE_STRING Value
)
{
    UNICODE_STRING   str1;
    PWCHAR           ptrEnvironment;
    ULONG            scanCount = 0;

    ptrEnvironment = (PWCHAR)RtlGetCurrentPeb()->ProcessParameters->Environment;

    do {
        if (*ptrEnvironment == 0 || scanCount++ > MAX_NTSUP_ENV_SCAN)
            return 0;

        RtlInitUnicodeString(&str1, ptrEnvironment);
        if (RtlPrefixUnicodeString(Value, &str1, TRUE))
            break;

        ptrEnvironment += _strlen(ptrEnvironment) + 1;

    } while (1);

    return (ptrEnvironment + Value->Length / sizeof(WCHAR));
}

/*
* ntsupExpandEnvironmentStrings
*
* Purpose:
*
* Reimplemented ExpandEnvironmentStrings.
*
*/
DWORD ntsupExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize
)
{
    NTSTATUS ntStatus;
    SIZE_T srcLength = 0, returnLength = 0, dstLength = (SIZE_T)nSize;

    if (lpSrc) {
        srcLength = _strlen(lpSrc);
    }

    ntStatus = RtlExpandEnvironmentStrings(
        NULL,
        (PWSTR)lpSrc,
        srcLength,
        (PWSTR)lpDst,
        dstLength,
        &returnLength);

    if ((NT_SUCCESS(ntStatus)) || (ntStatus == STATUS_BUFFER_TOO_SMALL)) {

        if (returnLength <= MAXDWORD32)
            return (DWORD)returnLength;

        ntStatus = STATUS_UNSUCCESSFUL;
    }
    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return 0;
}

/*
* ntsupIsUserHasInteractiveSid
*
* Purpose:
*
* pbInteractiveSid will be set to TRUE if current user has interactive sid, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS ntsupIsUserHasInteractiveSid(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbInteractiveSid)
{
    BOOL isInteractiveSid = FALSE;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE heapHandle = NtCurrentPeb()->ProcessHeap;
    ULONG neededLength = 0;

    DWORD i;

    SID_IDENTIFIER_AUTHORITY SidAuth = SECURITY_NT_AUTHORITY;
    PSID pInteractiveSid = NULL;
    PTOKEN_GROUPS groupInfo = NULL;

    do {

        ntStatus = NtQueryInformationToken(
            hToken,
            TokenGroups,
            NULL,
            0,
            &neededLength);

        if (ntStatus != STATUS_BUFFER_TOO_SMALL)
            break;

        groupInfo = (PTOKEN_GROUPS)RtlAllocateHeap(
            heapHandle,
            HEAP_ZERO_MEMORY,
            neededLength);

        if (groupInfo == NULL)
            break;

        ntStatus = NtQueryInformationToken(
            hToken,
            TokenGroups,
            groupInfo,
            neededLength,
            &neededLength);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlAllocateAndInitializeSid(
            &SidAuth,
            1,
            SECURITY_INTERACTIVE_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pInteractiveSid);

        if (!NT_SUCCESS(ntStatus))
            break;

        for (i = 0; i < groupInfo->GroupCount; i++) {

            if (RtlEqualSid(
                pInteractiveSid,
                groupInfo->Groups[i].Sid))
            {
                isInteractiveSid = TRUE;
                break;
            }
        }

    } while (FALSE);

    if (groupInfo != NULL)
        RtlFreeHeap(heapHandle, 0, groupInfo);

    if (pbInteractiveSid)
        *pbInteractiveSid = isInteractiveSid;

    if (pInteractiveSid)
        RtlFreeSid(pInteractiveSid);

    return ntStatus;
}

/*
* ntsupIsLocalSystem
*
* Purpose:
*
* pbResult will be set to TRUE if current account is run by system user, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS ntsupIsLocalSystem(
    _Out_ PBOOL pbResult)
{
    BOOL                            bResult = FALSE;

    NTSTATUS                        ntStatus;
    HANDLE                          tokenHandle = NULL;
    HANDLE                          heapHandle = NtCurrentPeb()->ProcessHeap;

    ULONG                           neededLength = 0;

    PSID                            systemSid = NULL;
    PTOKEN_USER                     ptu = NULL;
    SID_IDENTIFIER_AUTHORITY        ntAuthority = SECURITY_NT_AUTHORITY;

    ntStatus = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtQueryInformationToken(
            tokenHandle,
            TokenUser,
            NULL,
            0,
            &neededLength);

        if (ntStatus == STATUS_BUFFER_TOO_SMALL) {

            ptu = (PTOKEN_USER)RtlAllocateHeap(
                heapHandle,
                HEAP_ZERO_MEMORY,
                neededLength);

            if (ptu) {

                ntStatus = NtQueryInformationToken(
                    tokenHandle,
                    TokenUser,
                    ptu,
                    neededLength,
                    &neededLength);

                if (NT_SUCCESS(ntStatus)) {

                    ntStatus = RtlAllocateAndInitializeSid(
                        &ntAuthority,
                        1,
                        SECURITY_LOCAL_SYSTEM_RID,
                        0, 0, 0, 0, 0, 0, 0,
                        &systemSid);

                    if (NT_SUCCESS(ntStatus)) {

                        bResult = RtlEqualSid(
                            ptu->User.Sid,
                            systemSid);

                        RtlFreeSid(systemSid);
                    }

                }
                RtlFreeHeap(heapHandle, 0, ptu);
            }
            else {
                ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            }
        } //STATUS_BUFFER_TOO_SMALL
        NtClose(tokenHandle);
    }

    if (pbResult)
        *pbResult = bResult;

    return ntStatus;
}

/*
* ntsupGetProcessElevationType
*
* Purpose:
*
* Returns process elevation type.
*
*/
BOOL ntsupGetProcessElevationType(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ TOKEN_ELEVATION_TYPE * lpType
)
{
    HANDLE tokenHandle = NULL, processHandle = ProcessHandle;
    NTSTATUS ntStatus;
    ULONG returnedLength = 0;
    TOKEN_ELEVATION_TYPE tokenType = TokenElevationTypeDefault;

    if (ProcessHandle == NULL) {
        processHandle = GetCurrentProcess();
    }

    ntStatus = NtOpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle);
    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtQueryInformationToken(
            tokenHandle,
            TokenElevationType,
            &tokenType,
            sizeof(TOKEN_ELEVATION_TYPE),
            &returnedLength);

        NtClose(tokenHandle);
    }

    if (lpType)
        *lpType = tokenType;

    return (NT_SUCCESS(ntStatus));
}

/*
* ntsupIsProcessElevated
*
* Purpose:
*
* Returns process elevation state.
*
*/
NTSTATUS ntsupIsProcessElevated(
    _In_ ULONG ProcessId,
    _Out_ PBOOL Elevated)
{
    NTSTATUS ntStatus;
    ULONG returnedLength;
    HANDLE processHandle = NULL, tokenHandle = NULL;
    TOKEN_ELEVATION tokenInfo;

    if (Elevated) *Elevated = FALSE;

    ntStatus = ntsupOpenProcess(
        UlongToHandle(ProcessId),
        MAXIMUM_ALLOWED,
        &processHandle);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = NtOpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle);
        if (NT_SUCCESS(ntStatus)) {

            tokenInfo.TokenIsElevated = 0;
            ntStatus = NtQueryInformationToken(
                tokenHandle,
                TokenElevation,
                &tokenInfo,
                sizeof(TOKEN_ELEVATION),
                &returnedLength);

            if (NT_SUCCESS(ntStatus)) {

                if (Elevated)
                    *Elevated = (tokenInfo.TokenIsElevated > 0);

            }

            NtClose(tokenHandle);
        }
        NtClose(processHandle);
    }

    return ntStatus;
}

/*
* ntsupPurgeSystemCache
*
* Purpose:
*
* Flush file cache and memory standby list.
*
*/
VOID ntsupPurgeSystemCache(
    VOID
)
{
    SYSTEM_FILECACHE_INFORMATION sfc;
    SYSTEM_MEMORY_LIST_COMMAND smlc;

    //flush file system cache
    if (ntsupEnablePrivilege(SE_INCREASE_QUOTA_PRIVILEGE, TRUE)) {
        RtlSecureZeroMemory(&sfc, sizeof(SYSTEM_FILECACHE_INFORMATION));
        sfc.MaximumWorkingSet = (SIZE_T)-1;
        sfc.MinimumWorkingSet = (SIZE_T)-1;
        NtSetSystemInformation(SystemFileCacheInformation, (PVOID)&sfc, sizeof(sfc));
    }

    //flush standby list
    if (ntsupEnablePrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE)) {
        smlc = MemoryPurgeStandbyList;
        NtSetSystemInformation(SystemMemoryListInformation, (PVOID)&smlc, sizeof(smlc));
    }
}

/*
* ntsupGetSystemRoot
*
* Purpose:
*
* Return system root directory silo session aware.
*
*/
PWSTR ntsupGetSystemRoot(
    VOID
)
{
    PEB* peb = NtCurrentPeb();

    if (peb->SharedData && peb->SharedData->ServiceSessionId)
        return peb->SharedData->NtSystemRoot;
    else
        return USER_SHARED_DATA->NtSystemRoot;
}

/*
* ntsupGetProcessDebugObject
*
* Purpose:
*
* Reference process debug object.
*
*/
NTSTATUS ntsupGetProcessDebugObject(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE DebugObjectHandle
)
{
    return NtQueryInformationProcess(
        ProcessHandle,
        ProcessDebugObjectHandle,
        DebugObjectHandle,
        sizeof(HANDLE),
        NULL);
}

/*
* ntsupQueryResourceData
*
* Purpose:
*
* Load resource by given id (win32 FindResource, SizeofResource, LockResource).
*
*/
PBYTE ntsupQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize
)
{
    NTSTATUS                   ntStatus;
    ULONG_PTR                  idPath[3];
    IMAGE_RESOURCE_DATA_ENTRY* dataEntry;
    PBYTE                      dataPtr = NULL;
    ULONG                      dataSize = 0;

    if (DataSize) {
        *DataSize = 0;
    }

    if (DllHandle != NULL) {

        idPath[0] = (ULONG_PTR)RT_RCDATA; //type
        idPath[1] = ResourceId;           //id
        idPath[2] = 0;                    //lang

        ntStatus = LdrFindResource_U(DllHandle, (ULONG_PTR*)&idPath, 3, &dataEntry);
        if (NT_SUCCESS(ntStatus)) {
            ntStatus = LdrAccessResource(DllHandle, dataEntry, (PVOID*)&dataPtr, &dataSize);
            if (NT_SUCCESS(ntStatus)) {
                if (DataSize) {
                    *DataSize = dataSize;
                }
            }
        }
    }
    return dataPtr;
}

/*
* ntsupEnableWow64Redirection
*
* Purpose:
*
* Enable/Disable Wow64 redirection.
*
*/
NTSTATUS ntsupEnableWow64Redirection(
    _In_ BOOLEAN bEnable
)
{
    PVOID OldValue = NULL, Value;

    Value = IntToPtr(bEnable);
    return RtlWow64EnableFsRedirectionEx(Value, &OldValue);
}

/*
* ntsupDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI ntsupDetectObjectCallback(
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
* ntsupEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI ntsupEnumSystemObjects(
    _In_opt_ LPCWSTR pwszRootDirectory,
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

        objinf = (POBJECT_DIRECTORY_INFORMATION)ntsupHeapAlloc(rlen);
        if (objinf == NULL)
            break;

        status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
        if (!NT_SUCCESS(status)) {
            ntsupHeapFree(objinf);
            break;
        }

        CallbackStatus = CallbackProc(objinf, CallbackParam);

        ntsupHeapFree(objinf);

        if (NT_SUCCESS(CallbackStatus)) {
            status = STATUS_SUCCESS;
            break;
        }

    } while (TRUE);

    if (hDirectory != NULL) {
        NtClose(hDirectory);
    }

    return status;
}

/*
* ntsupIsObjectExists
*
* Purpose:
*
* Return TRUE if the given object exists, FALSE otherwise.
*
*/
BOOLEAN ntsupIsObjectExists(
    _In_ LPCWSTR RootDirectory,
    _In_ LPCWSTR ObjectName
)
{
    OBJSCANPARAM Param;

    Param.Buffer = ObjectName;
    Param.BufferSize = (ULONG)_strlen(ObjectName);

    return NT_SUCCESS(ntsupEnumSystemObjects(RootDirectory, NULL, ntsupDetectObjectCallback, &Param));
}

/*
* ntsupUserIsFullAdmin
*
* Purpose:
*
* Tests if the current user is admin with full access token.
*
*/
BOOLEAN ntsupUserIsFullAdmin(
    VOID
)
{
    BOOLEAN  bResult = FALSE;
    HANDLE   hToken = NULL;
    NTSTATUS status;
    DWORD    i, Attributes;
    ULONG    ReturnLength = 0;

    PTOKEN_GROUPS pTkGroups;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = NULL;

    hToken = ntsupGetCurrentProcessToken();
    if (hToken) {
        if (NT_SUCCESS(RtlAllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &AdministratorsGroup)))
        {
            status = ntsupQueryTokenInformation(hToken,
                TokenGroups,
                &pTkGroups,
                &ReturnLength,
                (PNTSUPMEMALLOC)ntsupHeapAlloc,
                (PNTSUPMEMFREE)ntsupHeapFree);

            if (NT_SUCCESS(status)) {

                for (i = 0; i < pTkGroups->GroupCount; i++) {

                    Attributes = pTkGroups->Groups[i].Attributes;

                    if (RtlEqualSid(AdministratorsGroup, pTkGroups->Groups[i].Sid))
                        if (
                            (Attributes & SE_GROUP_ENABLED) &&
                            (!(Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
                            )
                        {
                            bResult = TRUE;
                            break;
                        }

                }

                ntsupHeapFree(pTkGroups);
            }
            RtlFreeSid(AdministratorsGroup);
        }

        NtClose(hToken);
    }
    return bResult;
}

/*
* ntsupHashImageSections
*
* Purpose:
*
* Produce a SHA-256 hash for a PE image mapping in memory (either a raw
* file mapping or a loaded module) by hashing the PE headers plus every
* executable section.
*
*/
NTSTATUS ntsupHashImageSections(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,          // Size of image mapping
    _Out_writes_bytes_(HashBufferSize) PBYTE HashBuffer,
    _In_ SIZE_T HashBufferSize,
    _In_ NTSUP_IMAGE_TYPE ImageType
)
{
    BOOL anySectionHashed;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeader;
    ULONG numberOfSections, i;
    ULONG_PTR baseAddress = (ULONG_PTR)ImageBase;
    NTSUP_SHA256_CTX ctx;
    ULONG_PTR sectionStart, headersEnd;
    SIZE_T toHash, sizeOfHeaders, maxVirtualSize, maxRawSize, maxSafeSize;

    //
    // Validate parameters.
    //
    if (ImageBase == NULL || HashBuffer == NULL)
        return STATUS_INVALID_PARAMETER;

    if (HashBufferSize < NTSUPHASH_SHA256_SIZE)
        return STATUS_BUFFER_TOO_SMALL;

    if (ImageSize == 0)
        return STATUS_INVALID_PARAMETER;

    //
    // Get NT headers with boundary check.
    //
    if (!NT_SUCCESS(RtlImageNtHeaderEx(0,
        ImageBase,
        ImageSize,
        (PIMAGE_NT_HEADERS*)&ntHeaders)) || ntHeaders == NULL) 
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (ntHeaders->OptionalHeader.SizeOfImage == 0)
        return STATUS_INVALID_IMAGE_FORMAT;

    //
    // Validate image size matches reported size.
    //
    if (ntHeaders->OptionalHeader.SizeOfImage > ImageSize &&
        ImageType == ImageTypeLoaded) 
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    numberOfSections = ntHeaders->FileHeader.NumberOfSections;

    //
    // Validate section headers are within image bounds.
    //
    if (numberOfSections == 0 ||
        numberOfSections > (MAXULONG_PTR / sizeof(IMAGE_SECTION_HEADER)))
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    headersEnd = (ULONG_PTR)sectionHeader +
        (numberOfSections * sizeof(IMAGE_SECTION_HEADER));

    if (headersEnd < (ULONG_PTR)sectionHeader ||
        headersEnd > baseAddress + ImageSize)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntsupSha256Init(&ctx);

    //
    // Hash PE headers first.
    //
    sizeOfHeaders = min(ntHeaders->OptionalHeader.SizeOfHeaders, ImageSize);
    if (sizeOfHeaders) {
        ntsupSha256Update(&ctx, (PUCHAR)ImageBase, sizeOfHeaders);
    }

    anySectionHashed = FALSE;

    //
    // Process each section.
    //
    for (i = 0; i < numberOfSections; i++, sectionHeader++) {
        // Only hash executable sections
        if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;

        //
        // Determine section location based on image type.
        //
        if (ImageType == ImageTypeLoaded) {
            //
            // For loaded modules: use virtual addresses.
            //
            if (sectionHeader->VirtualAddress == 0 ||
                sectionHeader->Misc.VirtualSize == 0) {
                continue;
            }

            //
            // Skip sections outside loaded image.
            //
            if (sectionHeader->VirtualAddress >= ntHeaders->OptionalHeader.SizeOfImage) {
                continue;
            }

            maxVirtualSize = ntHeaders->OptionalHeader.SizeOfImage - sectionHeader->VirtualAddress;
            toHash = min(sectionHeader->Misc.VirtualSize, maxVirtualSize);
            sectionStart = baseAddress + sectionHeader->VirtualAddress;
        }
        else {
            //
            // For raw files: use file offsets.
            //
            if (sectionHeader->PointerToRawData == 0 ||
                sectionHeader->SizeOfRawData == 0) {
                continue;
            }

            //
            // Skip sections outside file.
            //
            if (sectionHeader->PointerToRawData >= ImageSize) {
                continue;
            }

            maxRawSize = ImageSize - sectionHeader->PointerToRawData;
            toHash = min(sectionHeader->SizeOfRawData, maxRawSize);
            sectionStart = baseAddress + sectionHeader->PointerToRawData;
        }

        if (sectionStart < baseAddress ||
            sectionStart >= baseAddress + ImageSize) 
        {
            continue;
        }

        maxSafeSize = (baseAddress + ImageSize) - sectionStart;
        if (toHash > maxSafeSize) {
            toHash = maxSafeSize;
        }

        ntsupSha256Update(&ctx, (PUCHAR)sectionStart, toHash);
        anySectionHashed = TRUE;
    }

    //
    // Return header-only hash if no executable sections found.
    //
    ntsupSha256Final(&ctx, HashBuffer);
    if (!anySectionHashed)
        return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}

#pragma warning(pop)
