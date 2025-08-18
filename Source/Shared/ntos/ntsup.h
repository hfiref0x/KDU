/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2011 - 2025 UGN/HE
*
*  TITLE:       NTSUP.H
*
*  VERSION:     2.25
*
*  DATE:        18 Aug 2025
*
*  Common header file for the NT API support functions and definitions.
*
*  Depends on:    ntos.h
*                 minirtl
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#define ENABLE_C_EXTERN

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef NTSUP_RTL
#define NTSUP_RTL

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int
#pragma warning(disable: 26812) // enum type % is unscoped

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#pragma warning(push)
#pragma warning(disable: 4005) //macro redefinition
#include <ntstatus.h>
#pragma warning(pop)

#include "ntos.h"

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "minirtl/minirtl.h"

#ifdef ENABLE_C_EXTERN
#if defined(__cplusplus)
extern "C" {
#endif
#endif

typedef NTSTATUS(NTAPI* PFN_NTQUERYROUTINE)(
   _In_opt_ HANDLE ObjectHandle,
   _In_ DWORD InformationClass,
   _Out_writes_bytes_(ObjectInformationLength) PVOID ObjectInformation,
   _In_ ULONG ObjectInformationLength,
   _Out_opt_ PULONG ReturnLength);

typedef PVOID(CALLBACK* PNTSUPMEMALLOC)(
    _In_ SIZE_T NumberOfBytes);

typedef BOOL(CALLBACK* PNTSUPMEMFREE)(
    _In_ PVOID Memory);

#define ntsupProcessHeap() NtCurrentPeb()->ProcessHeap

#define NTSUPHASH_SHA256_SIZE 32

#define MAX_NTSUP_BUFFER_SIZE (512 * 1024 * 1024) //512MB
#define MAX_NTSUP_ENV_SCAN 4096
#define MAX_NTSUP_PROCESS_ENUM_ITER (1024 * 1024)
#define MAX_NTSUP_WRITE_CHUNK 0x7FFFFFFF

typedef struct _OBJSCANPARAM {
    PCWSTR Buffer;
    ULONG BufferSize;
} OBJSCANPARAM, * POBJSCANPARAM;

typedef NTSTATUS(NTAPI* PENUMOBJECTSCALLBACK)(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry, 
    _In_opt_ PVOID CallbackParam);

typedef BOOL(CALLBACK* pfnPatternSearchCallback)(
    _In_ PBYTE Buffer,
    _In_ ULONG PatternSize,
    _In_opt_ PVOID CallbackContext
    );

typedef struct _PATTERN_SEARCH_PARAMS {
    PBYTE Buffer;
    DWORD BufferSize;
    PBYTE Pattern;
    DWORD PatternSize;
    PBYTE Mask;
    pfnPatternSearchCallback Callback;
    PVOID CallbackContext;
} PATTERN_SEARCH_PARAMS, * PPATTERN_SEARCH_PARAMS;

typedef enum _NTSUP_IMAGE_TYPE {
    ImageTypeRaw,       // Raw file mapping (CreateFileMapping)
    ImageTypeLoaded     // Loaded module (PEB/LdrEntry)
} NTSUP_IMAGE_TYPE;

PVOID ntsupHeapAlloc(
    _In_ SIZE_T Size);

VOID ntsupHeapFree(
    _In_ PVOID BaseAddress);

PVOID ntsupVirtualAllocEx(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);

PVOID ntsupVirtualAlloc(
    _In_ SIZE_T Size);

BOOL ntsupVirtualFree(
    _In_ PVOID Memory);

BOOL ntsupVirtualLock(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize);

BOOL ntsupVirtualUnlock(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize);

SIZE_T ntsupWriteBufferToFile(
    _In_ PCWSTR FileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append,
    _Out_opt_ NTSTATUS* Result);

PVOID ntsupGetModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ PVOID Address);

PVOID ntsupFindModuleEntryByName(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ LPCSTR ModuleName);

PVOID ntsupFindModuleEntryByName_U(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ LPCWSTR ModuleName);

BOOL ntsupFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ PVOID Address,
    _Out_ PULONG ModuleIndex);

PVOID ntsupFindModuleNameByAddress(
    _In_ PRTL_PROCESS_MODULES ModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

NTSTATUS ntsupConvertToUnicode(
    _In_ LPCSTR AnsiString,
    _Inout_ PUNICODE_STRING UnicodeString);

NTSTATUS ntsupConvertToAnsi(
    _In_ LPCWSTR UnicodeString,
    _Inout_ PANSI_STRING AnsiString);

BOOLEAN ntsupEnablePrivilege(
    _In_ DWORD Privilege,
    _In_ BOOLEAN Enable);

HANDLE ntsupGetCurrentProcessToken(
    VOID);

ULONG_PTR ntsupQuerySystemRangeStart(
    VOID);

BOOLEAN ntsupQueryUserModeAccessibleRange(
    _Out_ PULONG_PTR MinimumUserModeAddress,
    _Out_ PULONG_PTR MaximumUserModeAddress);

BOOL ntsupIsProcess32bit(
    _In_ HANDLE hProcess);

PVOID ntsupGetLoadedModulesListEx(
    _In_ BOOL ExtendedOutput,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

PVOID ntsupGetLoadedModulesList(
    _Out_opt_ PULONG ReturnLength);

PVOID ntsupGetLoadedModulesList2(
    _Out_opt_ PULONG ReturnLength);

PVOID ntsupGetSystemInfoEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

PVOID ntsupGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength);

NTSTATUS NTAPI ntsupEnumSystemObjects(
    _In_opt_ LPCWSTR pwszRootDirectory,
    _In_opt_ HANDLE hRootDirectory,
    _In_ PENUMOBJECTSCALLBACK CallbackProc,
    _In_opt_ PVOID CallbackParam);

BOOL ntsupResolveSymbolicLink(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING LinkName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cbBuffer);

BOOL ntsupQueryThreadWin32StartAddress(
    _In_ HANDLE ThreadHandle,
    _Out_ PULONG_PTR Win32StartAddress);

_Success_(return)
NTSTATUS ntsupOpenDirectoryEx(
    _Out_ PHANDLE DirectoryHandle,
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING DirectoryName,
    _In_ ACCESS_MASK DesiredAccess);

NTSTATUS ntsupOpenDirectory(
    _Out_ PHANDLE DirectoryHandle,
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ LPCWSTR DirectoryName,
    _In_ ACCESS_MASK DesiredAccess);

BOOL ntsupQueryProcessName(
    _In_ ULONG_PTR dwProcessId,
    _In_ PVOID ProcessList,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer);

BOOL ntsupQueryProcessEntryById(
    _In_ HANDLE UniqueProcessId,
    _In_ PVOID ProcessList,
    _Out_ PSYSTEM_PROCESS_INFORMATION* Entry);

NTSTATUS ntsupQueryProcessImageFileNameByProcessId(
    _In_ HANDLE UniqueProcessId,
    _Out_ PUNICODE_STRING ProcessImageFileName,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

NTSTATUS ntsupQuerySystemObjectInformationVariableSize(
    _In_ PFN_NTQUERYROUTINE QueryRoutine,
    _In_opt_ HANDLE ObjectHandle,
    _In_ DWORD InformationClass,
    _Out_ PVOID* Buffer,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

BOOLEAN ntsupQueryVsmProtectionInformation(
    _Out_ PBOOLEAN pbDmaProtectionsAvailable,
    _Out_ PBOOLEAN pbDmaProtectionsInUse,
    _Out_ PBOOLEAN pbHardwareMbecAvailable,
    _Out_ PBOOLEAN pbApicVirtualizationAvailable);

BOOLEAN ntsupQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled);

PVOID ntsupLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize);

PVOID ntsupFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize);

DWORD ntsupFindPatternEx(
    _In_ PATTERN_SEARCH_PARAMS * SearchParams);

NTSTATUS ntsupOpenProcess(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);

NTSTATUS ntsupOpenThread(
    _In_ PCLIENT_ID ClientId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ThreadHandle);

NTSTATUS ntsupCICustomKernelSignersAllowed(
    _Out_ PBOOLEAN bAllowed);

NTSTATUS ntsupPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ LPBOOL pfResult);

LPWSTR ntsupQueryEnvironmentVariableOffset(
    _In_ PUNICODE_STRING Value);

DWORD ntsupExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize);

NTSTATUS ntsupIsLocalSystem(
    _Out_ PBOOL pbResult);

NTSTATUS ntsupIsUserHasInteractiveSid(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbInteractiveSid);

BOOL ntsupGetProcessElevationType(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ TOKEN_ELEVATION_TYPE * lpType);

NTSTATUS ntsupIsProcessElevated(
    _In_ ULONG ProcessId,
    _Out_ PBOOL Elevated);

VOID ntsupPurgeSystemCache(
    VOID);

PWSTR ntsupGetSystemRoot(
    VOID);

NTSTATUS ntsupGetProcessDebugObject(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE DebugObjectHandle);

PBYTE ntsupQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

NTSTATUS ntsupEnableWow64Redirection(
    _In_ BOOLEAN bEnable);

BOOLEAN ntsupIsKdEnabled(
    _Out_opt_ PBOOLEAN DebuggerAllowed,
    _Out_opt_ PBOOLEAN DebuggerNotPresent);

BOOLEAN ntsupIsObjectExists(
    _In_ LPCWSTR RootDirectory,
    _In_ LPCWSTR ObjectName);

BOOLEAN ntsupUserIsFullAdmin(
    VOID);

NTSTATUS ntsupHashImageSections(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_writes_bytes_(HashBufferSize) PBYTE HashBuffer,
    _In_ SIZE_T HashBufferSize,
    _In_ NTSUP_IMAGE_TYPE ImageType);

#define ntsupQuerySecurityInformation(\
     ObjectHandle, SecurityInformationClass, Buffer, ReturnLength, AllocMem, FreeMem) \
ntsupQuerySystemObjectInformationVariableSize((PFN_NTQUERYROUTINE)NtQuerySecurityObject, \
     ObjectHandle, SecurityInformationClass, (PVOID*)Buffer, ReturnLength,\
    (PNTSUPMEMALLOC)AllocMem, (PNTSUPMEMFREE)FreeMem)

#define ntsupQueryTokenInformation(\
     TokenHandle, TokenInformationClass, Buffer, ReturnLength, AllocMem, FreeMem) \
ntsupQuerySystemObjectInformationVariableSize((PFN_NTQUERYROUTINE)NtQueryInformationToken, \
     TokenHandle, TokenInformationClass, (PVOID*)Buffer, ReturnLength,\
    (PNTSUPMEMALLOC)AllocMem, (PNTSUPMEMFREE)FreeMem)

#define ntsupQueryObjectInformation(\
     ObjectHandle, ObjectInformationClass, Buffer, ReturnLength, AllocMem, FreeMem) \
ntsupQuerySystemObjectInformationVariableSize((PFN_NTQUERYROUTINE)NtQueryObject, \
    ObjectHandle, ObjectInformationClass, (PVOID*)Buffer, ReturnLength, \
    (PNTSUPMEMALLOC)AllocMem, (PNTSUPMEMFREE)FreeMem)

#define ntsupQueryThreadInformation(\
    ThreadHandle, ThreadInformationClass, Buffer, ReturnLength, AllocMem, FreeMem) \
ntsupQuerySystemObjectInformationVariableSize((PFN_NTQUERYROUTINE)NtQueryInformationThread, \
    ThreadHandle, ThreadInformationClass, (PVOID*)Buffer, ReturnLength, \
    (PNTSUPMEMALLOC)AllocMem, (PNTSUPMEMFREE)FreeMem)

#define ntsupQueryProcessInformation(\
    ProcessHandle, ProcessInformationClass, Buffer, ReturnLength, AllocMem, FreeMem)\
ntsupQuerySystemObjectInformationVariableSize((PFN_NTQUERYROUTINE)NtQueryInformationProcess, \
    ProcessHandle, ProcessInformationClass, (PVOID*)Buffer, ReturnLength, \
    (PNTSUPMEMALLOC)AllocMem, (PNTSUPMEMFREE)FreeMem)


#ifdef ENABLE_C_EXTERN
#ifdef __cplusplus
}
#endif
#endif

#pragma warning(pop)

#endif NTSUP_RTL
