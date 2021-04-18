/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       SUP.H
*
*  VERSION:     1.10
*
*  DATE:        15 Apr 2021
*
*  Support routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//#define VERBOSE_FUNCTION_LOG

typedef NTSTATUS(NTAPI* PENUMOBJECTSCALLBACK)(POBJECT_DIRECTORY_INFORMATION Entry, PVOID CallbackParam);

#define USER_TO_KERNEL_HANDLE(Handle) { Handle += 0xffffffff80000000; }

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    ULONG BufferSize;
} OBJSCANPARAM, * POBJSCANPARAM;

#ifdef VERBOSE_FUNCTION_LOG
#define FUNCTION_ENTER_MSG(lpFunctionName) printf_s("[>] Entering %s\r\n", lpFunctionName)
#define FUNCTION_LEAVE_MSG(lpFunctionName) printf_s("[<] Leaving %s\r\n", lpFunctionName)
#else
#define FUNCTION_ENTER_MSG(lpFunctionName) 
#define FUNCTION_LEAVE_MSG(lpFunctionName)
#endif

typedef enum _KDU_EVENT_TYPE {
    kduEventNone = 0,
    kduEventError,
    kduEventInformation,
    kduEventMax
} KDU_EVENT_TYPE, * PKDU_EVENT_TYPE;

PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size);

BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory);

BOOL supCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength);

NTSTATUS supEnablePrivilege(
    _In_ DWORD Privilege,
    _In_ BOOL Enable);

NTSTATUS supLoadDriver(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance);

NTSTATUS supUnloadDriver(
    _In_ LPCWSTR DriverName,
    _In_ BOOLEAN fRemove);

NTSTATUS supOpenDriver(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE DeviceHandle);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass);

ULONG_PTR supGetNtOsBase(
    VOID);

PBYTE supQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize);

SIZE_T supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append,
    _Out_opt_ NTSTATUS* Result);

ULONG_PTR supGetProcAddress(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR FunctionName);

VOID supResolveKernelImport(
    _In_ ULONG_PTR Image,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase);

BOOLEAN supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName);

BOOL supQueryObjectFromHandle(
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR* Address);

BOOL supGetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Out_writes_opt_z_(ValueSize) LPTSTR OptionValue,
    _In_ ULONG ValueSize,
    _Out_opt_ PULONG ParamLength);

BOOLEAN supQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled);

DWORD supExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize);

BOOLEAN supQuerySecureBootState(
    _Out_ PBOOLEAN pbSecureBoot);

ULONG_PTR supQueryMaximumUserModeAddress();

BOOLEAN supVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength,
    _Out_opt_ PULONG HeaderChecksum,
    _Out_opt_ PULONG CalculatedChecksum);

ULONG_PTR supGetPML4FromLowStub1M(
    _In_ ULONG_PTR pbLowStub1M);

NTSTATUS supCreateSystemAdminAccessSD(
    _Out_ PSECURITY_DESCRIPTOR * SecurityDescriptor,
    _Out_ PACL * DefaultAcl);

ULONG supGetTimeAsSecondsSince1970();

ULONG_PTR supGetModuleBaseByName(
    _In_ LPCSTR ModuleName);

BOOL supManageDummyDll(
    _In_ LPCWSTR lpDllName,
    _In_ BOOLEAN fRemove);

ULONG supSelectNonPagedPoolTag(
    VOID);

NTSTATUS supLoadFileForMapping(
    _In_ LPCWSTR PayloadFileName,
    _Out_ PVOID * LoadBase);

VOID supPrintfEvent(
    _In_ KDU_EVENT_TYPE Event,
    _In_ LPCSTR Format,
    ...);