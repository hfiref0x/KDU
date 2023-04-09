/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       SUP.H
*
*  VERSION:     1.31
*
*  DATE:        08 Apr 2023
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

#define USER_TO_KERNEL_HANDLE(Handle) { Handle += 0xffffffff80000000; }

typedef struct _SUP_SETUP_DRVPKG {
    HDEVINFO DeviceInfo;
    SP_DEVINFO_DATA DeviceInfoData;
    LPCWSTR CatalogFile;
    LPCWSTR InfFile;
    ULONG CatalogFileResourceId;
    ULONG InfFileResourceId;
    BYTE* Hwid;
    ULONG HwidLength;
    ULONG InstallFlags;
    WCHAR DeviceName[MAX_PATH];
} SUP_SETUP_DRVPKG, * PSUP_SETUP_DRVPKG;

typedef BOOL(CALLBACK* pfnOpenProcessCallback)(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);

typedef BOOL(CALLBACK* pfnDuplicateHandleCallback)(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE SourceProcessId, //some drivers need pid not handle
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _Out_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options);

typedef BOOL(CALLBACK* pfnSetupDeviceEnumCallback)(
    _In_ HDEVINFO DeviceInfo,
    _In_ PSP_DEVINFO_DATA DeviceInfoData,
    _In_ PVOID Param
    );

typedef NTSTATUS(CALLBACK* pfnLoadDriverCallback)(
    _In_ PUNICODE_STRING RegistryPath,
    _In_opt_ PVOID Param
    );

#define supEnablePrivilege ntsupEnablePrivilege
#define supQueryHVCIState ntsupQueryHVCIState
#define supExpandEnvironmentStrings ntsupExpandEnvironmentStrings
#define supQueryResourceData ntsupQueryResourceData
#define supWriteBufferToFile ntsupWriteBufferToFile
#define supIsObjectExists ntsupIsObjectExists
#define supConvertToAnsi ntsupConvertToAnsi
#define supQueryObjectInformation ntsupQueryObjectInformation
#define supEnumSystemObjects ntsupEnumSystemObjects
#define supFindModuleEntryByAddress ntsupFindModuleEntryByAddress

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

typedef BOOL(WINAPI* pfnPhysMemEnumCallback)(
    _In_ ULONG_PTR Address,
    _In_ PVOID UserContext);

#define GET_CPU_VENDOR_STRING(VendorString) \
    INT cpuInfo[4]; \
    RtlFillMemory(cpuInfo, sizeof(cpuInfo), 0); \
    __cpuid((INT*)cpuInfo, 0); \
    *(DWORD*)(VendorString) = cpuInfo[1]; \
    *(DWORD*)(VendorString + 4) = cpuInfo[3]; \
    *(DWORD*)(VendorString + 8) = cpuInfo[2]; \

BOOL supIsSupportedCpuVendor(
    _In_ LPCSTR Vendor,
    _In_ ULONG Length);

PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size);

BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory);

PVOID supMapPhysicalMemory(
    _In_ HANDLE SectionHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL MapForWrite);

VOID supUnmapPhysicalMemory(
    _In_ PVOID BaseAddress);

BOOL WINAPI supReadWritePhysicalMemory(
    _In_ HANDLE SectionHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite);

BOOL WINAPI supOpenPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ pfnOpenProcessCallback OpenProcessCallback,
    _In_ pfnDuplicateHandleCallback DuplicateHandleCallback,
    _Out_ PHANDLE PhysicalMemoryHandle);

NTSTATUS supCallDriverEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength,
    _Out_opt_ PIO_STATUS_BLOCK IoStatus);

BOOL supCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength);

NTSTATUS supLoadDriverEx(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance,
    _In_opt_ pfnLoadDriverCallback Callback,
    _In_opt_ PVOID CallbackParam);

NTSTATUS supLoadDriver(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance);

NTSTATUS supUnloadDriver(
    _In_ LPCWSTR DriverName,
    _In_ BOOLEAN fRemove);

NTSTATUS supOpenDriverEx(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE DeviceHandle);

NTSTATUS supOpenDriver(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE DeviceHandle);

PVOID supGetLoadedModulesList(
    _In_ BOOL ExtendedOutput,
    _Out_opt_ PULONG ReturnLength);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass);

ULONG_PTR supGetNtOsBase(
    VOID);

PBYTE supReadFileToBuffer(
    _In_ LPWSTR lpFileName,
    _Inout_opt_ LPDWORD lpBufferSize);

ULONG_PTR supGetProcAddress(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR FunctionName);

VOID supResolveKernelImport(
    _In_ ULONG_PTR Image,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase);

BOOL supQueryObjectFromHandle(
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR* Address);

BOOL supGetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Inout_opt_ LPTSTR OptionValue,
    _In_ ULONG ValueSize,
    _Out_opt_ PULONG ParamLength);

BOOLEAN supQuerySecureBootState(
    _Out_ PBOOLEAN pbSecureBoot);

NTSTATUS supGetFirmwareType(
    _Out_ PFIRMWARE_TYPE FirmwareType);

ULONG_PTR supQueryMaximumUserModeAddress();

DWORD supCalculateCheckSumForMappedFile(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength);

BOOLEAN supVerifyMappedImageMatchesChecksum(
    _In_ PVOID BaseAddress,
    _In_ ULONG FileLength,
    _Out_opt_ PULONG HeaderChecksum,
    _Out_opt_ PULONG CalculatedChecksum);

BOOL supReplaceDllEntryPoint(
    _In_ PVOID DllImage,
    _In_ ULONG SizeOfDllImage,
    _In_ LPCSTR lpEntryPointName,
    _In_ BOOL fConvertToExe);

ULONG_PTR supGetPML4FromLowStub1M(
    _In_ ULONG_PTR pbLowStub1M);

NTSTATUS supCreateSystemAdminAccessSD(
    _Out_ PSECURITY_DESCRIPTOR * SecurityDescriptor,
    _Out_ PACL * DefaultAcl);

ULONG supGetTimeAsSecondsSince1970();

ULONG_PTR supGetModuleBaseByName(
    _In_ LPCWSTR ModuleName,
    _Out_opt_ PULONG ImageSize);

BOOL supManageDummyDll(
    _In_ LPCWSTR lpDllName,
    _In_ BOOLEAN fRemove);

ULONG supSelectNonPagedPoolTag(
    VOID);

NTSTATUS supRegWriteValueDWORD(
    _In_ HANDLE RegistryHandle,
    _In_ LPCWSTR ValueName,
    _In_ DWORD ValueData);

NTSTATUS supRegWriteValueString(
    _In_ HANDLE RegistryHandle,
    _In_ LPCWSTR ValueName,
    _In_ LPCWSTR ValueData);

NTSTATUS supLoadFileForMapping(
    _In_ LPCWSTR PayloadFileName,
    _Out_ PVOID * LoadBase);

VOID supPrintfEvent(
    _In_ KDU_EVENT_TYPE Event,
    _Printf_format_string_ LPCSTR Format,
    ...);

NTSTATUS supQueryImageSize(
    _In_ PVOID ImageBase,
    _Out_ PSIZE_T ImageSize);

VOID supGenerateSharedObjectName(
    _In_ WORD ObjectId,
    _Inout_ LPWSTR lpBuffer);

BOOL supSetupManageDriverPackage(
    _In_ PVOID Context,
    _In_ BOOLEAN DoInstall,
    _In_ PSUP_SETUP_DRVPKG DriverPackage);

BOOL supSetupRemoveDriver(
    _In_ HDEVINFO DeviceInfo,
    _In_ SP_DEVINFO_DATA * DeviceInfoData);

BOOL supQueryDeviceProperty(
    _In_ HDEVINFO hDevInfo,
    _In_ SP_DEVINFO_DATA* pDevInfoData,
    _In_ ULONG Property,
    _Out_ LPWSTR* PropertyBuffer,
    _Out_opt_ ULONG* PropertyBufferSize);

BOOL supSetupEnumDevices(
    _In_ pfnSetupDeviceEnumCallback Callback,
    _In_ PVOID CallbackParam);

BOOL supExtractFileFromDB(
    _In_ HMODULE ImageBase,
    _In_ LPCWSTR FileName,
    _In_ ULONG FileId);

VOID supExtractFileToTemp(
    _In_opt_ HMODULE ImageBase,
    _In_opt_ ULONG FileResourceId,
    _In_ LPCWSTR lpTempPath,
    _In_ LPCWSTR lpFileName,
    _In_ BOOL fDelete);

BOOL supDeleteFileWithWait(
    _In_ ULONG WaitMilliseconds,
    _In_ ULONG NumberOfAttempts,
    _In_ LPCWSTR lpFileName);

PVOID supMapFileAsImage(
    _In_ LPWSTR lpImagePath);

PVOID supGetEntryPointForMappedFile(
    _In_ PVOID ImageBase);

NTSTATUS supInjectPayload(
    _In_ PVOID pvTargetImage,
    _In_ PVOID pbShellCode,
    _In_ ULONG cbShellCode,
    _In_ LPWSTR lpTargetModule,
    _Out_ PHANDLE phZombieProcess);

NTSTATUS supFilterDeviceIoControl(
    _In_ HANDLE Handle,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_(InBufferSize) PVOID InBuffer,
    _In_ ULONG InBufferSize,
    _Out_writes_bytes_to_opt_(OutBufferSize, *BytesReturned) PVOID OutBuffer,
    _In_ ULONG OutBufferSize,
    _Out_opt_ PULONG BytesReturned);

ULONG_PTR supGetHalQuerySystemInformation(
    _In_ ULONG_PTR NtOsLoadedBase,
    _In_ ULONG_PTR NtOsMappedBase);

PCM_RESOURCE_LIST supQueryPhysicalMemoryLayout(
    VOID);

BOOL supEnumeratePhysicalMemory(
    _In_ pfnPhysMemEnumCallback Callback,
    _In_ PVOID UserContext);

BOOL supDetectMsftBlockList(
    _In_ PBOOL Enabled,
    _In_ BOOL Disable);

ULONG_PTR supResolveMiPteBaseAddress(
    _In_opt_ PVOID NtOsBase);
