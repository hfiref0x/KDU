/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2025
*
*  TITLE:       DIAG.CPP
*
*  VERSION:     1.44
*
*  DATE:        18 Aug 2025
*
*  Hamakaze system diagnostics component.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

BOOLEAN g_ConsoleOutput = TRUE;

typedef struct _OBJENUMPARAM {
    PWSTR ObjectDirectory;
    PUNICODE_STRING ObjectType;
} OBJENUMPARAM, * POBJENUMPARAM;

NTSTATUS NTAPI EnumObjectsCallback(
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ PVOID CallbackParam
)
{
    POBJENUMPARAM Param = (POBJENUMPARAM)CallbackParam;

    if (RtlEqualUnicodeString(&Entry->TypeName, Param->ObjectType, TRUE)) {
        printf_s("\t%ws -> %wZ\r\n", Param->ObjectDirectory, &Entry->Name);
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS EmptyWorkingSet()
{
    NTSTATUS ntStatus;
    QUOTA_LIMITS quotaLimits;

    ntStatus = NtQueryInformationProcess(NtCurrentProcess(),
        ProcessQuotaLimits,
        &quotaLimits,
        sizeof(quotaLimits),
        NULL);

    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }

    quotaLimits.MinimumWorkingSetSize = (SIZE_T)-1;
    quotaLimits.MaximumWorkingSetSize = (SIZE_T)-1;

    return NtSetInformationProcess(NtCurrentProcess(),
        ProcessQuotaLimits,
        &quotaLimits,
        sizeof(quotaLimits));

}

VOID KDUPrintBooleanValueWithColor(
    _In_ CONST char* Name,
    _In_ BOOLEAN Value
)
{
#define PRINTGRN  "\x1B[32m"
#define PRINTWHT "\x1B[37m"

    if (g_ConsoleOutput) {

        printf_s("\t\t%s %s\r\n%s", Name, Value ? PRINTGRN"TRUE" : PRINTWHT"FALSE", PRINTWHT);

    }
    else {

        printf_s("\t\t%s %s\r\n", Name, Value ? "TRUE" : "FALSE");

    }
}

VOID KDUQuerySpecMitigationState()
{
    union {
        SYSTEM_SPECULATION_CONTROL_INFORMATION v1;
        SYSTEM_SPECULATION_CONTROL_INFORMATION_V2 v2;
    } SpecControlInfo;

    SYSTEM_KERNEL_VA_SHADOW_INFORMATION KvaShadowInfo;

    DWORD bytesIO = 0;

    RtlSecureZeroMemory(&KvaShadowInfo, sizeof(KvaShadowInfo));

    NTSTATUS ntStatus = NtQuerySystemInformation(SystemKernelVaShadowInformation, &KvaShadowInfo, sizeof(KvaShadowInfo), &bytesIO);

    if (NT_SUCCESS(ntStatus)) {

        printf_s("\t>> SystemKernelVaShadowInformation\r\n");
        KDUPrintBooleanValueWithColor("KvaShadowEnabled", KvaShadowInfo.KvaShadowFlags.KvaShadowEnabled);
        KDUPrintBooleanValueWithColor("KvaShadowUserGlobal", KvaShadowInfo.KvaShadowFlags.KvaShadowUserGlobal);
        KDUPrintBooleanValueWithColor("KvaShadowPcid", KvaShadowInfo.KvaShadowFlags.KvaShadowPcid);
        KDUPrintBooleanValueWithColor("KvaShadowInvpcid", KvaShadowInfo.KvaShadowFlags.KvaShadowInvpcid);
        KDUPrintBooleanValueWithColor("KvaShadowRequired", KvaShadowInfo.KvaShadowFlags.KvaShadowRequired);
        KDUPrintBooleanValueWithColor("KvaShadowRequiredAvailable", KvaShadowInfo.KvaShadowFlags.KvaShadowRequiredAvailable);
        printf_s("\tInvalidPteBit %lu\r\n", KvaShadowInfo.KvaShadowFlags.InvalidPteBit);
        KDUPrintBooleanValueWithColor("L1DataCacheFlushSupported", KvaShadowInfo.KvaShadowFlags.L1DataCacheFlushSupported);
        KDUPrintBooleanValueWithColor("L1TerminalFaultMitigationPresent", KvaShadowInfo.KvaShadowFlags.L1TerminalFaultMitigationPresent);

    }
    else {
        supShowHardError("Cannot query Kernel VA Shadow information", ntStatus);
    }

    RtlSecureZeroMemory(&SpecControlInfo, sizeof(SpecControlInfo));

    bytesIO = sizeof(SpecControlInfo);
    ntStatus = NtQuerySystemInformation(SystemSpeculationControlInformation, &SpecControlInfo, bytesIO, &bytesIO);

    if (ntStatus == STATUS_NOT_IMPLEMENTED ||
        ntStatus == STATUS_INVALID_INFO_CLASS)
    {
        supShowHardError("Speculation control information class not present", ntStatus);
    }
    else if (ntStatus != STATUS_SUCCESS) {
        supShowHardError("Cannot query speculation control information", ntStatus);
    }
    else {

        if (bytesIO != sizeof(SYSTEM_SPECULATION_CONTROL_INFORMATION_V2) &&
            bytesIO != sizeof(SYSTEM_SPECULATION_CONTROL_INFORMATION)) {
            supPrintfEvent(kduEventError,
                "Unknown speculation control information size %lu\r\n", bytesIO);
        }

        printf_s("\t>> SystemSpeculationControlInformation\r\n");

        KDUPrintBooleanValueWithColor("BpbEnabled", SpecControlInfo.v1.SpeculationControlFlags.BpbEnabled);
        KDUPrintBooleanValueWithColor("BpbDisabledSystemPolicy", SpecControlInfo.v1.SpeculationControlFlags.BpbDisabledSystemPolicy);
        KDUPrintBooleanValueWithColor("BpbDisabledNoHardwareSupport", SpecControlInfo.v1.SpeculationControlFlags.BpbDisabledNoHardwareSupport);
        KDUPrintBooleanValueWithColor("SpecCtrlEnumerated", SpecControlInfo.v1.SpeculationControlFlags.SpecCtrlEnumerated);
        KDUPrintBooleanValueWithColor("SpecCmdEnumerated", SpecControlInfo.v1.SpeculationControlFlags.SpecCmdEnumerated);
        KDUPrintBooleanValueWithColor("IbrsPresent", SpecControlInfo.v1.SpeculationControlFlags.IbrsPresent);
        KDUPrintBooleanValueWithColor("StibpPresent", SpecControlInfo.v1.SpeculationControlFlags.StibpPresent);
        KDUPrintBooleanValueWithColor("SmepPresent", SpecControlInfo.v1.SpeculationControlFlags.SmepPresent);
        KDUPrintBooleanValueWithColor("SpeculativeStoreBypassDisableAvailable", SpecControlInfo.v1.SpeculationControlFlags.SpeculativeStoreBypassDisableAvailable);
        KDUPrintBooleanValueWithColor("SpeculativeStoreBypassDisableSupported", SpecControlInfo.v1.SpeculationControlFlags.SpeculativeStoreBypassDisableSupported);
        KDUPrintBooleanValueWithColor("SpeculativeStoreBypassDisabledSystemWide", SpecControlInfo.v1.SpeculationControlFlags.SpeculativeStoreBypassDisabledSystemWide);
        KDUPrintBooleanValueWithColor("SpeculativeStoreBypassDisabledKernel", SpecControlInfo.v1.SpeculationControlFlags.SpeculativeStoreBypassDisabledKernel);
        KDUPrintBooleanValueWithColor("SpeculativeStoreBypassDisableRequired", SpecControlInfo.v1.SpeculationControlFlags.SpeculativeStoreBypassDisableRequired);
        KDUPrintBooleanValueWithColor("BpbDisabledKernelToUser", SpecControlInfo.v1.SpeculationControlFlags.BpbDisabledKernelToUser);
        KDUPrintBooleanValueWithColor("SpecCtrlRetpolineEnabled", SpecControlInfo.v1.SpeculationControlFlags.SpecCtrlRetpolineEnabled);
        KDUPrintBooleanValueWithColor("SpecCtrlImportOptimizationEnabled", SpecControlInfo.v1.SpeculationControlFlags.SpecCtrlImportOptimizationEnabled);
        KDUPrintBooleanValueWithColor("EnhancedIbrs", SpecControlInfo.v1.SpeculationControlFlags.EnhancedIbrs);
        KDUPrintBooleanValueWithColor("HvL1tfStatusAvailable", SpecControlInfo.v1.SpeculationControlFlags.HvL1tfStatusAvailable);
        KDUPrintBooleanValueWithColor("HvL1tfProcessorNotAffected", SpecControlInfo.v1.SpeculationControlFlags.HvL1tfProcessorNotAffected);
        KDUPrintBooleanValueWithColor("HvL1tfMigitationEnabled", SpecControlInfo.v1.SpeculationControlFlags.HvL1tfMigitationEnabled);
        KDUPrintBooleanValueWithColor("HvL1tfMigitationNotEnabled_Hardware", SpecControlInfo.v1.SpeculationControlFlags.HvL1tfMigitationNotEnabled_Hardware);
        KDUPrintBooleanValueWithColor("HvL1tfMigitationNotEnabled_LoadOption", SpecControlInfo.v1.SpeculationControlFlags.HvL1tfMigitationNotEnabled_LoadOption);
        KDUPrintBooleanValueWithColor("HvL1tfMigitationNotEnabled_CoreScheduler", SpecControlInfo.v1.SpeculationControlFlags.HvL1tfMigitationNotEnabled_CoreScheduler);
        KDUPrintBooleanValueWithColor("EnhancedIbrsReported", SpecControlInfo.v1.SpeculationControlFlags.EnhancedIbrsReported);
        KDUPrintBooleanValueWithColor("MdsHardwareProtected", SpecControlInfo.v1.SpeculationControlFlags.MdsHardwareProtected);
        KDUPrintBooleanValueWithColor("MbClearEnabled", SpecControlInfo.v1.SpeculationControlFlags.MbClearEnabled);
        KDUPrintBooleanValueWithColor("MbClearReported", SpecControlInfo.v1.SpeculationControlFlags.MbClearReported);
        printf_s("\t\tTsxCtrlStatus %lu\r\n", SpecControlInfo.v1.SpeculationControlFlags.TsxCtrlStatus);
        KDUPrintBooleanValueWithColor("TsxCtrlReported", SpecControlInfo.v1.SpeculationControlFlags.TsxCtrlReported);
        KDUPrintBooleanValueWithColor("TaaHardwareImmune", SpecControlInfo.v1.SpeculationControlFlags.TaaHardwareImmune);

        if (bytesIO == sizeof(SYSTEM_SPECULATION_CONTROL_INFORMATION_V2)) {

            printf_s("\t>> SystemSpeculationControlInformation v2\r\n");

            KDUPrintBooleanValueWithColor("SbdrSsdpHardwareProtected", SpecControlInfo.v2.SpeculationControlFlags2.SbdrSsdpHardwareProtected);
            KDUPrintBooleanValueWithColor("FbsdpHardwareProtected", SpecControlInfo.v2.SpeculationControlFlags2.FbsdpHardwareProtected);
            KDUPrintBooleanValueWithColor("PsdpHardwareProtected", SpecControlInfo.v2.SpeculationControlFlags2.PsdpHardwareProtected);
            KDUPrintBooleanValueWithColor("FbClearEnabled", SpecControlInfo.v2.SpeculationControlFlags2.FbClearEnabled);
            KDUPrintBooleanValueWithColor("FbClearReported", SpecControlInfo.v2.SpeculationControlFlags2.FbClearReported);
        }
    }
}

#define WATCH_COUNT 256

VOID KDUQueryProcessWorkingSet(
    _In_ ULONG_PTR SystemRangeStart,
    _In_ PRTL_PROCESS_MODULES pvModules
)
{
    NTSTATUS ntStatus;

    ntStatus = NtSetInformationProcess(
        NtCurrentProcess(),
        ProcessWorkingSetWatch,
        NULL,
        0);

    if (!NT_SUCCESS(ntStatus)) {
        supShowHardError("Cannot enable ws watch", ntStatus);
        return;
    }

    PROCESS_WS_WATCH_INFORMATION_EX watchInfo[WATCH_COUNT];

    RtlSecureZeroMemory(&watchInfo, sizeof(watchInfo));

    ntStatus = EmptyWorkingSet();
    if (!NT_SUCCESS(ntStatus)) {
        supShowHardError("Error at EmptyWorkingSet", ntStatus);
        return;
    }

    ntStatus = NtQueryInformationProcess(
        NtCurrentProcess(),
        ProcessWorkingSetWatchEx,
        (PVOID*)&watchInfo,
        sizeof(watchInfo),
        NULL);

    if (!NT_SUCCESS(ntStatus)) {
        supShowHardError("Error at working set changes query", ntStatus);
        return;
    }

    PVOID cookie;
    ntStatus = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, NULL, &cookie);

    if (NT_SUCCESS(ntStatus)) {

        PLDR_DATA_TABLE_ENTRY entry;
        UNICODE_STRING moduleUnknown;
        RtlInitUnicodeString(&moduleUnknown, L"Unknown");

        for (ULONG i = 0; i < WATCH_COUNT; i++) {

            PVOID faultingPc = watchInfo[i].BasicInfo.FaultingPc;
            PVOID faultingVa = watchInfo[i].BasicInfo.FaultingVa;

            if (faultingPc == NULL || faultingVa == NULL)
                continue;

            PWSTR pcName = moduleUnknown.Buffer, vaName = moduleUnknown.Buffer;
            ULONG moduleIndex;
            UNICODE_STRING pcModuleName, vaModuleName;

            RtlInitEmptyUnicodeString(&pcModuleName, NULL, 0);
            RtlInitEmptyUnicodeString(&vaModuleName, NULL, 0);

            if ((ULONG_PTR)faultingPc >= SystemRangeStart) {

                moduleIndex = 0;

                if (supFindModuleEntryByAddress(pvModules,
                    faultingPc,
                    &moduleIndex))
                {
                    if (NT_SUCCESS(ntsupConvertToUnicode(
                        (LPCSTR)pvModules->Modules[moduleIndex].FullPathName,
                        &pcModuleName)))
                    {
                        pcName = pcModuleName.Buffer;
                    }
                }

            }
            else {

                ntStatus = LdrFindEntryForAddress(faultingPc, (PLDR_DATA_TABLE_ENTRY*)&entry);
                if (NT_SUCCESS(ntStatus))
                    pcName = entry->BaseDllName.Buffer;

            }

            if ((ULONG_PTR)faultingVa >= SystemRangeStart) {

                moduleIndex = 0;

                if (supFindModuleEntryByAddress(pvModules,
                    faultingVa,
                    &moduleIndex))
                {
                    if (NT_SUCCESS(ntsupConvertToUnicode(
                        (LPCSTR)pvModules->Modules[moduleIndex].FullPathName,
                        &vaModuleName)))
                    {
                        pcName = vaModuleName.Buffer;
                    }
                }

            }
            else {

                ntStatus = LdrFindEntryForAddress(faultingVa, (PLDR_DATA_TABLE_ENTRY*)&entry);
                if (NT_SUCCESS(ntStatus))
                    vaName = entry->BaseDllName.Buffer;

            }

            printf_s("\t>> ThreadId [%llu] Pc %p (%ws) : Va %p (%ws)\r\n",
                watchInfo[i].FaultingThreadId,
                faultingPc,
                pcName,
                faultingVa,
                vaName);

            if (pcModuleName.Buffer) RtlFreeUnicodeString(&pcModuleName);
            if (vaModuleName.Buffer) RtlFreeUnicodeString(&vaModuleName);

        }

        LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie);
    }
    else {
        supShowHardError("Failed acquire loader lock", ntStatus);
    }
}

VOID TraceHandle(
    _In_ ULONG_PTR SystemRangeStart,
    _In_ HANDLE Handle,
    _In_ PRTL_PROCESS_MODULES pvModules
)
{
    NTSTATUS ntStatus;
    PROCESS_HANDLE_TRACING_QUERY trace;

    RtlSecureZeroMemory(&trace, sizeof(trace));
    trace.Handle = Handle;

    ntStatus = NtQueryInformationProcess(NtCurrentProcess(), ProcessHandleTracing, &trace, sizeof(trace), NULL);
    if (NT_SUCCESS(ntStatus)) {

        for (ULONG i = 0; i < trace.TotalTraces; i++) {
            for (ULONG j = 0; j < PROCESS_HANDLE_TRACING_MAX_STACKS; j++) {

                ULONG moduleIndex = 0;
                PVOID stackAddress = trace.HandleTrace[i].Stacks[j];

                if (stackAddress == NULL)
                    continue;

                if (supFindModuleEntryByAddress(pvModules,
                    stackAddress,
                    &moduleIndex))
                {

                    printf_s("\t>> 0x%p, %s, base 0x%p\r\n",
                        stackAddress,
                        pvModules->Modules[moduleIndex].FullPathName,
                        pvModules->Modules[moduleIndex].ImageBase);

                }
                else {
                    if ((ULONG_PTR)stackAddress >= SystemRangeStart) {
                        printf_s("\t>> 0x%p, !UNKNOWN! module\r\n",
                            stackAddress);
                    }
                    else {

                        PVOID cookie = NULL;
                        ntStatus = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, NULL, &cookie);

                        if (NT_SUCCESS(ntStatus)) {

                            PLDR_DATA_TABLE_ENTRY entry;

                            ntStatus = LdrFindEntryForAddress(stackAddress, (PLDR_DATA_TABLE_ENTRY*)&entry);
                            if (NT_SUCCESS(ntStatus)) {
                                printf_s("\t>> 0x%p, %wZ, base 0x%p\r\n",
                                    stackAddress,
                                    entry->BaseDllName,
                                    entry->DllBase);
                            }
                            else {
                                printf_s("\t>> 0x%p, !UNKNOWN! module\r\n",
                                    stackAddress);
                            }

                            LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, cookie);
                        }
                        else {
                            supShowHardError("Failed to acquire loader lock", ntStatus);
                        }

                    }
                }

            }
        }

    }
    else {
        supShowHardError("Cannot query trace", ntStatus);
    }
}

VOID TracePsHandle(
    _In_ PCLIENT_ID ClientId,
    _In_ ULONG_PTR SystemRangeStart,
    _In_ PRTL_PROCESS_MODULES pvModules,
    _In_ BOOL TraceThread
)
{
    NTSTATUS ntStatus;
    HANDLE objectHandle = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    if (ClientId->UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess) {
        printf_s("> Process (self) handle trace\r\n");
    }
    else {
        printf_s("> Process (%lu) handle trace\r\n", HandleToULong(ClientId->UniqueProcess));
    }

    clientId = *ClientId;

    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    ntStatus = NtOpenProcess(&objectHandle, PROCESS_ALL_ACCESS, &obja, &clientId);
    if (NT_SUCCESS(ntStatus)) {
        TraceHandle(
            SystemRangeStart,
            objectHandle,
            pvModules);

        NtClose(objectHandle);
    }
    else {
        supShowHardError("Cannot open process", ntStatus);
    }

    if (!TraceThread)
        return;

    printf_s("> Thread handle trace\r\n");
    clientId = NtCurrentTeb()->ClientId;

    ntStatus = NtOpenThread(&objectHandle, THREAD_ALL_ACCESS, &obja, &clientId);
    if (NT_SUCCESS(ntStatus)) {
        TraceHandle(
            SystemRangeStart,
            objectHandle,
            pvModules);

        NtClose(objectHandle);
    }
    else {
        supShowHardError("Cannot open thread", ntStatus);
    }
}

VOID TraceSectionHandle(
    _In_ ULONG_PTR SystemRangeStart,
    _In_ PRTL_PROCESS_MODULES pvModules
)
{
    NTSTATUS ntStatus;
    HANDLE sectionHandle = NULL, fileHandle = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usName;
    IO_STATUS_BLOCK iost;

    RtlInitUnicodeString(&usName, L"\\systemroot\\system32\\drivers\\acpi.sys");
    InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ntStatus = NtOpenFile(&fileHandle,
        SYNCHRONIZE | FILE_EXECUTE,
        &obja,
        &iost,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(ntStatus)) {
        supShowHardError("Cannot open test file", ntStatus);
        return;
    }

    RtlInitUnicodeString(&usName, L"\\RPC Control\\zzz");

    ntStatus = NtCreateSection(&sectionHandle,
        SECTION_ALL_ACCESS,
        &obja,
        NULL,
        PAGE_EXECUTE,
        SEC_IMAGE,
        fileHandle);

    if (NT_SUCCESS(ntStatus)) {

        printf_s("> Section handle trace\r\n");
        TraceHandle(SystemRangeStart, sectionHandle, pvModules);

        NtClose(sectionHandle);
    }
    else {
        supShowHardError("Cannot create test section", ntStatus);
    }

    NtClose(fileHandle);
}

#define FLTMGR_LINK_HANDLE_FUNCID 3
#define FLTMGR_FIND_FIRST_FUNCID  9
#define FLTMGR_FIND_NEXT_FUNCID   0xA

#define IOCTL_FLTMGR_LINK_HANDLE    \
    CTL_CODE(FILE_DEVICE_DISK_FILE_SYSTEM, FLTMGR_LINK_HANDLE_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_FLTMGR_FIND_FIRST     \
    CTL_CODE(FILE_DEVICE_DISK_FILE_SYSTEM, FLTMGR_FIND_FIRST_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_FLTMGR_FIND_NEXT      \
    CTL_CODE(FILE_DEVICE_DISK_FILE_SYSTEM, FLTMGR_FIND_NEXT_FUNCID, METHOD_BUFFERED, FILE_READ_ACCESS)

NTSTATUS KDUpFilterFindFirst(
    _In_ HANDLE FltMgrHandle,
    _In_ FILTER_INFORMATION_CLASS InformationClass,
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize
)
{
    FILTER_INFORMATION_CLASS infoClass = InformationClass;
    NTSTATUS ntStatus;
    DWORD linkInfo[2];

    linkInfo[0] = 3; //type of callback, 3 is for filters.
    linkInfo[1] = 0;

    ntStatus = supFilterDeviceIoControl(FltMgrHandle,
        IOCTL_FLTMGR_LINK_HANDLE,
        &linkInfo,
        sizeof(linkInfo),
        NULL,
        0,
        NULL);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = supFilterDeviceIoControl(FltMgrHandle,
            IOCTL_FLTMGR_FIND_FIRST,
            &infoClass,
            sizeof(infoClass),
            Buffer,
            BufferSize,
            NULL);

    }

    return ntStatus;
}

NTSTATUS KDUpFilterFindNext(
    _In_ HANDLE FltMgrHandle,
    _In_ FILTER_INFORMATION_CLASS InformationClass,
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize
)
{
    FILTER_INFORMATION_CLASS infoClass = InformationClass;

    return supFilterDeviceIoControl(FltMgrHandle,
        IOCTL_FLTMGR_FIND_NEXT,
        &infoClass,
        sizeof(infoClass),
        Buffer,
        BufferSize,
        NULL);
}

VOID KDUListFilters()
{
    DWORD bufferSize;
    PFILTER_FULL_INFORMATION buffer = NULL;
    HANDLE fltMgrHandle = NULL;
    NTSTATUS ntStatus;
    UNICODE_STRING usDeviceName;
    IO_STATUS_BLOCK iost;
    OBJECT_ATTRIBUTES obja;

    bufferSize = sizeof(FILTER_FULL_INFORMATION) + MAX_PATH * 2;
    buffer = (PFILTER_FULL_INFORMATION)supHeapAlloc((SIZE_T)bufferSize);
    if (buffer) {

        RtlInitUnicodeString(&usDeviceName, L"\\??\\FltMgr");
        InitializeObjectAttributes(&obja, &usDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        ntStatus = NtCreateFile(&fltMgrHandle,
            GENERIC_READ,
            &obja,
            &iost,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            0,
            NULL,
            0);

        if (!NT_SUCCESS(ntStatus)) {
            supPrintfEvent(kduEventError, "Cannot open %wZ, NTSTATUS (0x%lX)\r\n", usDeviceName, ntStatus);
            return;
        }

        if (NT_SUCCESS(KDUpFilterFindFirst(fltMgrHandle, FilterFullInformation, buffer, bufferSize))) {

            do {

                printf_s("\t>> %ws\r\n", buffer->FilterNameBuffer);
                RtlSecureZeroMemory(buffer, bufferSize);

            } while (KDUpFilterFindNext(fltMgrHandle,
                FilterFullInformation,
                buffer, bufferSize) != STATUS_NO_MORE_ENTRIES);

        }

        NtClose(fltMgrHandle);
        supHeapFree(buffer);
    }
}

VOID KDUBacktraceByHandle(
    _In_ ULONG_PTR SystemRangeStart,
    _In_ PRTL_PROCESS_MODULES pvModules
)
{
    NTSTATUS ntStatus;
    CLIENT_ID cid;
    PVOID procBuffer;
    PROCESS_HANDLE_TRACING_ENABLE traceEnable;
    ULONG nextEntryDelta = 0;
    UNICODE_STRING usLsass;

    union {
        PSYSTEM_PROCESS_INFORMATION Process;
        PBYTE ListRef;
    } List;

    RtlSecureZeroMemory(&traceEnable, sizeof(traceEnable));

    ntStatus = NtSetInformationProcess(NtCurrentProcess(),
        ProcessHandleTracing,
        &traceEnable,
        sizeof(traceEnable));

    if (!NT_SUCCESS(ntStatus)) {
        supShowHardError("Cannot enable backtrace", ntStatus);
        return;
    }

    //
    // Trace self process/thread
    //
    cid.UniqueProcess = NtCurrentTeb()->ClientId.UniqueProcess;
    cid.UniqueThread = NULL;

    TracePsHandle(&cid, SystemRangeStart, pvModules, TRUE);

    //
    // Trace lsass process
    //
    procBuffer = supGetSystemInfo(SystemProcessInformation);

    List.ListRef = (PBYTE)procBuffer;
    if (List.ListRef) {

        RtlInitUnicodeString(&usLsass, L"lsass.exe");

        cid.UniqueProcess = cid.UniqueThread = NULL;

        do {

            List.ListRef += nextEntryDelta;
            if (RtlEqualUnicodeString(&usLsass, &List.Process->ImageName, TRUE)) {
                cid.UniqueProcess = List.Process->UniqueProcessId;
                TracePsHandle(&cid, SystemRangeStart, pvModules, FALSE);
                break;
            }

            nextEntryDelta = List.Process->NextEntryDelta;

        } while (nextEntryDelta);

        supHeapFree(procBuffer);

    }
    else {
        supPrintfEvent(kduEventError, "Cannot allocate process list, process trace unavailable\r\n");
    }

    TraceSectionHandle(SystemRangeStart, pvModules);
}

VOID KDUListObjects(
    VOID
)
{
    OBJENUMPARAM enumParam;
    UNICODE_STRING usObjectType;

    enumParam.ObjectDirectory = (PWSTR)L"\\";
    RtlInitUnicodeString(&usObjectType, L"Device");
    enumParam.ObjectType = &usObjectType;

    supEnumSystemObjects(enumParam.ObjectDirectory, NULL,
        (PENUMOBJECTSCALLBACK)EnumObjectsCallback,
        (PVOID)&enumParam);

    enumParam.ObjectDirectory = (PWSTR)L"\\Device";
    supEnumSystemObjects(enumParam.ObjectDirectory, NULL,
        (PENUMOBJECTSCALLBACK)EnumObjectsCallback,
        (PVOID)&enumParam);

    enumParam.ObjectDirectory = (PWSTR)L"\\Driver";
    RtlInitUnicodeString(&usObjectType, L"Driver");
    enumParam.ObjectType = &usObjectType;
    supEnumSystemObjects(enumParam.ObjectDirectory, NULL,
        (PENUMOBJECTSCALLBACK)EnumObjectsCallback,
        (PVOID)&enumParam);

}

VOID KDUListDrivers(
    _In_ PRTL_PROCESS_MODULES pvModules
)
{
    for (ULONG i = 0; i < pvModules->NumberOfModules; i++) {

        printf_s("\t%lu %p %lu %s\r\n",
            pvModules->Modules[i].LoadOrderIndex,
            pvModules->Modules[i].ImageBase,
            pvModules->Modules[i].ImageSize,
            pvModules->Modules[i].FullPathName);

    }

}

VOID KDUListMemoryLayout()
{
    PCM_FULL_RESOURCE_DESCRIPTOR pDesc;
    PCM_RESOURCE_LIST pList = supQueryPhysicalMemoryLayout();
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pPartialDesc;
    if (pList == NULL)
        return;

    printf_s("ResourceList Count %lx\r\n", pList->Count);
    for (ULONG i = 0; i < pList->Count; i++) {
        pDesc = &pList->List[i];

        printf_s("pDesc[%lu].PartialResourceList.Count %lu\r\n",
            i,
            pDesc->PartialResourceList.Count);

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

                printf_s("#%lu Flags 0x%04lX 0x%016llX::0x%016llX (length 0x%016llX, %llu Mb)\r\n",
                    j,
                    pPartialDesc->Flags,
                    pPartialDesc->u.Memory.Start.QuadPart,
                    pPartialDesc->u.Memory.Start.QuadPart + length,
                    length,
                    length / 1024 / 1024);

            }
            else {
                printf_s("#%lu Type 0x%04lX, Flags 0x%04lX\r\n", j, pPartialDesc->Type, pPartialDesc->Flags);
            }
        }

    }
    supHeapFree(pList);
}

VOID KDUDiagStart()
{
    PRTL_PROCESS_MODULES pvModules;
    ULONG_PTR systemRangeStart;
    DWORD dwDummy = 0;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    if (!GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &dwDummy)) {
        g_ConsoleOutput = FALSE;
    }

    //header
    printf_s("[+] Running system diagnostics\r\n");

    __try {

        systemRangeStart = ntsupQuerySystemRangeStart();
        printf_s("> System range start %llX\r\n", systemRangeStart);

        printf_s("> Speculation mitigation state flags\r\n");
        KDUQuerySpecMitigationState();

        pvModules = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(FALSE, NULL);
        if (pvModules) {

            printf_s("> List of loaded drivers\r\n\t[#] [ImageBase] [ImageSize] [FileName]\r\n");
            KDUListDrivers(pvModules);

            printf_s("> List of device and driver objects in the common locations\r\n");
            KDUListObjects();

            KDUBacktraceByHandle(systemRangeStart, pvModules);

            printf_s("> Analyzing process working set\r\n");
            KDUQueryProcessWorkingSet(systemRangeStart, pvModules);

            supHeapFree(pvModules);
        }
        else {
            supPrintfEvent(kduEventError, "Cannot allocate memory\r\n");
        }

        printf_s("> List of registered minifilters\r\n");
        KDUListFilters();

        printf_s("> Physical memory layout\r\n");
        KDUListMemoryLayout();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        supPrintfEvent(kduEventError, "Exception (0x%lX) during diagnostics\r\n", GetExceptionCode());
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
}
