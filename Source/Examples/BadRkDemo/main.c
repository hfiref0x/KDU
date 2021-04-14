/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2021
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.02
*
*  DATE:        02 Apr 2021
*
*  PatchGuard BSOD generator.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "main.h"

RTL_OSVERSIONINFOW g_osver;

typedef NTSTATUS(NTAPI * pfnDispatch)(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp);

pfnDispatch g_NtfsFsdCreateOriginal = NULL;

/*
* ModifyPsLoadedModuleList
*
* Purpose:
*
* Modify PsLoadedModulesList by removing entry from it.
*
* Expected PG BSOD: Loaded module list modification.
*
*/
#pragma warning(push)
#pragma warning(disable: 28175) //private member of struct
NTSTATUS ModifyPsLoadedModuleList(
    _In_ DEVICE_OBJECT *DeviceObject)
{
    DRIVER_OBJECT *DriverObject = DeviceObject->DriverObject;
    KLDR_DATA_TABLE_ENTRY *LoaderSection = (KLDR_DATA_TABLE_ENTRY*)DriverObject->DriverSection;

    //
    // Corrupt list.
    //
    if (RemoveEntryList(&LoaderSection->InLoadOrderLinks))
        return STATUS_SUCCESS;

    return STATUS_UNSUCCESSFUL;
}
#pragma warning(pop)

NTSTATUS NtfsFsdCreateHook(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[PGDemo] NtfsFsdCreate called\r\n");
    }
    return g_NtfsFsdCreateOriginal(DeviceObject, Irp);
}

/*
* ModifyDriverObject
*
* Purpose:
*
* Modify driver object by replacing IRP handler for NTFS->IRP_MJ_CREATE.
*
* Expected PG BSOD: Driver object corruption.
*
*/
#pragma warning(push)
#pragma warning(disable: 28175) //private member of struct
NTSTATUS ModifyDriverObject(
    VOID)
{
    NTSTATUS Status;
    UNICODE_STRING fsdName;
    PDRIVER_OBJECT drvNtfs;

    RtlInitUnicodeString(&fsdName, L"\\FileSystem\\NTFS");

    //
    // Modify driver object
    //
    Status = ObReferenceObjectByName(
        &fsdName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        &drvNtfs);

    if (NT_SUCCESS(Status)) {

        g_NtfsFsdCreateOriginal = InterlockedExchangePointer(
            (PVOID*)&drvNtfs->MajorFunction[IRP_MJ_CREATE],
            (PVOID)NtfsFsdCreateHook);

        ObfDereferenceObject(drvNtfs);
    }

    return Status;
}
#pragma warning(pop)

typedef struct _CPUInfo {
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUInfo, *PCPUInfo;

/*
* ModifyCR4
*
* Purpose:
*
* Modify CR4 by turning off SMEP (if supported).
*
* Expected PG BSOD: A processor control register.
*
*/
NTSTATUS ModifyCR4(
    VOID)
{
    ULONG_PTR cr4;

    CPUInfo cpuInfo = { 0, 0, 0, 0 };

    KeSetSystemAffinityThread(0x00000001);

    __cpuid((int*)&cpuInfo, 7);

    if (cpuInfo.ebx & (1 << 7)) {

        //
        // Modify CR4, disable SMEP.
        //
        cr4 = __readcr4();

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[PGDemo] cr4 value, before = %llx\r\n", cr4);

        cr4 &= ~(1 << 20);
        __writecr4(cr4);

        cr4 = __readcr4();

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[PGDemo] cr4 value, after = %llx\r\n", cr4);

        return STATUS_SUCCESS;
    }

    return STATUS_NOT_SUPPORTED;
}

// xor eax, eax
// retn
unsigned char StubRoutine[] = { 0x33, 0xC0, 0xC3 };

/*
* SetNotifyFromPool
*
* Purpose:
*
* Allocate nonpaged executable pool and use it as LoadImageNotifyRoutine code.
*
* Expected PG BSOD: Kernel notification callout modification.
*
*/
#pragma warning(push)
#pragma warning(disable: 6014) //leaking memory
#pragma warning(disable: 30030) //executable memory
NTSTATUS SetNotifyFromPool(
    VOID)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID CodeBuffer;

    CodeBuffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'edgP');
    if (CodeBuffer) {
        RtlSecureZeroMemory(CodeBuffer, PAGE_SIZE);
        RtlCopyMemory(CodeBuffer, StubRoutine, sizeof(StubRoutine));
        status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)CodeBuffer);

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[PGDemo] CodeBuffer=%p, PsSetLoadImageNotifyRoutine=%lx\r\n", CodeBuffer, status);
    }
    return status;
}
#pragma warning(pop)

/*
* DevioctlDispatch
*
* Purpose:
*
* IRP_MJ_DEVICE_CONTROL dispatch.
*
*/
NTSTATUS DevioctlDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    NTSTATUS				status = STATUS_SUCCESS;
    ULONG					bytesIO = 0;
    PIO_STACK_LOCATION		stack;
    PINOUTPARAM             rp;

    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[PGDemo] %s IRP_MJ_DEVICE_CONTROL\r\n", 
        __FUNCTION__);

    stack = IoGetCurrentIrpStackLocation(Irp);

    do {

        if (stack == NULL) {
            status = STATUS_INTERNAL_ERROR;
            break;
        }

        rp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
        if (rp == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case PGDEMO_SET_TEST_TYPE:


            DbgPrintEx(DPFLTR_DEFAULT_ID,
                DPFLTR_INFO_LEVEL,
                "[PGDemo] %s PGDEMO_SET_TEST_TYPE hit\r\n", 
                __FUNCTION__);

            if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(INOUT_PARAM)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            switch (rp->TestType) {

            case TT_DRIVER_LIST:

                DbgPrintEx(DPFLTR_DEFAULT_ID,
                    DPFLTR_INFO_LEVEL,
                    "[PGDemo] Corrupting drivers list\r\n");

                status = ModifyPsLoadedModuleList(DeviceObject);
                break;

            case TT_DRIVER_OBJECT:

                DbgPrintEx(DPFLTR_DEFAULT_ID,
                    DPFLTR_INFO_LEVEL,
                    "[PGDemo] Corrupting driver object\r\n");
                
                status = ModifyDriverObject();
                break;

            case TT_CR4:

                DbgPrintEx(DPFLTR_DEFAULT_ID,
                    DPFLTR_INFO_LEVEL,
                    "[PGDemo] Corrupting CPU Control Register\r\n");
                
                status = ModifyCR4();
                if (status == STATUS_NOT_SUPPORTED) {

                    DbgPrintEx(DPFLTR_DEFAULT_ID,
                        DPFLTR_INFO_LEVEL,
                        "[PGDemo] SMEP not supported\r\n");
                }
                break;

            case TT_NOTIFY_CALLOUT:

                DbgPrintEx(DPFLTR_DEFAULT_ID,
                    DPFLTR_INFO_LEVEL,
                    "[PGDemo] Corrupting notify callout\r\n");

                status = SetNotifyFromPool();
                break;

            default:

                DbgPrintEx(DPFLTR_DEFAULT_ID,
                    DPFLTR_INFO_LEVEL,
                    "[PGDemo] %lx is unknown test type\r\n", 
                    rp->TestType);
                
                break;
            }

            status = STATUS_SUCCESS;
            bytesIO = sizeof(INOUT_PARAM);

            break;

        default:

            DbgPrintEx(DPFLTR_DEFAULT_ID,
                DPFLTR_INFO_LEVEL,
                "[PGDemo] %s hit with invalid IoControlCode\r\n", 
                __FUNCTION__);
            
            status = STATUS_INVALID_PARAMETER;
        };

    } while (FALSE);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*
* UnsupportedDispatch
*
* Purpose:
*
* Unused IRP_MJ_* dispatch.
*
*/
NTSTATUS UnsupportedDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

/*
* CreateDispatch
*
* Purpose:
*
* IRP_MJ_CREATE dispatch.
*
*/
NTSTATUS CreateDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[PGDemo] %s Create\r\n", 
        __FUNCTION__);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
* CloseDispatch
*
* Purpose:
*
* IRP_MJ_CLOSE dispatch.
*
*/
NTSTATUS CloseDispatch(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[PGDemo] %s Close\r\n", 
        __FUNCTION__);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
* BeaconRoutine
*
* Purpose:
*
* Print alive message in infinite loop with a short delay.
*
*/
_IRQL_requires_same_
_Function_class_(KSTART_ROUTINE)
VOID BeaconRoutine(
    _In_ PVOID StartContext
)
{
    LARGE_INTEGER tm, time;
    TIME_FIELDS SystemTime;

    UNREFERENCED_PARAMETER(StartContext);

    tm.QuadPart = -10000000;

    do {
        KeDelayExecutionThread(KernelMode, FALSE, &tm);

        KeQuerySystemTime(&time);
        RtlTimeToTimeFields(&time, &SystemTime);


        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[PGDemo] Beacon %02hd:%02hd:%02hd:%03hd\r\n",
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Milliseconds);

    } while (1);
}

/*
* DriverEntry
*
* Purpose:
*
* Driver base entry point.
*
*/
NTSTATUS DriverEntry(
    _In_  struct _DRIVER_OBJECT *DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    HANDLE              hThread;
    UNICODE_STRING      SymLink, DevName, SddlString;
    OBJECT_ATTRIBUTES   Obja;
    PDEVICE_OBJECT      devobj;
    ULONG               t;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL, 
        "[PGDemo] %s\r\n",
        __FUNCTION__);

    RtlSecureZeroMemory(&g_osver, sizeof(RTL_OSVERSIONINFOW));
    g_osver.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    if (NT_SUCCESS(RtlGetVersion(&g_osver))) {
        if (g_osver.dwBuildNumber <= 10240) {

            DbgPrintEx(DPFLTR_DEFAULT_ID,
                DPFLTR_INFO_LEVEL, 
                "[PGDemo] This version of Windows is out of interest\r\n");

            return STATUS_NOT_SUPPORTED;
        }
    }
    else {
        return STATUS_INTERNAL_ERROR;
    }

    RtlInitUnicodeString(&DevName, PGDEMO_DEVICE);
    RtlInitUnicodeString(&SddlString, PGDEMO_DEVICE_SDDL);
    
    status = IoCreateDeviceSecure(DriverObject,
        0,
        &DevName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &SddlString,
        (LPCGUID)&GUID_PGDEMO,
        &devobj);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL, 
        "[PGDemo] %s IoCreateDeviceSecure(%wZ) = %lx\r\n", 
        __FUNCTION__, 
        &DevName, 
        status);

    if (NT_SUCCESS(status)) {

        RtlInitUnicodeString(&SymLink, PGDEMO_SYMLINK);
        status = IoCreateSymbolicLink(&SymLink, &DevName);

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL, 
            "[PGDemo] %s IoCreateSymbolicLink(%wZ) = %lx\r\n", 
            __FUNCTION__, 
            &SymLink, 
            status);

        devobj->Flags |= DO_BUFFERED_IO;

        for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
            DriverObject->MajorFunction[t] = &UnsupportedDispatch;

        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
        DriverObject->DriverUnload = NULL;

        devobj->Flags &= ~DO_DEVICE_INITIALIZING;

        hThread = NULL;
        InitializeObjectAttributes(&Obja, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        if (NT_SUCCESS(PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &Obja, NULL, NULL,
            (PKSTART_ROUTINE)BeaconRoutine, NULL)))
        {
            ZwClose(hThread);
        }
    }

    return status;
}
