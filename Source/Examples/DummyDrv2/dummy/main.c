/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.03
*
*  DATE:        02 Apr 2021
*
*  Example driver #2 for driver loaders usage (KDU/ALICE)
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include <ntddk.h>
#include "main.h"

/*
* PrintIrql
*
* Purpose:
*
* Debug print current irql.
*
*/
VOID PrintIrql()
{
    KIRQL Irql;
    PSTR sIrql;

    Irql = KeGetCurrentIrql();

    switch (Irql) {

    case PASSIVE_LEVEL:
        sIrql = "PASSIVE_LEVEL";
        break;
    case APC_LEVEL:
        sIrql = "APC_LEVEL";
        break;
    case DISPATCH_LEVEL:
        sIrql = "DISPATCH_LEVEL";
        break;
    case CMCI_LEVEL:
        sIrql = "CMCI_LEVEL";
        break;
    case CLOCK_LEVEL:
        sIrql = "CLOCK_LEVEL";
        break;
    case IPI_LEVEL:
        sIrql = "IPI_LEVEL";
        break;
    case HIGH_LEVEL:
        sIrql = "HIGH_LEVEL";
        break;
    default:
        sIrql = "Unknown Value";
        break;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] KeGetCurrentIrql=%u(%s)\r\n",
        __FUNCTION__,
        Irql,
        sIrql);
}

/*
* DevioctlDispatch
*
* Purpose:
*
* IRP_MJ_DEVICE_CONTROL dispatch.
*
*/
NTSTATUS DevioctlDispatch(
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp
)
{
    NTSTATUS				status = STATUS_SUCCESS;
    ULONG					bytesIO = 0;
    PIO_STACK_LOCATION		stack;
    BOOLEAN					condition = FALSE;
    PINOUTPARAM             rp, wp;

    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] IRP_MJ_DEVICE_CONTROL\r\n",
        __FUNCTION__);

    stack = IoGetCurrentIrpStackLocation(Irp);

    do {

        if (stack == NULL) {
            status = STATUS_INTERNAL_ERROR;
            break;
        }

        rp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
        wp = (PINOUTPARAM)Irp->AssociatedIrp.SystemBuffer;
        if (rp == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case DUMMYDRV_REQUEST1:

            DbgPrintEx(DPFLTR_DEFAULT_ID,
                DPFLTR_INFO_LEVEL,
                "[%s] DUMMYDRV_REQUEST1 hit\r\n",
                __FUNCTION__);

            if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(INOUT_PARAM)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            DbgPrintEx(DPFLTR_DEFAULT_ID,
                DPFLTR_INFO_LEVEL,
                "[%s] Params = %lx, %lx, %lx, %lx\r\n",
                __FUNCTION__,
                rp->Param1,
                rp->Param2,
                rp->Param3,
                rp->Param4);

            wp->Param1 = 11111111;
            wp->Param2 = 22222222;
            wp->Param3 = 33333333;
            wp->Param4 = 44444444;

            status = STATUS_SUCCESS;
            bytesIO = sizeof(INOUT_PARAM);

            break;

        default:

            DbgPrintEx(DPFLTR_DEFAULT_ID,
                DPFLTR_INFO_LEVEL,
                "[%s] Hit with invalid IoControlCode\r\n",
                __FUNCTION__);

            status = STATUS_INVALID_PARAMETER;
            break;
        };

    } while (condition);

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
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp
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
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp
)
{
    NTSTATUS status = Irp->IoStatus.Status;
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] Create\r\n",
        __FUNCTION__);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
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
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp
)
{
    NTSTATUS status = Irp->IoStatus.Status;
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] Close\r\n",
        __FUNCTION__);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*
* DriverInitialize
*
* Purpose:
*
* Driver main.
*
*/
NTSTATUS DriverInitialize(
    _In_  struct _DRIVER_OBJECT* DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        status;
    UNICODE_STRING  SymLink, DevName;
    PDEVICE_OBJECT  devobj;
    ULONG           t;

    PETHREAD        ThreadObject;
    PEPROCESS       ProcessObject;

    //RegistryPath is NULL
    UNREFERENCED_PARAMETER(RegistryPath);

    ProcessObject = PsGetCurrentProcess();
    ThreadObject = PsGetCurrentThread();

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] CurrentProcess : %lu (%p) CurrentThread : %lu (%p)\r\n",
        __FUNCTION__,
        HandleToUlong(PsGetCurrentProcessId()),
        ProcessObject,
        HandleToUlong(PsGetCurrentThreadId()),
        ThreadObject);

    RtlInitUnicodeString(&DevName, L"\\Device\\TDLD");
    status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] IoCreateDevice(%wZ) = %lx\r\n",
        __FUNCTION__,
        &DevName,
        status);

    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&SymLink, L"\\DosDevices\\TDLD");
    status = IoCreateSymbolicLink(&SymLink, &DevName);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] IoCreateSymbolicLink(%wZ) = %lx\r\n",
        __FUNCTION__,
        &SymLink,
        status);

    devobj->Flags |= DO_BUFFERED_IO;

    for (t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
        DriverObject->MajorFunction[t] = &UnsupportedDispatch;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
    DriverObject->DriverUnload = NULL; //nonstandard way of driver loading, no unload

    devobj->Flags &= ~DO_DEVICE_INITIALIZING;
    return status;
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
    _In_  struct _DRIVER_OBJECT* DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        status;
    UNICODE_STRING  drvName;

    /* This parameters are invalid due to nonstandard way of loading and should not be used. */
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[%s] Driver built at %s\r\n",
        __FUNCTION__, __TIMESTAMP__); // Set DriverModel to allow timestamps.

    PrintIrql();

    RtlInitUnicodeString(&drvName, L"\\Driver\\TDLD");
    status = IoCreateDriver(&drvName, &DriverInitialize);

    if (status == STATUS_OBJECT_NAME_COLLISION) {

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[%s] Driver object %wZ already exist\r\n",
            __FUNCTION__, &drvName);

    }
    else {

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[%s] IoCreateDriver(%wZ) = %lx\r\n",
            __FUNCTION__,
            &drvName,
            status);

    }

    return status;
}
