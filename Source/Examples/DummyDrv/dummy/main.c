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
*  Example driver for driver loaders usage (KDU/ALICE)
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

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
    PEPROCESS Process;
    PETHREAD Thread;
    KIRQL Irql;
    PSTR sIrql;

    /* This parameters are invalid due to nonstandard way of loading and should not be used. */
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    Irql = KeGetCurrentIrql();
    if (Irql <= DISPATCH_LEVEL) {

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[%s] Driver built at %s\r\n",
            __FUNCTION__, __TIMESTAMP__); // Set DriverModel to allow timestamps.

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[%s] System range start is %p, code mapped at %p\r\n",
            __FUNCTION__,
            MmSystemRangeStart,
            DriverEntry);       

        Process = PsGetCurrentProcess();
        Thread = PsGetCurrentThread();
        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[%s] Current Process : %lu (%p) Current Thread : %lu (%p)\r\n",
            __FUNCTION__,           
            HandleToULong(PsGetCurrentProcessId()),
            Process,
            HandleToULong(PsGetCurrentThreadId()),
            Thread);

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
        default:
            sIrql = "Unknown Value";
            break;
        }

        DbgPrintEx(DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[%s] KeGetCurrentIrql=%s\r\n",
            __FUNCTION__,
            sIrql);
    }

    return STATUS_SUCCESS;
}
