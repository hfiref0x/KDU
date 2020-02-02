/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2020
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.02
*
*  DATE:        24 Jan 2020
*
*  Example driver for driver loaders usage (TDL/Stryker/Diplodocus/KDU)
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
    _In_  struct _DRIVER_OBJECT *DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    PEPROCESS Process;
    KIRQL Irql;
    PSTR sIrql;

    /* This parameters are invalid due to nonstandard way of loading and should not be used. */
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    Irql = KeGetCurrentIrql();
    if (Irql <= DISPATCH_LEVEL) {

        DbgPrintEx(DPFLTR_DEFAULT_ID, 
            DPFLTR_INFO_LEVEL, 
            "Hello from kernel mode, system range start is %p, code mapped at %p\r\n", 
            MmSystemRangeStart, 
            DriverEntry);

        Process = PsGetCurrentProcess();
        DbgPrintEx(DPFLTR_DEFAULT_ID, 
            DPFLTR_INFO_LEVEL, 
            "I'm at %s, Process : %lu (%p)\r\n",
            __FUNCTION__,
            (ULONG)PsGetCurrentProcessId(),
            Process);

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
            "KeGetCurrentIrql=%s\r\n", 
            sIrql);
    }

    return STATUS_SUCCESS;
}
