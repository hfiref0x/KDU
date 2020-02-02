/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018, translated from Microsoft sources/debugger
*
*  TITLE:       IRP.H
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Header file for IRP/STACK_LOCATION define.
*
*  WARNING: structures opaque and incomplete.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/
#pragma once

typedef
VOID
(NTAPI* PIO_APC_ROUTINE) (
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    //incomplete
} IO_STACK_LOCATION, * PIO_STACK_LOCATION;

typedef struct _KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    struct _KTHREAD* Thread;
    LIST_ENTRY ApcListEntry;
    PVOID Reserved[3];
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CCHAR ApcStateIndex;
    KPROCESSOR_MODE ApcMode;
    BOOLEAN Inserted;
} KAPC, * PKAPC, * PRKAPC;

#pragma warning(push)
#pragma warning(disable:4324) // structure padded due to __declspec(align())
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _IRP {
    CSHORT Type;
    USHORT Size;
    PVOID MdlAddress;
    ULONG Flags;

    union {
        struct _IRP* MasterIrp;
        __volatile LONG IrpCount;
        PVOID SystemBuffer;
    } AssociatedIrp;

    LIST_ENTRY ThreadListEntry;
    IO_STATUS_BLOCK IoStatus;
    KPROCESSOR_MODE RequestorMode;
    BOOLEAN PendingReturned;
    CHAR StackCount;
    CHAR CurrentLocation;
    BOOLEAN Cancel;
    KIRQL CancelIrql;
    CCHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PIO_STATUS_BLOCK UserIosb;
    PVOID UserEvent;
    union {
        struct {
            union {
                PIO_APC_ROUTINE UserApcRoutine;
                PVOID IssuingProcess;
            };
            PVOID UserApcContext;
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay;

    __volatile PVOID CancelRoutine;

    PVOID UserBuffer;

    union {

        struct {

            union {

                KDEVICE_QUEUE_ENTRY DeviceQueueEntry;

                struct {
                    PVOID DriverContext[4];
                };

            };

            PVOID Thread;
            PCHAR AuxiliaryBuffer;

            struct {

                LIST_ENTRY ListEntry;

                union {

                    struct _IO_STACK_LOCATION* CurrentStackLocation;
                    ULONG PacketType;
                };
            };

            PVOID OriginalFileObject;

        } Overlay;

        //incomplete

    } Tail;

} IRP;
#pragma warning(pop)

typedef IRP* PIRP;

FORCEINLINE
PIO_STACK_LOCATION
IoGetCurrentIrpStackLocation(
    _In_ PIRP Irp
)
{
    return Irp->Tail.Overlay.CurrentStackLocation;
}
