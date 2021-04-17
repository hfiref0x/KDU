/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2021, translated from Microsoft sources/debugger
*
*  TITLE:       WDKSUP.H
*
*  VERSION:     1.10
*
*  DATE:        02 Apr 2021
*
*  Header file for NT WDK definitions.
*
*  WARNING: some structures are opaque and incomplete.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/
#pragma once

//
// Processor modes.
//

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

#define FIXED_UNICODE_STRING_LENGTH MAX_PATH

typedef struct _FIXED_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR Buffer[FIXED_UNICODE_STRING_LENGTH];
} FIXED_UNICODE_STRING, * PFIXED_UNICODE_STRING;

typedef _Enum_is_bitflag_ enum _WORK_QUEUE_TYPE {
    CriticalWorkQueue,
    DelayedWorkQueue,
    HyperCriticalWorkQueue,
    NormalWorkQueue,
    BackgroundWorkQueue,
    RealTimeWorkQueue,
    SuperCriticalWorkQueue,
    MaximumWorkQueue,
    CustomPriorityWorkQueue = 32
} WORK_QUEUE_TYPE;

typedef
VOID
WORKER_THREAD_ROUTINE(
    _In_ PVOID Parameter);

typedef WORKER_THREAD_ROUTINE* PWORKER_THREAD_ROUTINE;
typedef VOID* PACCESS_STATE;

typedef
NTSTATUS
DRIVER_INITIALIZE(
    _In_ struct _DRIVER_OBJECT* DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

typedef DRIVER_INITIALIZE* PDRIVER_INITIALIZE;

typedef struct _WORK_QUEUE_ITEM {
    LIST_ENTRY List;
    PWORKER_THREAD_ROUTINE WorkerRoutine;
    __volatile PVOID Parameter;
} WORK_QUEUE_ITEM, * PWORK_QUEUE_ITEM;

typedef BOOLEAN (NTAPI *pfnRtlCreateUnicodeString)(
    _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem))
    PUNICODE_STRING DestinationString,
    _In_z_ PCWSTR SourceString);

typedef NTSTATUS (WINAPI *pfnIoCreateDriver)(
    _In_ PUNICODE_STRING DriverName, OPTIONAL
    _In_ PDRIVER_INITIALIZE InitializationFunction);

typedef VOID(NTAPI* pfnExQueueWorkItem)(
    _Inout_ PWORK_QUEUE_ITEM WorkItem,
    _In_ WORK_QUEUE_TYPE QueueType);

typedef NTSTATUS(NTAPI* pfnZwOpenSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI* pfnZwMapViewOfSection)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect);

typedef NTSTATUS(NTAPI* pfnZwUnmapViewOfSection)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress);

typedef ULONG(NTAPI* pfnDbgPrint)(
    _In_ PCHAR Format,
    ...);

typedef PVOID(NTAPI* pfnExAllocatePoolWithTag)(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag);

typedef VOID(NTAPI* pfnExFreePoolWithTag)(
    _In_ PVOID P,
    _In_ ULONG Tag);

typedef NTSTATUS(NTAPI* pfnPsCreateSystemThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_  HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ PVOID StartContext);

typedef NTSTATUS(NTAPI* pfnZwClose)(
    _In_ HANDLE Handle);

typedef VOID(NTAPI* pfnIofCompleteRequest)(
    _In_ VOID* Irp,
    _In_ CCHAR PriorityBoost);

typedef NTSTATUS(NTAPI* pfnObReferenceObjectByHandle)(
    _In_ HANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PVOID* Object,
    _Out_opt_ PVOID HandleInformation);

typedef VOID(NTAPI* pfnObfDereferenceObject)(
    _In_ PVOID Object);

typedef NTSTATUS(NTAPI* pfnKeSetEvent)(
    _In_ PKEVENT Event,
    _In_ KPRIORITY Increment,
    _In_ _Literal_ BOOLEAN Wait);

typedef NTSTATUS(NTAPI* pfnObCreateObject)(
    _In_ KPROCESSOR_MODE ProbeMode,
    _In_ POBJECT_TYPE ObjectType,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ KPROCESSOR_MODE OwnershipMode,
    _Inout_opt_ PVOID ParseContext,
    _In_ ULONG ObjectBodySize,
    _In_ ULONG PagedPoolCharge,
    _In_ ULONG NonPagedPoolCharge,
    _Out_ PVOID* Object);

typedef NTSTATUS(NTAPI* pfnObInsertObject)(
    _In_ PVOID Object,
    _Inout_opt_ PACCESS_STATE AccessState,
    _Inout_opt_ ACCESS_MASK DesiredAccess,
    _In_ ULONG ObjectPointerBias,
    _Out_opt_ PVOID* NewObject,
    _Out_opt_ PHANDLE Handle);

typedef VOID(NTAPI* pfnObMakeTemporaryObject)(
    _In_ PVOID Object);

typedef NTSTATUS(NTAPI *pfnZwMakeTemporaryObject)(
    _In_ HANDLE Handle);

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
