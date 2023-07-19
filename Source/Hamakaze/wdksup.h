/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2023, translated from Microsoft sources/debugger
*
*  TITLE:       WDKSUP.H
*
*  VERSION:     1.33
*
*  DATE:        16 Jul 2023
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

#define IO_NO_INCREMENT 0

//
// Processor modes.
//

#ifndef NTOS_RTL

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

#endif

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

typedef int CM_RESOURCE_TYPE;

// CmResourceTypeNull is reserved

#define CmResourceTypeNull                0   // ResType_All or ResType_None (0x0000)
#define CmResourceTypePort                1   // ResType_IO (0x0002)
#define CmResourceTypeInterrupt           2   // ResType_IRQ (0x0004)
#define CmResourceTypeMemory              3   // ResType_Mem (0x0001)
#define CmResourceTypeDma                 4   // ResType_DMA (0x0003)
#define CmResourceTypeDeviceSpecific      5   // ResType_ClassSpecific (0xFFFF)
#define CmResourceTypeBusNumber           6   // ResType_BusNumber (0x0006)
#define CmResourceTypeMemoryLarge         7   // ResType_MemLarge (0x0007)
#define CmResourceTypeNonArbitrated     128   // Not arbitrated if 0x80 bit set
#define CmResourceTypeConfigData        128   // ResType_Reserved (0x8000)
#define CmResourceTypeDevicePrivate     129   // ResType_DevicePrivate (0x8001)
#define CmResourceTypePcCardConfig      130   // ResType_PcCardConfig (0x8002)
#define CmResourceTypeMfCardConfig      131   // ResType_MfCardConfig (0x8003)
#define CmResourceTypeConnection        132   // ResType_Connection (0x8004)

#define CM_RESOURCE_MEMORY_LARGE_40  0x0200
#define CM_RESOURCE_MEMORY_LARGE_48  0x0400
#define CM_RESOURCE_MEMORY_LARGE_64  0x0800
#define CM_RESOURCE_MEMORY_LARGE     (CM_RESOURCE_MEMORY_LARGE_40 | CM_RESOURCE_MEMORY_LARGE_48 | CM_RESOURCE_MEMORY_LARGE_64)

//
// Define the bit masks for Flags when type is CmResourceTypeMemory
// or CmResourceTypeMemoryLarge
//

#define CM_RESOURCE_MEMORY_READ_WRITE                       0x0000
#define CM_RESOURCE_MEMORY_READ_ONLY                        0x0001
#define CM_RESOURCE_MEMORY_WRITE_ONLY                       0x0002
#define CM_RESOURCE_MEMORY_WRITEABILITY_MASK                0x0003
#define CM_RESOURCE_MEMORY_PREFETCHABLE                     0x0004

#define CM_RESOURCE_MEMORY_COMBINEDWRITE                    0x0008
#define CM_RESOURCE_MEMORY_24                               0x0010
#define CM_RESOURCE_MEMORY_CACHEABLE                        0x0020
#define CM_RESOURCE_MEMORY_WINDOW_DECODE                    0x0040
#define CM_RESOURCE_MEMORY_BAR                              0x0080

#define CM_RESOURCE_MEMORY_COMPAT_FOR_INACCESSIBLE_RANGE    0x0100

//
// Define limits for large memory resources
//

#define CM_RESOURCE_MEMORY_LARGE_40_MAXLEN          0x000000FFFFFFFF00
#define CM_RESOURCE_MEMORY_LARGE_48_MAXLEN          0x0000FFFFFFFF0000
#define CM_RESOURCE_MEMORY_LARGE_64_MAXLEN          0xFFFFFFFF00000000

#include "pshpack4.h"
typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    union {

        //
        // Range of resources, inclusive.  These are physical, bus relative.
        // It is known that Port and Memory below have the exact same layout
        // as Generic.
        //

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Generic;

        //
        //

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Port;

        //
        //

        struct {
#if defined(NT_PROCESSOR_GROUPS)
            USHORT Level;
            USHORT Group;
#else
            ULONG Level;
#endif
            ULONG Vector;
            KAFFINITY Affinity;
        } Interrupt;

        //
        // Values for message signaled interrupts are distinct in the
        // raw and translated cases.
        //

        struct {
            union {
                struct {
#if defined(NT_PROCESSOR_GROUPS)
                    USHORT Group;
#else
                    USHORT Reserved;
#endif
                    USHORT MessageCount;
                    ULONG Vector;
                    KAFFINITY Affinity;
                } Raw;

                struct {
#if defined(NT_PROCESSOR_GROUPS)
                    USHORT Level;
                    USHORT Group;
#else
                    ULONG Level;
#endif
                    ULONG Vector;
                    KAFFINITY Affinity;
                } Translated;
            } DUMMYUNIONNAME;
        } MessageInterrupt;

        //
        // Range of memory addresses, inclusive. These are physical, bus
        // relative. The value should be the same as the one passed to
        // HalTranslateBusAddress().
        //

        struct {
            PHYSICAL_ADDRESS Start;    // 64 bit physical addresses.
            ULONG Length;
        } Memory;

        //
        // Physical DMA channel.
        //

        struct {
            ULONG Channel;
            ULONG Port;
            ULONG Reserved1;
        } Dma;

        //
        // Device driver private data, usually used to help it figure
        // what the resource assignments decisions that were made.
        //

        struct {
            ULONG Data[3];
        } DevicePrivate;

        //
        // Bus Number information.
        //

        struct {
            ULONG Start;
            ULONG Length;
            ULONG Reserved;
        } BusNumber;

        //
        // Device Specific information defined by the driver.
        // The DataSize field indicates the size of the data in bytes. The
        // data is located immediately after the DeviceSpecificData field in
        // the structure.
        //

        struct {
            ULONG DataSize;
            ULONG Reserved1;
            ULONG Reserved2;
        } DeviceSpecificData;

        // The following structures provide support for memory-mapped
        // IO resources greater than MAXULONG
        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length40;
        } Memory40;

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length48;
        } Memory48;

        struct {
            PHYSICAL_ADDRESS Start;
            ULONG Length64;
        } Memory64;


    } u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR, * PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#include "poppack.h"

//
// A Partial Resource List is what can be found in the ARC firmware
// or will be generated by ntdetect.com.
// The configuration manager will transform this structure into a Full
// resource descriptor when it is about to store it in the regsitry.
//
// Note: There must a be a convention to the order of fields of same type,
// (defined on a device by device basis) so that the fields can make sense
// to a driver (i.e. when multiple memory ranges are necessary).
//

typedef struct _CM_PARTIAL_RESOURCE_LIST {
    USHORT Version;
    USHORT Revision;
    ULONG Count;
    CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
} CM_PARTIAL_RESOURCE_LIST, * PCM_PARTIAL_RESOURCE_LIST;

//
// A Full Resource Descriptor is what can be found in the registry.
// This is what will be returned to a driver when it queries the registry
// to get device information; it will be stored under a key in the hardware
// description tree.
//
// Note: There must a be a convention to the order of fields of same type,
// (defined on a device by device basis) so that the fields can make sense
// to a driver (i.e. when multiple memory ranges are necessary).
//

typedef struct _CM_FULL_RESOURCE_DESCRIPTOR {
    INTERFACE_TYPE InterfaceType; // unused for WDM
    ULONG BusNumber; // unused for WDM
    CM_PARTIAL_RESOURCE_LIST PartialResourceList;
} CM_FULL_RESOURCE_DESCRIPTOR, * PCM_FULL_RESOURCE_DESCRIPTOR;

//
// The Resource list is what will be stored by the drivers into the
// resource map via the IO API.
//

typedef struct _CM_RESOURCE_LIST {
    ULONG Count;
    CM_FULL_RESOURCE_DESCRIPTOR List[1];
} CM_RESOURCE_LIST, * PCM_RESOURCE_LIST;

//x64
typedef struct _MMPTE_HARDWARE {
    union {
        ULONGLONG Flags;
        struct {
            ULONGLONG Valid : 1;
            ULONGLONG Dirty1 : 1;
            ULONGLONG Owner : 1;
            ULONGLONG WriteThrough : 1;
            ULONGLONG CacheDisable : 1;
            ULONGLONG Accessed : 1;
            ULONGLONG Dirty : 1;
            ULONGLONG LargePage : 1;
            ULONGLONG Global : 1;
            ULONGLONG CopyOnWrite : 1;
            ULONGLONG Unused : 1;
            ULONGLONG Write : 1;
            ULONGLONG PageFrameNumber : 40;
            ULONGLONG ReservedForSoftware : 4;
            ULONGLONG WsleAge : 4;
            ULONGLONG WsleProtection : 3;
            ULONGLONG NoExecute : 1;
        };
    };
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef union _tagMMPTE {
    ULONGLONG Value;
    MMPTE_HARDWARE HardwarePte;
} MMPTE, *PMMPTE;

typedef struct _MI_PTE_HIERARCHY {
    ULONG_PTR PXE;
    ULONG_PTR PPE;
    ULONG_PTR PDE;
    ULONG_PTR PTE;
} MI_PTE_HIERARCHY, * PMI_PTE_HIERARCHY;

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

typedef NTSTATUS(NTAPI* pfnDriverEntry)();

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

typedef PVOID(NTAPI* pfnExAllocatePool)(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes);

typedef PVOID(NTAPI* pfnExAllocatePoolWithTag)(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag);

typedef VOID(NTAPI* pfnExFreePoolWithTag)(
    _In_ PVOID P,
    _In_ ULONG Tag);

typedef PVOID (NTAPI* pfnMmGetSystemRoutineAddress)(
    _In_ PUNICODE_STRING SystemRoutineName);

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
