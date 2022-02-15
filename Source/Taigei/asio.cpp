/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       ASIO.CPP
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  Asus hack-o-rama v3.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

VOID RegisterTrustedCallerForAsIO()
{
    NTSTATUS ntStatus;
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    PROCESS_BASIC_INFORMATION pbi;

    DWORD dummyValue, parentPID;

    LARGE_INTEGER liTimeOut;
    HANDLE deviceHandle;

    ntStatus = NtQueryInformationProcess(NtCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &dummyValue);

    if (NT_SUCCESS(ntStatus)) {

        parentPID = PtrToUlong((PVOID)pbi.InheritedFromUniqueProcessId);

        RtlInitUnicodeString(&deviceName, L"\\Device\\Asusgio3");
        InitializeObjectAttributes(&objectAttributes, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        ntStatus = NtCreateFile(&deviceHandle,
            GENERIC_READ | GENERIC_WRITE,
            &objectAttributes,
            &ioStatusBlock,
            NULL,
            0,
            0,
            FILE_OPEN,
            0,
            NULL,
            0);

        if (NT_SUCCESS(ntStatus)) {

            dummyValue = 0;

            ntStatus = NtDeviceIoControlFile(deviceHandle,
                NULL,
                NULL,
                NULL,
                &ioStatusBlock,
                IOCTL_ASUSIO_REGISTER_TRUSTED_CALLER,
                &parentPID,
                sizeof(parentPID),
                &dummyValue,
                sizeof(dummyValue));

            if (NT_SUCCESS(ntStatus)) {

                liTimeOut.QuadPart = UInt32x32To64(3000, 10000);
                liTimeOut.QuadPart *= -1;

                //
                // Infinite loop.
                //
                while (TRUE) {

                    NtDelayExecution(0, (PLARGE_INTEGER)&liTimeOut);

                }
            }
        }

    }
}

#define EXPORT comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)

BOOL WINAPI UnlockAsIO(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

#define EXPORT
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        RegisterTrustedCallerForAsIO();
    }

    return TRUE;
}
