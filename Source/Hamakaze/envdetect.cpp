/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2026
*
*  TITLE:       ENVDETECT.CPP
*
*  VERSION:     1.51
*
*  DATE:        16 Nov 2026
*
*  Environment diagnostics support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "envdetect.h"

/*
* KDURegistryKeyExists
*
* Purpose:
*
* Return TRUE if the specified registry key can be opened.
*
*/
BOOL KDURegistryKeyExists(
    _In_ HKEY RootKey,
    _In_ LPCWSTR SubKey
)
{
    HKEY hKey;
    LSTATUS lResult;

    hKey = NULL;
    lResult = RegOpenKeyEx(RootKey, SubKey, 0, KEY_QUERY_VALUE, &hKey);
    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }

    return FALSE;
}

/*
* KDUAppendEnvironmentIndicator
*
* Purpose:
*
* Append a diagnostic indicator string to the environment description buffer.
*
*/
VOID KDUAppendEnvironmentIndicator(
    _Inout_ PKDU_ENVIRONMENT_INFO EnvironmentInfo,
    _In_ LPCWSTR Indicator
)
{
    SIZE_T cch;
    SIZE_T remain;

    if (EnvironmentInfo->Description[0] == 0) {
        _strncpy(EnvironmentInfo->Description,
            RTL_NUMBER_OF(EnvironmentInfo->Description),
            Indicator,
            RTL_NUMBER_OF(EnvironmentInfo->Description) - 1);
        return;
    }

    cch = _strlen(EnvironmentInfo->Description);
    remain = RTL_NUMBER_OF(EnvironmentInfo->Description) - cch;

    if (_strlen(Indicator) + 3 > remain)
        return;

    _strcat(EnvironmentInfo->Description, L", ");
    _strcat(EnvironmentInfo->Description, Indicator);
}

/*
* KDUAddVmIndicator
*
* Purpose:
*
* Record a virtualization-related diagnostic indicator.
*
*/
VOID KDUAddVmIndicator(
    _Inout_ PKDU_ENVIRONMENT_INFO EnvironmentInfo,
    _In_ LPCWSTR Indicator
)
{
    EnvironmentInfo->VmArtifactsPresent = TRUE;
    EnvironmentInfo->IndicatorCount++;
    KDUAppendEnvironmentIndicator(EnvironmentInfo, Indicator);
}

/*
* KDUAddSandboxIndicator
*
* Purpose:
*
* Record a sandbox-related diagnostic indicator.
*
*/
VOID KDUAddSandboxIndicator(
    _Inout_ PKDU_ENVIRONMENT_INFO EnvironmentInfo,
    _In_ LPCWSTR Indicator
)
{
    EnvironmentInfo->SandboxArtifactsPresent = TRUE;
    EnvironmentInfo->IndicatorCount++;
    KDUAppendEnvironmentIndicator(EnvironmentInfo, Indicator);
}

/*
* KDUAddEmulationIndicator
*
* Purpose:
*
* Record an emulation-related diagnostic indicator.
*
*/
VOID KDUAddEmulationIndicator(
    _Inout_ PKDU_ENVIRONMENT_INFO EnvironmentInfo,
    _In_ LPCWSTR Indicator
)
{
    EnvironmentInfo->EmulationArtifactsPresent = TRUE;
    EnvironmentInfo->IndicatorCount++;
    KDUAppendEnvironmentIndicator(EnvironmentInfo, Indicator);
}

/*
* KDUQueryVmArtifacts
*
* Purpose:
*
* Query known virtualization-related object and registry artifacts.
*
*/
VOID KDUQueryVmArtifacts(
    _Inout_ PKDU_ENVIRONMENT_INFO EnvironmentInfo
)
{
    if (supIsObjectExists(L"\\Device", L"VBoxMiniRdrDN"))
        KDUAddVmIndicator(EnvironmentInfo, L"VirtualBox MiniRdr");

    if (supIsObjectExists(L"\\Device", L"VBoxGuest"))
        KDUAddVmIndicator(EnvironmentInfo, L"VirtualBox Guest");

    if (supIsObjectExists(L"\\Device", L"vmci"))
        KDUAddVmIndicator(EnvironmentInfo, L"VMware VMCI");

    if (supIsObjectExists(L"\\Device", L"VMMEMCTL"))
        KDUAddVmIndicator(EnvironmentInfo, L"VMware balloon");

    if (supIsObjectExists(L"\\Device", L"HGFS"))
        KDUAddVmIndicator(EnvironmentInfo, L"VMware HGFS");

    if (supIsObjectExists(L"\\Device", L"xenbus"))
        KDUAddVmIndicator(EnvironmentInfo, L"Xen bus");

    if (supIsObjectExists(L"\\Device", L"xenvbd"))
        KDUAddVmIndicator(EnvironmentInfo, L"Xen block device");

    if (supIsObjectExists(L"\\Device", L"qemupciserial"))
        KDUAddVmIndicator(EnvironmentInfo, L"QEMU PCI serial");

    if (supIsObjectExists(L"\\Device", L"qemufwcfg"))
        KDUAddVmIndicator(EnvironmentInfo, L"QEMU fwcfg");

    if (supIsObjectExists(L"\\Device", L"vioscsi"))
        KDUAddVmIndicator(EnvironmentInfo, L"VirtIO SCSI");

    if (supIsObjectExists(L"\\Device", L"viostor"))
        KDUAddVmIndicator(EnvironmentInfo, L"VirtIO storage");

    if (supIsObjectExists(L"\\Device", L"vioser"))
        KDUAddVmIndicator(EnvironmentInfo, L"VirtIO serial");

    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"))
        KDUAddVmIndicator(EnvironmentInfo, L"VBoxGuest service");

    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat"))
        KDUAddVmIndicator(EnvironmentInfo, L"Hyper-V integration");

    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmicvss"))
        KDUAddVmIndicator(EnvironmentInfo, L"Hyper-V VSS");

    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmicshutdown"))
        KDUAddVmIndicator(EnvironmentInfo, L"Hyper-V shutdown");

    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmicexchange"))
        KDUAddVmIndicator(EnvironmentInfo, L"Hyper-V exchange");

    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\xenbus"))
        KDUAddVmIndicator(EnvironmentInfo, L"XenBus service");
}

/*
* KDUQuerySandboxArtifacts
*
* Purpose:
*
* Query known sandbox and analysis-related object and registry artifacts.
*
*/
VOID KDUQuerySandboxArtifacts(
    _Inout_ PKDU_ENVIRONMENT_INFO EnvironmentInfo
)
{
    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Cuckoo"))
        KDUAddSandboxIndicator(EnvironmentInfo, L"Cuckoo");

    if (KDURegistryKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie"))
        KDUAddSandboxIndicator(EnvironmentInfo, L"Sandboxie");

    if (supIsObjectExists(L"\\Device", L"SbieDrv"))
        KDUAddSandboxIndicator(EnvironmentInfo, L"Sandboxie driver");

    if (supIsObjectExists(L"\\Device", L"pstore"))
        KDUAddSandboxIndicator(EnvironmentInfo, L"Process storage-like device");
}

/*
* KDUQueryEmulationArtifacts
*
* Purpose:
*
* Query known emulation-related object artifacts.
*
*/
VOID KDUQueryEmulationArtifacts(
    _Inout_ PKDU_ENVIRONMENT_INFO EnvironmentInfo
)
{
    if (supIsObjectExists(L"\\Device", L"qemu_pipe"))
        KDUAddEmulationIndicator(EnvironmentInfo, L"QEMU pipe");

    if (supIsObjectExists(L"\\Device", L"goldfish_pipe"))
        KDUAddEmulationIndicator(EnvironmentInfo, L"Goldfish pipe");

    if (supIsObjectExists(L"\\Device", L"androidboot"))
        KDUAddEmulationIndicator(EnvironmentInfo, L"Android emulator artifact");
}

/*
* KDUQueryEnvironmentInformation
*
* Purpose:
*
* Collect environment diagnostic indicators and build a printable summary.
*
*/
VOID KDUQueryEnvironmentInformation(
    _Out_ PKDU_ENVIRONMENT_INFO EnvironmentInfo
)
{
    RtlSecureZeroMemory(EnvironmentInfo, sizeof(KDU_ENVIRONMENT_INFO));

    KDUQueryVmArtifacts(EnvironmentInfo);
    KDUQuerySandboxArtifacts(EnvironmentInfo);
    KDUQueryEmulationArtifacts(EnvironmentInfo);

    if (EnvironmentInfo->IndicatorCount == 0) {
        _strcpy(EnvironmentInfo->Description, L"No known environment indicators");
    }
}

/*
* KDUDetectEnvironment
*
* Purpose:
*
* Query environment diagnostic indicators and print the result.
*
*/
VOID KDUDetectEnvironment(
    VOID
)
{
    KDU_ENVIRONMENT_INFO environmentInfo;

    KDUQueryEnvironmentInformation(&environmentInfo);
    supPrintfEvent(kduEventInformation,
        "[+] Environment diagnostics: %ws\r\n",
        environmentInfo.Description);
}
