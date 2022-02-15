/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       ASIO.H
*
*  VERSION:     1.20
*
*  DATE:        10 Feb 2022
*
*  ASUS hack-o-rama prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FILE_DEVICE_ASUSIO          (DWORD)0x0000A040

#define ASUSIO3_REGISTER_FUNCID     (DWORD)0x924

#define IOCTL_ASUSIO_REGISTER_TRUSTED_CALLER     \
    CTL_CODE(FILE_DEVICE_ASUSIO, ASUSIO3_REGISTER_FUNCID, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0xA040A490

VOID RegisterTrustedCallerForAsIO();
