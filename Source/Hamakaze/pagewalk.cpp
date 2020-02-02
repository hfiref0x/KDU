/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2020
*
*  TITLE:       PAGEWALK.C
*
*  VERSION:     1.00
*
*  DATE:        24 Jan 2020
*
*  Function to translate virtual to physical addresses, x86-64.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define PHY_ADDRESS_MASK                0x000ffffffffff000ull
#define PHY_ADDRESS_MASK_2MB_PAGES      0x000fffffffe00000ull
#define VADDR_ADDRESS_MASK_2MB_PAGES    0x00000000001fffffull
#define VADDR_ADDRESS_MASK_4KB_PAGES    0x0000000000000fffull
#define ENTRY_PRESENT_BIT               1
#define ENTRY_PAGE_SIZE_BIT             0x0000000000000080ull

int EntryToPhyAddr(ULONG_PTR entry, ULONG_PTR* phyaddr)
{
    if (entry & ENTRY_PRESENT_BIT) {
        *phyaddr = entry & PHY_ADDRESS_MASK;
        return 1;
    }

    return 0;
}

BOOL PwVirtualToPhysical(
    _In_ KDU_CONTEXT *Context,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    KDU_PROVIDER* prov = Context->Provider;
    ULONG_PTR	reg_cr3, selector, table, entry;
    INT			r, shift;

    if (prov->Callbacks.ReadControlRegister(Context->DeviceHandle,
        3,
        &reg_cr3) == 0)
    {
        return 0;
    }

    table = reg_cr3 & PHY_ADDRESS_MASK;

    for (r = 0; r < 4; r++) {

        shift = 39 - (r * 9);
        selector = (VirtualAddress >> shift) & 0x1ff;

        if (prov->Callbacks.ReadPhysicalMemory(Context->DeviceHandle,
            table + selector * 8,
            &entry,
            sizeof(ULONG_PTR)) == 0)
        {
            return 0;
        }

        if (EntryToPhyAddr(entry, &table) == 0)
            return 0;

        if ((r == 2) && ((entry & ENTRY_PAGE_SIZE_BIT) != 0)) {
            table &= PHY_ADDRESS_MASK_2MB_PAGES;
            table += VirtualAddress & VADDR_ADDRESS_MASK_2MB_PAGES;
            *PhysicalAddress = table;
            return 1;
        }
    }

    table += VirtualAddress & VADDR_ADDRESS_MASK_4KB_PAGES;
    *PhysicalAddress = table;

    return 1;
}
