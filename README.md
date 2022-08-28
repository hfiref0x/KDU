# KDU
## Kernel Driver Utility

#### System Requirements

+ x64 Windows 7/8/8.1/10/11;
+ Administrative privilege is required.

# Purpose and Features

The purpose of this tool is to give a simple way to explore Windows kernel/components without doing a lot of additional work or setting up local debugger.
It features:
+ Protected Processes Hijacking via Process object modification;
+ Driver Signature Enforcement Overrider (similar to DSEFIx);
+ Driver loader for bypassing Driver Signature Enforcement (similar to TDL/Stryker);
+ Support of various vulnerable drivers use as functionality "providers".

#### Usage

###### KDU -list
###### KDU -prv ProviderID
###### KDU -ps ProcessID
###### KDU -dse value
###### KDU -map filename
* -list - list currently available providers;
* -prv  - optional, select vulnerability driver provider;
* -ps 	- modify process object of given ProcessID;
* -dse  - write user defined value to the system DSE state flags;
* -map  - map driver to the kernel and execute it entry point, this command have dependencies listed below;
  * -scv version - optional, select shellcode version, default 1;
  * -drvn name - driver object name (only valid for shellcode version 3);
  * -drvr name - optional, driver registry key name (only valid for shellcode version 3).

Example:
+ kdu -ps 1234
+ kdu -map c:\driverless\mysuperhack.sys
+ kdu -prv 1 -ps 1234
+ kdu -prv 1 -map c:\driverless\mysuperhack.sys
+ kdu -prv 6 -scv 3 -drvn DrvObj -map c:\install\e3600bm.sys
+ kdu -prv 6 -scv 3 -drvn edrv -drvr e3600bl -map c:\install\e3600bl.sys
+ kdu -dse 0
+ kdu -dse 6

Run on Windows 10 20H2*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu1.png" width="600" />

Compiled and run on Windows 8.1*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu2.png" width="600" />

Run on Windows 7 SP1 fully patched (precomplied version)*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu3.png" width="600" />

Run on Windows 10 19H2 (precompiled version, SecureBoot enabled)*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu4.png" width="600" />

###### All screenshots are from version 1.0X.

#### Limitations of -map command

Due to unusual way of loading that is not involving standard kernel loader, but uses overwriting already loaded modules with shellcode, there are some limitations:

+ Loaded drivers MUST BE specially designed to run as "driverless";

That mean you cannot use parameters specified at your DriverEntry as they won't be valid. That also mean you can not load *any* drivers but only specially designed or you need to alter shellcode responsible for driver mapping.

+ No SEH support for target drivers;

There is no SEH code in x64. Instead of this you have table of try/except/finally regions which must be in the executable image described by pointer in PE header. If there is an exception occured system handler will first look in which module that happened. Mapped drivers are not inside Windows controlled list of drivers (PsLoadedModulesList - PatchGuard protected), so nothing will be found and system will simple crash.

+ No driver unloading;

Mapped code can't unload itself, however you still can release all resources allocated by your mapped code.
DRIVER_OBJECT->DriverUnload should be set to NULL.

+ Only ntoskrnl import resolved, everything else is up to you;

If your project need another module dependency then you have to rewrite this loader part.

+ Several Windows primitives are banned by PatchGuard from usage from the dynamic code.

Because of unsual way of loading mapped driver won't be inside PsLoadedModulesList. That mean any callback registered by such code will have handler located in memory outside this list. PatchGuard has ability to check whatever the registered callbacks point to valid loaded modules or not and BSOD with "Kernel notification callout modification" if such dynamic code detected.

In general if you want to know what you *should not do* in kernel look at https://github.com/hfiref0x/KDU/tree/master/Source/Examples/BadRkDemo which contain a few examples of forbidden things.

#### Kernel traces note
This tool does not change (and this won't change in future) internal Windows structures of MmUnloadedDrivers and/or PiDDBCacheTable. That's because:
+ KDU is not designed to circumvent third-party security software or various dubious crapware (e.g. anti-cheats);
+ These data can be a target for PatchGuard protection in the next major Windows 10 update.

You use it at your own risk. Some lazy AV may flag this tool as hacktool/malware.

# Currently Supported Providers

| Provider Id | Product Vendor | Driver      | Software package                   | Code base         | Version                     |
|-------------|----------------|-------------|------------------------------------|-------------------|-----------------------------|
| 0           | Intel          | IQVM64/Nal  | Network Adapter Diagnostic Driver  | Original          | 1.03.0.7                    |
| 1           | MSI            | RTCore64    | MSI Afterburner                    | Semi-original     | 4.6.2 build 15658 and below |
| 2           | Gigabyte       | Gdrv        | Gigabyte TOOLS                     | MAPMEM NTDDK 3.51 | Undefined                   |
| 3           | ASUSTeK        | ATSZIO64    | ASUSTeK WinFlash utility           | Semi-original     | Undefined                   |
| 4           | Patriot        | MsIo64      | Patriot Viper RGB utility          | WINIO             | 1.0                         |
| 5           | ASRock         | GLCKIO2     | ASRock Polychrome RGB              | WINIO             | 1.0.4                       |
| 6           | G.SKILL        | EneIo64     | G.SKILL Trident Z Lighting Control | WINIO             | 1.00.08                     |
| 7           | EVGA           | WinRing0x64 | EVGA Precision X1                  | WINRING0          | 1.0.2.0                     |
| 8           | Thermaltake    | EneTechIo64 | Thermaltake TOUGHRAM software      | WINIO             | 1.0.3                       |
| 9           | Huawei         | PhyMemx64   | Huawei MateBook Manager software   | WINIO             | Undefined                   |
| 10          | Realtek        | RtkIo64     | Realtek Dash Client Utility        | PHYMEM            | Various                     |
| 11          | MSI            | EneTechIo64 | MSI Dragon Center                  | WINIO             | Various                     |
| 12          | LG             | LHA         | LG Device Manager                  | Semi-original     | 1.6.0.2                     |
| 13          | ASUSTeK        | AsIO2       | ASUS GPU Tweak                     | WINIO             | 2.1.7.1 and below           |
| 14          | PassMark       | DirectIo64  | PassMark Performance Test          | Original          | 10.1 and below              |
| 15          | GMER           | GmerDrv     | Gmer "Antirootkit"                 | Original          | 2.2 and below               |
| 16          | Dell           | DBUtil_2_3  | Dell BIOS Utility                  | Original          | 2.3 and below               |
| 17          | Benjamin Delpy | Mimidrv     | Mimikatz                           | Original          | 2.2 and below               |
| 18          | Wen Jia Liu    | KProcessHacker2  | Process Hacker                | Original          | 2.38 and below              |
| 19          | Microsoft      | ProcExp152  | Process Explorer                   | Original          | 1.5.2 and below             |
| 20          | Dell           | DBUtilDrv2  | Dell BIOS Utility                  | Original          | 2.7 and below               |
| 21          | DarkByte       | Dbk64       | Cheat Engine                       | Original          | 7.4 and below               |
| 22          | ASUSTeK        | AsIO3       | ASUS GPU TweakII                   | WINIO             | 2.3.0.3                     |
| 23          | Marvin         | Hw          | Marvin Hardware Access Driver      | Original          | 4.9 and below               |

More providers maybe added in the future.

# How it work

It uses known to be vulnerable (or wormhole by design) driver from legitimate software to access arbitrary kernel memory with read/write primitives.

Depending on command KDU will either work as TDL/DSEFix or modify kernel mode process objects (EPROCESS). 

When in -map mode KDU for most available providers will by default use 3rd party signed driver from SysInternals Process Explorer and hijack it by placing a small loader shellcode inside it IRP_MJ_DEVICE_CONTROL/IRP_MJ_CREATE/IRP_MJ_CLOSE handler. This is done by overwriting physical memory where Process Explorer dispatch handler located and triggering it by calling driver IRP_MJ_CREATE handler (CreateFile call). Next shellcode will map input driver as code buffer to kernel mode and run it with current IRQL be PASSIVE_LEVEL. After that hijacked Process Explorer driver will be unloaded together with vulnerable provider driver. This entire idea comes from malicious software of the middle of 200x known as rootkits.

# Shellcode versions

KDU uses shellcode to map input drivers and execute their DriverEntry. There are few shellcode variants embedded into KDU. Shellcode V1, V2 and V3 used together with 3rd party victim driver (Process Explorer, by default). They are implemented as fake driver dispatch entry and their differences are: V1 uses newly created system thread to execute code, V2 uses system work items, V3 manually builds driver object and runs DriverEntry as if this driver was loaded normally. Shellcode V4 is simplified version of previous variants intended to be run not like an driver dispatch entry. While theoretically all "providers" can support all variants this implementation is limited per provider. You can view it by typing -list command and looking for shellcode support mask. Currently all providers except N21 support V1, V2 and V3 variants.

# Build 

KDU comes with full source code.
In order to build from source you need Microsoft Visual Studio 2019 and later versions. For driver builds you need Microsoft Windows Driver Kit 10 and/or above.

# Utils and Notes

GenAsIo2Unlock is a special utility used to generate "unlocking" resource which is required for working with AsIO2 driver. Full source of this utility included in Source\Utils\GenAsIo2Unlock. Compiled version located in Sources\Hamakaze\Utils\GenAsIo2Unlock.exe. **Warning this utility is set on execution at post-build-event for both Debug/Release configurations.** If you don't want to run precompiled version replace it with newly compiled from sources. If you remove this post-build-event newly compiled KDU will NOT BE ABLE to use AsIO2 driver (provider #13).

# Disclaimer

Using this program might crash your computer with BSOD. Compiled binary and source code provided AS-IS in hope it will be useful BUT WITHOUT WARRANTY OF ANY KIND. Since KDU rely on completely bugged and vulnerable drivers security of computer where it executed maybe put at risk. Make sure you understand what you do.

# Third party code usage

* TinyAES, https://github.com/kokke/tiny-AES-c

# References

* DSEFix, https://github.com/hfiref0x/DSEFix
* Turla Driver Loader, https://github.com/hfiref0x/TDL
* Stryker, https://github.com/hfiref0x/Stryker
* Unwinding RTCore, https://swapcontext.blogspot.com/2020/01/unwinding-rtcore.html
* CVE-2019-16098, https://github.com/Barakat/CVE-2019-16098
* CVE-2015-2291, https://www.exploit-db.com/exploits/36392
* CVE-2018-19320, https://seclists.org/fulldisclosure/2018/Dec/39
* ATSZIO64 headers and libs, https://github.com/DOGSHITD/SciDetectorApp/tree/master/DetectSciApp
* ATSZIO64 ASUS Drivers Privilege Escalation, https://github.com/LimiQS/AsusDriversPrivEscala
* CVE-2019-18845, https://www.activecyber.us/activelabs/viper-rgb-driver-local-privilege-escalation-cve-2019-18845
* DEFCON27: Get off the kernel if you cant drive, https://eclypsium.com/wp-content/uploads/2019/08/EXTERNAL-Get-off-the-kernel-if-you-cant-drive-DEFCON27.pdf
* CVE-2019-8372: Local Privilege Elevation in LG Kernel Driver, http://www.jackson-t.ca/lg-driver-lpe.html
* CVE-2021-21551, https://attackerkb.com/topics/zAHZGAFaQX/cve-2021-21551
* KDU v1.1 release and bonus (AsIO3.sys unlock), https://swapcontext.blogspot.com/2021/04/kdu-v11-release-and-bonus-asio3sys.html
* GhostEmperor: From ProxyLogon to kernel mode, https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/
* KDU v1.2 release and the wonderful world of Microsoft incoherency, https://swapcontext.blogspot.com/2022/02/kdu-v12-release-and-wonderful-world-of.html

# Wormhole drivers code

They are used in multiple products from hardware vendors mostly in unmodified state. They all break OS security model and additionally bugged. Links are for educational purposes of how not to do your drivers. Note that following github account have nothing to do with these code, these code in unmodified state and provided only for educational purposes.

* WinIo 3.0 BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/WINIO
* WinRing0 BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/WINRING0
* PhyMem BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/PHYMEM
* MapMem BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/MAPMEM

# Authors

(c) 2020 - 2022 KDU Project
