# KDU
## Kernel Driver Utility

#### System Requirements

+ x64 Windows 7/8/8.1/10;
+ Administrative privilege is required.

# Purpose and Features

The purpose of this tool is to give a simple way to explore Windows kernel/components without doing a lot of additional work or setting up local debugger.
It features:
+ Protected Processes Hijacking via Process object modification;
+ Driver Signature Enforcement Overrider (similar to DSEFIx);
+ Driver loader for bypassing Driver Signature Enforcement (similar to TDL/Stryker);
+ Support of various vulnerable drivers use as functionality "providers".

#### Usage

###### KDU -ps ProcessID
###### KDU -map filename
###### KDU -dse value
###### KDU -prv ProviderID
###### KDU -list
* -prv  - optional, select vulnerability driver provider;
* -ps 	- modify process object of given ProcessID;
* -map  - load input file as code buffer to kernel mode and run it;
* -dse  - write user defined value to the system DSE state flags;
* -list - list currently available providers.

Example:
+ kdu -ps 1234
+ kdu -map c:\driverless\mysuperhack.sys
+ kdu -prv 1 -ps 1234
+ kdu -prv 1 -map c:\driverless\mysuperhack.sys
+ kdu -dse 0
+ kdu -dse 6

Run on Windows 10 20H2 (precomplied version)

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu1.png" width="600" />

Compiled and run on Windows 8.1

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu2.png" width="600" />

Run on Windows 7 SP1 fully patched (precomplied version)

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu3.png" width="600" />

Run on Windows 10 19H2 (precompiled version, SecureBoot enabled)

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu4.png" width="600" />


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

+ Intel Network Adapter Diagnostic Driver of version 1.03.0.7;
+ RTCore64 driver from MSI Afterburner of version 4.6.2 build 15658 and below;
+ Gdrv driver from various Gigabyte TOOLS of undefined version;
+ ATSZIO64 driver from ASUSTeK WinFlash utility of various versions;
+ MICSYS MsIo (WinIo) driver from Patriot Viper RGB utility of version 1.0;
+ GLCKIO2 (WinIo) driver from ASRock Polychrome RGB of version 1.0.4;
+ EneIo (WinIo) driver from G.SKILL Trident Z Lighting Control of version 1.00.08;
+ WinRing0x64 driver from EVGA Precision X1 of version 1.0.2.0;
+ EneTechIo (WinIo) driver from Thermaltake TOUGHRAM software of version 1.0.3.

More providers maybe added in the future.

# How it work

It uses known to be vulnerable driver from legitimate software to access arbitrary kernel memory with read/write primitives.

Depending on command KDU will either work as TDL/DSEFix or modify kernel mode process objects (EPROCESS). 

When in -map mode KDU will use 3rd party signed driver from SysInternals Process Explorer and hijack it by placing a small loader shellcode inside it IRP_MJ_DEVICE_CONTROL/IRP_MJ_CREATE/IRP_MJ_CLOSE handler. This is done by overwriting physical memory where Process Explorer dispatch handler located and triggering it by calling driver IRP_MJ_CREATE handler (CreateFile call). Next shellcode will map input driver as code buffer to kernel mode and run it with current IRQL be PASSIVE_LEVEL. After that hijacked Process Explorer driver will be unloaded together with vulnerable provider driver. This entire idea comes from malicious software of the middle of 200x known as rootkits.

# Build 

KDU comes with full source code.
In order to build from source you need Microsoft Visual Studio 2019 and later versions. For driver builds you need Microsoft Windows Driver Kit 10 and/or above.

# Support and Warranties

Using this program might render your computer into BSOD. Compiled binary and source code provided AS-IS in help it will be useful BUT WITHOUT WARRANTY OF ANY KIND.

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

# Wormhole drivers code

They are used in multiple products from hardware vendors mostly in unmodified state. They all break OS security model and additionally bugged. Links are for educational purposes of how not to do your drivers. Note that following github accounts have nothing to do with these code, they are just forked/uploaded it.

* WinIo 3.0 BSOD/CVE generator, https://github.com/starofrainnight/winio/blob/master/Source/Drv/WinIo.c
* WinRing0 BSOD/CVE generator, https://github.com/QCute/WinRing0/blob/master/dll/sys/OpenLibSys.c

# Authors

(c) 2020 KDU Project
