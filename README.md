# KDU
[![Build status](https://ci.appveyor.com/api/projects/status/pxpwehogor7x4mqa?svg=true)](https://ci.appveyor.com/project/hfiref0x/kdu)
[![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2Fkdu&countColor=%23263759&style=flat)](https://visitorbadge.io/status?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2Fkdu)

## Kernel Driver Utility

#### System Requirements

+ x64 Windows 7/8/8.1/10/11;
+ Administrative privilege is required.

# Purpose and Features

The purpose of this tool is to provide a simple way to explore the Windows kernel/components without requiring extensive setup or a local debugger.
It features:
+ Protected Process Hijacking via Process object modification;
+ Driver Signature Enforcement Overrider (similar to DSEFix);
+ Driver loader for bypassing Driver Signature Enforcement (similar to TDL/Stryker);
+ Support for various vulnerable drivers used as functionality "providers".

#### Usage

###### KDU -list
###### KDU -diag
###### KDU -prv ProviderID
###### KDU -ps ProcessID
###### KDU -pse Commandline
###### KDU -dmp ProcessID
###### KDU -dse value
###### KDU -map filename
* -list - list currently available providers;
* -diag - run system diagnostics for troubleshooting;
* -prv  - optional, select vulnerable driver provider;
* -ps   - modify process object of given ProcessID, downgrading any protections;
* -pse  - launch program as ProtectedProcessLight-AntiMalware (PPL);
* -psw  - launch program as ProtectedProcessLight-WinTcb (PPL);
* -dmp  - dump virtual memory of the given process;
* -dse  - write user-defined value to the system DSE state flags;
* -map  - map driver to the kernel and execute its entry point; this command has dependencies listed below;
  * -scv version - optional, select shellcode version, default 1;
  * -drvn name - driver object name (only valid for shellcode version 3);
  * -drvr name - optional, driver registry key name (only valid for shellcode version 3).

Example:
+ kdu -ps 1234
+ kdu -map c:\driverless\mysuperhack.sys
+ kdu -dmp 666
+ kdu -prv 1 -ps 1234
+ kdu -prv 1 -map c:\driverless\mysuperhack.sys
+ kdu -prv 6 -scv 3 -drvn DrvObj -map c:\install\e3600bm.sys
+ kdu -prv 6 -scv 3 -drvn edrv -drvr e3600bl -map c:\install\e3600bl.sys
+ kdu -dse 0
+ kdu -dse 6
+ kdu -pse "C:\Windows\System32\notepad.exe C:\TEMP\words.txt"
+ kdu -psw "C:\Windows\System32\cmd.exe"

Run on Windows 11 24H2*

<img width="1181" height="563" alt="image" src="https://github.com/user-attachments/assets/bbdf6d18-bc74-41e2-a7cf-297e439ec9df" />

Run on Windows 10 20H2*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu1.png" width="600" />

Compiled and run on Windows 8.1*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu2.png" width="600" />

Run on Windows 7 SP1 fully patched (precompiled version)*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu3.png" width="600" />

Run on Windows 10 19H2 (precompiled version, SecureBoot enabled)*

<img src="https://raw.githubusercontent.com/hfiref0x/kdu/master/Help/kdu4.png" width="600" />

###### All screenshots are from version 1.0X.

#### Limitations of -map command

Due to the unusual way of loading that does not involve the standard kernel loader, but uses overwriting already loaded modules with shellcode, there are some limitations:

+ Loaded drivers MUST BE specially designed to run as "driverless";

That means you cannot use parameters specified at your DriverEntry as they won't be valid. That also means you cannot load *any* drivers but only specially designed ones, or you need to alter shellcode routines.

+ No SEH support for target drivers;

There is no SEH code in x64. Instead, you have a table of try/except/finally regions described by a pointer in the PE header. If there is an exception, it may result in a BSOD.

+ No driver unloading;

Mapped code can't unload itself; however, you can release all resources allocated by your mapped code.
DRIVER_OBJECT->DriverUnload should be set to NULL.

+ Only ntoskrnl import resolved, everything else is up to you;

If your project needs another module dependency, you must rewrite this loader part.

+ Several Windows primitives are banned by PatchGuard from usage by dynamic code.

Because of the unusual way of loading, mapped driver won't be inside PsLoadedModulesList. That means any callback registered by such code will have its handler located in memory outside this list. PatchGuard may detect this and crash the system.

In general, if you want to know what you *should not do* in kernel, look at https://github.com/hfiref0x/KDU/tree/master/Source/Examples/BadRkDemo which contains a few examples of forbidden things.

#### Kernel traces note
This tool does not change (and will not change in future) internal Windows structures of MmUnloadedDrivers and/or PiDDBCacheTable. That's because:
+ KDU is not designed to circumvent third-party security software or various dubious software (e.g. anti-cheats);
+ These data can be a target for PatchGuard protection in the next major Windows 10 update.

You use it at your own risk. Some lazy AV may flag this tool as hacktool/malware.

# Supported Providers

Note: Provider with Id 0 is assumed as default if no -prv command is specified.

| Id     | Vendor         | Driver      | Software package                   | Version                      | MSFT blacklist*     |
|--------|----------------|-------------|------------------------------------|-----------------------------|----------------------|
| 0      | Intel          | IQVM64/Nal  | Network Adapter Diagnostic Driver  | 1.03.0.7                    | Cert                 |
| 1      | MSI            | RTCore64    | MSI Afterburner                    | 4.6.2 build 15658 and below | Page hash            |
| 2      | Gigabyte       | Gdrv        | Gigabyte TOOLS                     | Undefined                   | Name                 |
| 3      | ASUSTeK        | ATSZIO64    | ASUSTeK WinFlash utility           | Undefined                   | Name                 |
| 4      | Patriot        | MsIo64      | Patriot Viper RGB utility          | 1.0                         | Page hash            |
| 5      | ASRock         | GLCKIO2     | ASRock Polychrome RGB              | 1.0.4                       | Page hash            |
| 6      | G.SKILL        | EneIo64     | G.SKILL Trident Z Lighting Control | 1.00.08                     | Cert                 |
| 7      | EVGA           | WinRing0x64 | EVGA Precision X1                  | 1.0.2.0                     | Name                 |
| 8      | Thermaltake    | EneTechIo64 | Thermaltake TOUGHRAM software      | 1.0.3                       | Page hash            |
| 9      | Huawei         | PhyMemx64   | Huawei MateBook Manager software   | Undefined                   | Name, Page hash      |
| 10     | Realtek        | RtkIo64     | Realtek Dash Client Utility        | Various                     | Name                 |
| 11     | MSI            | EneTechIo64 | MSI Dragon Center                  | Various                     |                      |
| 12     | LG             | LHA         | LG Device Manager                  | 1.6.0.2                     | Name                 |
| 13     | ASUSTeK        | AsIO2       | ASUS GPU Tweak                     | 2.1.7.1 and below           |                      |
| 14     | PassMark       | DirectIo64  | PassMark Performance Test          | 10.1 and below              | Page hash            |
| 15     | GMER           | GmerDrv     | Gmer "Antirootkit"                 | 2.2 and below               | Name, Page hash, Cert|
| 16     | Dell           | DBUtil_2_3  | Dell BIOS Utility                  | 2.3 and below               | Page hash            |
| 17     | Benjamin Delpy | Mimidrv     | Mimikatz                           | 2.2 and below               | Cert                 |
| 18     | Wen Jia Liu    | KProcessHacker2  | Process Hacker                | 2.38 and below              | Name                 |
| 19     | Microsoft      | ProcExp152  | Process Explorer                   | 1.5.2 and below             | Name, Cert           |
| 20     | Dell           | DBUtilDrv2  | Dell BIOS Utility                  | 2.7 and below               |                      |
| 21     | DarkByte       | Dbk64       | Cheat Engine                       | 7.4 and below               | Cert, Name           |
| 22     | ASUSTeK        | AsIO3       | ASUS GPU TweakII                   | 2.3.0.3                     |                      |
| 23     | Marvin         | Hw          | Marvin Hardware Access Driver      | 4.9 and below               | Name                 |
| 24     | CODESYS        | SysDrv3S    | CODESYS SysDrv3S                   | 3.5.6 and below             | Cert                 |
| 25     | Zemana         | amsdk       | WatchDog/MalwareFox/Zemana AM      | 3.0.0 and below             |                      |
| 26     | HiRes Ent.     | inpoutx64   | Various                            | 1.2.0 and below             |                      |
| 27     | PassMark       | DirectIo64  | PassMark OSForensics               | Any                         |                      |
| 28     | ASRock         | AsrDrv106   | Phantom Gaming Tuning              | 1.0.6 and below             |                      |
| 29     | Arthur Liberman| ALSysIO64   | Core Temp                          | 2.0.11 and below            |                      |
| 30     | AMD            | AMDRyzenMasterDriver  | Multiple software packages | 2.0.0.0 and below           |                      |
| 31     | Hilscher       | physmem     | Physical Memory Viewer for Windows | 1.0.0.0                     |  Cert, Name          |
| 32     | Lenovo         | LDD         | Lenovo Diagnostics Driver for Windows 10 and later | 1.0.4.0 and below               |  Cert, Name          |
| 33     | Dell           | pcdsrvc_x64 | Dell PC Doctor                     | 6.2.2.0                     |                      |
| 34     | MSI            | winio       | MSI Foundation Service             | Undefined                   |                      |
| 35     | HP             | EtdSupport  | ETDi Support Driver                | 18.0 and below              |  Cert                |
| 36     | Pavel Yosifovich | KExplore  | Kernel Explorer                | Undefined              |                      |
| 37     | Pavel Yosifovich | KObjExp  | Kernel Object Explorer          | Undefined              |                      |
| 38     | Pavel Yosifovich | KRegExp  | Kernel Registry Explorer        | Undefined              |                      |
| 39     | Inspect Element LTD | EchoDrv  | Echo AntiCheat (spyware)  | Undefined              |  Hash                   |
| 40     | NVidia         | nvoclock  | NVidia System Utility Driver     | 7.0.0.32              |                      |
| 41     | Binalyze       | IREC  | Binalyze DFIR    | 3.11.0  |                      |
| 42     | DavidXXW       | PhyDMACC  | SLIC ToolKit     | 1.2.0  |  Page hash                    |
| 43     | Razer          | rzpnk  | Razer Synapse     |  2.20.15.1104   |                      |
| 44     | AMD            | PdFwKrnl  | AMD Radeon™ Software (Adrenalin Edition and PRO Edition) | 23.9.1 and below             |                      |
| 45     | AMD            | AODDriver  | AMD OverDrive Driver     | 2.1.5 and below              |                      |
| 46     | Wincor Nixdorf | wnBios64  | WinBios Driver     | 1.2.0 and below              |                      |
| 47     | EVGA  | EleetX1| EVGA ELEET X1     | 1.0.16.0 and below              |                      |
| 48     | ASRock         | AxtuDrv  | AsRock Extreme Tuner     | Undefined              |                      |
| 49     | ASRock         | AppShopDrv103  | ASRock APP Shop    | 1.0.58 and below       |                      |
| 50     | ASRock         | AsrDrv107n  | ASRock Motherboard Utility    | 3.0.498 and below       |                      |
| 51     | ASRock         | AsrDrv107  | ASRock Motherboard Utility    | 3.0.498 and below       |                      |
| 52     | Intel          | PmxDrv  | Intel(R) Management Engine Tools Driver    | 1.0.0.1003 and below       |                      |
| 53     | Jun Liu        | HwRwDrv  | Hardware read & write driver    | 1.0.0.6 and below       |                      |
| 54     | NetEase        | NeacSafe64  | NeacSafe64 mini-filter driver    | 1.0.0.1 and below       |                      |

MSFT blacklist types:
* Cert - by certificate used to sign the driver which makes it possible to ban huge number of files at one time.
* Name - by original filename entry stored inside VERSION_INFO file resources, this type of bans are only possible with cross-checking of file version otherwise it will cause false-positives in case if the driver has "fixed/unaffected" version. 
* Hash/Page hash - by authenticode hash/page hash, allows MSFT to ban exact driver file.

# KDU provider details, alternatives are available
| Id     | Codebase       | Assigned CVE's | Hashes | 
|--------|----------------|-------------  |--------|
|0|Original|CVE-2015-2291|**File(SHA1):** D04E5DB5B6C848A29732BFD52029001F23C3DA75<br>**Authenticode(SHA1):** 2CBFE4AD0E1231FF3E19C19CA9311D952CE170B7<br>**Page(SHA1):** 55B90A6E4323FC1D7B71B23F81FC758F45740E02<br>**Page(SHA256):** FB14DC1657C0EDD18FA747005EB7125DBBD83595095D67906BB0B4D57222D4C1 |
|1|Semi-original|CVE-2019-16098|**File(SHA1):** F6F11AD2CD2B0CF95ED42324876BEE1D83E01775<br>**Authenticode(SHA1):** 4A68C2D7A4C471E062A32C83A36EEDB45A619683<br>**Page(SHA1):** 84152FA241C3808F8C7752964589C957E440403F<br>**Page(SHA256):** A807532037A3549AE3E046F183D782BCB78B6193163EA448098140563CF857CB |
|2|MAPMEM|CVE-2018-19320|**File(SHA1):** FE10018AF723986DB50701C8532DF5ED98B17C39<br>**Authenticode(SHA1):** 0F5034FCF5B34BE22A72D2ECC29E348E93B6F00F<br>**Page(SHA1):** DC02DA48DF2F9B558453847399A8DE47C5AD56CC<br>**Page(SHA256):** 95406C37FDE1B08524FAB782200C8BECAEC98A40B020F41C5BA13032FE9522FA |
|3|Semi-original|CVE-2023-41444|**File(SHA1):** 490109FA6739F114651F4199196C5121D1C6BDF2<br>**Authenticode(SHA1):** B66BF2B1B07F8F2BAB1418131AE66B0A55265F73<br>**Page(SHA1):** 04384DE86A18CE8D17DB3BB33CB9DD06868D4C32<br>**Page(SHA256):** 1871BE94AD775FD220F9A04C0F6B84C2C34CF898A4096E94359D9E5E269835DC |
|4|WINIO|CVE-2019-18845|**File(SHA1):** E6305DDDD06490D7F87E3B06D09E9D4C1C643AF0<br>**Authenticode(SHA1):** 7E732ACB7CFAD9BA043A9350CDEFF25D742BECB8<br>**Page(SHA1):** CDE1A50E1DF7870F8E4AFD8631E45A847C714C0A<br>**Page(SHA256):** 05736AB8B48DF84D81CB2CC0FBDC9D3DA34C22DB67A3E71C6F4B6B3923740DD5 |
|5|WINIO|CVE-2018-18535, CVE-2018-18536, CVE-2018-18537|**File(SHA1):** CC51BE79AE56BC97211F6B73CC905C3492DA8F9D<br>**Authenticode(SHA1):** D99B80B3269D735CAC43AF5E43483E64CA7961C3<br>**Page(SHA1):** 51E0740AAEE5AE76B0095C92908C97B817DB8BEA<br>**Page(SHA256):** E7F011E9857C7DB5AACBD424612CD7E3D12C363FDC8F072DDFAF9E2E5C85F5F3 |
|6|WINIO|CVE-2020-12446|**File(SHA1):** B4D014B5EDD6E19CE0E8395A64FAEDF49688ECB5<br>**Authenticode(SHA1):** 651B953CB03928E41424AD59F21D4978D6F4952E<br>**Page(SHA1):** 3727D824713E733558A20DE9876AABF1059D3158<br>**Page(SHA256):** 88C83F618C8F4069DED87C409A8446C5A30E22A303E64AAFF1C5BE6302ADEDB4 |
|7|WINRING0|CVE-2020–14979|**File(SHA1):** 012DB3A80FAF1F7F727B538CBE5D94064E7159DE<br>**Authenticode(SHA1):** 7AED8186977FCF7EE219DA493BAECDB95EC8040D<br>**Page(SHA1):** 9AB2257AE97DB4B0617640C90DD45AB7F144FBB9<br>**Page(SHA256):** D48209A183CDFEAADBD8A644730BD76BBF89C759844890739F934F242C226305 |
|8|WINIO||**File(SHA1):** 3CD037FBBA8AAE82C1B111C9F8755349C98BCB3C<br>**Authenticode(SHA1):** CE280412DD778CAFBE6DBB05B8CAB42E98D3AE56<br>**Page(SHA1):** 6CAFC03207391464AB7E69F47228CB82539BEBDE<br>**Page(SHA256):** 3F88ABF8908108207DA38DBC9E8690B3D63DB7F856B16E9F0D3A3B389FC72561 |
|9|WINIO||**File(SHA1):** 6ECFC7CCC4843812BFCCFB7E91594C018F0A0FF9<br>**Authenticode(SHA1):** 3C9F40AC72B0202CB40627FDEB7298079187193A<br>**Page(SHA1):** 6E7D8ABF7F81A2433F27B052B3952EFC4B9CC0B1<br>**Page(SHA256):** B7113B9A68E17428E2107B19BA099571AAFFC854B8FB9CBCEB79EF9E3FD1CC62 |
|10|PHYMEM||**File(SHA1):** B21CBA198D721737AABD882ADA6C91295A5975ED<br>**Authenticode(SHA1):** 7593D46A73EC00E00AEF3E9D0031C2B21B74ECFB<br>**Page(SHA1):** D4B640263D2A6C9906D4032F252CC81D838E2116<br>**Page(SHA256):** 77EC9BF2DBB106EF51D4DE49E70801D48001BF06146A370D0669E385B87C0826 |
|11|WINIO||**File(SHA1):** A87D6EAC2D70A3FBC04E59412326B28001C179DE<br>**Authenticode(SHA1):** 6B60825564B2DCCFF3A4F904B71541BFE94136C9<br>**Page(SHA1):** 8911B97A3140C2523287E1039B08DE8EF4D7F9AB<br>**Page(SHA256):** 85859FFD16396D0FE9897BAFBDCE94FF66474DCDEF7754FCDF2C9C7A8CE451DB |
|12|Semi-original|CVE-2019-8372|**File(SHA1):** 3FD55927D5997D33F5449E9A355EB5C0452E0DE3<br>**Authenticode(SHA1):** 87C155D933CA3513E29D235562D96B88D3913CDE<br>**Page(SHA1):** B565361205846323911766F55E380D93C6A3AB02<br>**Page(SHA256):** 4818AA3F52BCF3554131B56A3A0F0C2D8BBB5F6D18837F68D811EAD7917A2DE3 |
|13|WINIO|CVE-2021-28685|**File(SHA1):** AA2EA973BB248B18973E57339307CFB8D309F687<br>**Authenticode(SHA1):** 92FEE95E32A727D135F1F46CA98C201FFFBF6950<br>**Page(SHA1):** C5F1D135831851E9D7A06F9636E2A50B1D5C3A04<br>**Page(SHA256):** B4DCE5B50224C2461B49F1850C73EF84E65A64D89E2F32DD931A2F3C62D9D6BF |
|14|Original|CVE-2020-15481|**File(SHA1):** 2DB49BDF8029FDCDA0A2F722219AE744EAE918B0<br>**Authenticode(SHA1):** F1BDD3236F43338A119D74ECA730F0D464DED973<br>**Page(SHA1):** A14331F63EC907BF3E472F1E0CB8F19DE06EF4E4<br>**Page(SHA256):** 7F0A28CCF0AB76964D40E063F9D4B88193B77E4BADF66E8C8F87C97127885987 |
|15|Original||**File(SHA1):** 83506DE48BD0C50EA00C9E889FE980F56E6C6E1B<br>**Authenticode(SHA1):** 0BCA6C35159282FD64615ABC4D398399B061847B<br>**Page(SHA1):** 0882AB6651CD17F3D7D696E9C48EB4934159AE4C<br>**Page(SHA256):** 0F5DE6DE77D764E2370FA69D3CD8B2C0EC4DFC6F6736C7EDE97F3F75567ED47A |
|16|Original|CVE-2021-21551|**File(SHA1):** C948AE14761095E4D76B55D9DE86412258BE7AFD<br>**Authenticode(SHA1):** E3C1DD569AA4758552566B0213EE4D1FE6382C4B<br>**Page(SHA1):** E09B5E80805B8FE853EA27D8773E31BFF262E3F7<br>**Page(SHA256):** 7E2AD3D6D76F4FCD4583B865FFC12DE6C44FC16CBCBB81D480CB067F2A860422 |
|17|Original||**File(SHA1):** A8DDB7565B61BC021CD2543A137E00627F999DCC<br>**Authenticode(SHA1):** 0E732D18A7D880F0505433A0DA0E100DA0E1C3A3<br>**Page(SHA1):** A1E322631A67DE6441A08C991352281CF7C83FD8<br>**Page(SHA256):** 787AC1DB370421BD26915EAE797F67AD4C6E53775970DC18226ED5225B0B8A3B |
|18|Original||**File(SHA1):** D8498707F295082F6A95FD9D32C9782951F5A082<br>**Authenticode(SHA1):** 61B55BB7C111F93BD3EA9AC71591E1A6B89FEEE1<br>**Page(SHA1):** 15FA18C40598FFD05C7F99DB81EEEA1336FC4213<br>**Page(SHA256):** B6033C16527F2ADBC9E8E5C7678F649E55009319B8612765686ACB1A1C82FDDA |
|19|Original||**File(SHA1):** 3296844D22C87DD5EBA3AA378A8242B41D59DB7A<br>**Authenticode(SHA1):** EDC10781EB6D1E3BDF9D15CFEBDDBE1A1FB804D9<br>**Page(SHA1):** AF2B5A3F4DBCE417295FB2CECD8DF91C5A679D44<br>**Page(SHA256):** 2C22F27671EE4C530C16821CEE2A9F48C19F99B873E36D94C4AAA0194D52B8CB |
|20|Original|CVE-2021-36276|**File(SHA1):** 90A76945FD2FA45FAB2B7BCFDAF6563595F94891<br>**Authenticode(SHA1):** 6BC2AB0F03D7A58685A165B519E8FEE6937526A6<br>**Page(SHA1):** 66B2E2438725B576428CBEAE3E481148B4B5FD8C<br>**Page(SHA256):** C60578FAD95216EF74BCD9661A562C0DDC2C8697D64B546F59A7EF85F71D3814 |
|21|Original||**File(SHA1):** A54AE1793E9D77E61416E0D9FB81269A4BC8F8A2<br>**Authenticode(SHA1):** 1BE4BA36BA9CE5B10D90137C08CC21F823379841<br>**Page(SHA1):** 2EF1502DDE6A1CB120AC379F8C7155EB96E4BA02<br>**Page(SHA256):** F7443FBAC813EAF0AA94C73265C3BE7E723A5BF64BEF1D80E8FF57D7573FC53C |
|22|WINIO||**File(SHA1):** CFA85A19D9A2F7F687B0DECDC4A5480B6E30CB8C<br>**Authenticode(SHA1):** 4BFC51E23494F7EAF27560F92CD6FBCED2FFA4F6<br>**Page(SHA1):** 09C0DC0C0440F9362BD29960236CD716B3E21453<br>**Page(SHA256):** 209D5B95C83B4923C825DF9F3DE5F5EFCEFA0C2F82FD77D9BB38FE41E81B3D02 |
|23|Original||**File(SHA1):** 4E56E0B1D12664C05615C69697A2F5C5D893058A<br>**Authenticode(SHA1):** 6E87CD3B027A07A810164D618E3F2FCE61EB6EC4<br>**Page(SHA1):** 45F1309E10159325BA1DFAE4CAE214BD07B355F1<br>**Page(SHA256):** EF15F8CE1C905139AC64C15C2E91E808054421D2B95E2F531EFC6FC5D9D2A471 |
|24|MAPMEM|CVE-2022-22516|**File(SHA1):** E1069365CB580E3525090F2FA28EFD4127223588<br>**Authenticode(SHA1):** 432B5809D84935D15574DE8D64B22E06682FF715<br>**Page(SHA1):** 13EA5846AFE3B9141C712FAFBA9F1B95B26087E5<br>**Page(SHA256):** 6E0C60A5AA46C6CCE7EB4EFA8D36D6D343C0D26694D8A9E194F254988603FC26 |
|25|Original|CVE-2021-31728, CVE-2022-42045|**File(SHA1):** 290D6376658CF0F8182DE0FAE40B503098FA09FD<br>**Authenticode(SHA1):** 084553447BDBC056BBE49BAD8ACFAF25EB83462A<br>**Page(SHA1):** 760DE62D6AF5F8CD46E2B2074CDF7B0805B58484<br>**Page(SHA256):** 8BFEE3E7582C0432CD02A8D75D00B8CBA9CD9A2525E3E61E0D0C8AAAC2FCFEEB |
|26| WINIO||**File(SHA1):** 6AFC6B04CF73DD461E4A4956365F25C1F1162387<br>**Authenticode(SHA1):** 8E1F51761F21148F68AC925CC5F9E9C78F3D5EC4<br>**Page(SHA1):** 83714FAAF1643DBA7ABF28A4AC287A43FDEBDE81<br>**Page(SHA256):** 1D665C5DDA5E49B5C7F5231327D4A41D83201107CF428800EF24FDBB1CC505F7 |
|27|Original||**File(SHA1):** 01B95AE502AA09AABC69A0482FCC8198F7765950<br>**Authenticode(SHA1):** 4AEA4FBB9A732D57643F61F1BF3B82CEBB18AB72<br>**Page(SHA1):** 981F8CC044C6E21E2A4746B47EBEBAEEF49B9114<br>**Page(SHA256):** 50F9C8874653A6C25179C33EAEB19A6EC4C21BCB1EB14429DD0746C338766911 |
|28|RWEverything|CVE-2020-15368|**File(SHA1):** B0032B8D8E6F4BD19A31619CE38D8E010F29A816<br>**Authenticode(SHA1):** F621633290173DAAC18BB14CA3F52BC027CD2721<br>**Page(SHA1):** 32F6424734185AF58281EA4C66805A8238E61427<br>**Page(SHA256):** 281D8225E91591F799F93BF448F78F3F50B9AA7D6F1ADD3E2AC58D6BA0DE1473 |
|29|Original||**File(SHA1):** 256D285347ACD715ED8920E41E5EC928AE9201A8<br>**Authenticode(SHA1):** 530DD2863A09DC57801D62551C48EB9E48476FE8<br>**Page(SHA1):** 845EE7617D94A6A13016419B94CFC2D15D9BB71A<br>**Page(SHA256):** C13FDB8225E21B899A340506DB055B949C941A33D8C2D73C81E46BF5C4DDFF47 |
|30|Original|CVE-2020-12928|**File(SHA1):** CEC887F20AB468CAA1C99FCBE7FBDFAB25FADF39<br>**Authenticode(SHA1):** E37C6AA2630FA3CCB3EE7D219A7332CCE95FA11F<br>**Page(SHA1):** 70A164E25FD351CEDFEDEB3D89871A1D487D0379<br>**Page(SHA256):** E47556832FA7CF286FFD7F7A0646FA8015AF651D5C968F20353F6B7CFF18A1DC |
|31|Original||**File(SHA1):** 17614FDEE3B89272E99758983B99111CBB1B312C<br>**Authenticode(SHA1):** FD0CB3EA1DEB4FDB22536A7C15669EB53315E5C8<br>**Page(SHA1):** 0D03AC1B15AE10BB40A7660F25F3A68E1330024E<br>**Page(SHA256):** CB27AD883FCF265B8E2C8D393C0B403914C1911A935A5D248B4C37B4D99CD7BE |
|32|Original|CVE-2022-3699|**File(SHA1):** B89A8EEF5AEAE806AF5BA212A8068845CAFDAB6F<br>**Authenticode(SHA1):** 6D9543725ACA0C9C8F403425952692CCC1D2D7F2<br>**Page(SHA1):** B40A38E4D3BFB567F313A190A30F3AA9189EC1A0<br>**Page(SHA256):** 4273E0BE1A21142DE6BA672EFDAC0AC1FADC7AF0D0DAACA4E4D330D02C8F4CC8 |
|33|Original|CVE-2019-12280|**File(SHA1):** D0A228ED8AF190DEC0C1A812E212F5E68EE3B43E<br>**Authenticode(SHA1):** 85D493F5636B46F6C4F8B1028F8E8659F31DC562<br>**Page(SHA1):** A48431302A6C5053D178FCEC3390FBC1CACCB893<br>**Page(SHA256):** 08AFD2489CB6A093E3F588B1D13D20468AE3E27A2F0AEC9E43C41D20FFB2F6EE |
|34|WINIO||**File(SHA1):** 9745D77E3C27437BBCCF39E074F7D57A99FE83B1<br>**Authenticode(SHA1):** 1419392FC1EC6EF497442FEE3F7553A68B78A03D<br>**Page(SHA1):** 863F4AFE82D791D655B2DCE5C893B37422364230<br>**Page(SHA256):** F3165AFC15FA99745D7151501E1E2A738AD04DA5A4E76E5CE135B8E247AE0D1D |
|35|Original||**File(SHA1):** A57EEFA0C653B49BD60B6F46D7C441A78063B682<br>**Authenticode(SHA1):** 96FAA975FEB28588372A98A1E77D98AF7FC90E41<br>**Page(SHA1):** 197859EEFBCF17BE48A3C49818B35F263701755F<br>**Page(SHA256):** 5C8C0FC9B3B7C6C7E6BDD83A8D3ED44E075D9C3B42463E1CC5EE28049517488E |
|36|Original||**File(SHA1):** 090A4FC285D4F47B1E6A1011353A329C1F4C8E09<br>**Authenticode(SHA1):** C77403CFFCD15438EA3DDDF0763AB0A70A9100CB<br>**Page(SHA1):** DCCA45C770E93BCF9FC7A9ADFC4653AE744C798C<br>**Page(SHA256):** DE88E584BC88C463F479CAA5A6F4C166B8180E2AEAC62A54879875D374704631 |
|37|Original||**File(SHA1):** 3303BA52A334DA58A4992C4F9FBA7272E294B7AF<br>**Authenticode(SHA1):** 43239D3355CED44FB56C4127BF96EF2ED1BE2780<br>**Page(SHA1):** 6ECDAAECEB20B8D037FD4508A4B1DCE1ADCD2203<br>**Page(SHA256):** 6DA94C767419BAFB993B39913CD99146EB80FC13B5A6D5DE96829E084D4CFC83 |
|38|Original||**File(SHA1):** F3383FE0FF00BDEA1AA9E68BCAAD8B83885E306D<br>**Authenticode(SHA1):** D889E03CE654903A5113F49F49A1C23F3317E7D0<br>**Page(SHA1):** 0773B431922B3208DB0C4A4E02F9CE7297AAE774<br>**Page(SHA256):** AE38ADF8B97188675D8F6396F2DC0801C60CBFD546CAEDE915B73E9332DF6C8C |
|39|Original|CVE-2023-38817|**File(SHA1):** A93197C8C1897A95C4FB0367D7451019AE9F3054<br>**Authenticode(SHA1):** 678620A9CC9E7FFE179BC5CDA0A2DD0597E231EE<br>**Page(SHA1):** 832832028D40A3CFD08D364554FCE0B4F37317FF<br>**Page(SHA256):** 49ED19D5E1E122936035A48EA99FFD68CA4915578107888D5C2B0BB9E30E67C0 |
|40|Original||**File(SHA1):** BDA102AFBC60F3F3C5BCBD5390FFBBBB89170B9C<br>**Authenticode(SHA1):** 0FB1D0EF14AB73FCB4C62043859064CC5F9F88C2<br>**Page(SHA1):** B754B2C62796004560E2ADF5178099B98F111C25<br>**Page(SHA256):** 83D2A9535CDB68A8D6EAE5582DB7A70E01A520151448CEB572D96566A2AECB82 |
|41|Original|CVE-2023-41444|**File(SHA1):** D2FB46277C36498E87D0F47415B7980440D40E3D<br>**Authenticode(SHA1):** 719F659300BA463EFEEAB5916F0378C64FC1AD4A<br>**Page(SHA1):** F7FEA2BE8FF65DBB89BAF39EF8E0D80DAB81CB8E<br>**Page(SHA256):** 5FEB045C2452FD280BA1CAD5FC9B4F0DE7FC95EABDCE19FA2CD1F632891F3B1A |
|42|WINRING0||**File(SHA1):** 177B541412A45646177B2352FA2D9E89E0EEFE5A<br>**Authenticode(SHA1):** 200ABD07303234FC114360D9DABC38DA1F1F2A22<br>**Page(SHA1):** 84B91B1AED8F83DE14323089148BE2577FDC826C<br>**Page(SHA256):** B8502DB6B8947E5D852102166D0BEF8252EA3431D582E968EF44C35E56609C91 |
|43|Original|CVE-2017-9769|**File(SHA1):** F999709E5B00A68A0F4FA912619FE6548AD0C42D<br>**Authenticode(SHA1):** 1AC31466261A6DA69FBEB8E99D0B7B772071AC7F<br>**Page(SHA1):** 4EC299E9A539F6BC194BD3D436B24A565BD32EF4<br>**Page(SHA256):** C8CE0EE4FF58779A292B5626D9953888A1A04799E18924CB7A075095C25042E8 |
|44|Original|CVE-2023-20598|**File(SHA1):** A24840E32071E0F64E1DFF8CA540604896811587<br>**Authenticode(SHA1):** 661A1A28950CEC3F2C3D0E72AB2A05D4A173CF9A<br>**Page(SHA1):** 869BED04EB66492AC532E36C3C6171AB34DA1A00<br>**Page(SHA256):** E5DC6305227951B05997CD147C59795991F7EDE52461D069EFE1D568DD25C580 |
|45|Original|CVE-2020-12928|**File(SHA1):** 17D28A90EF4D3DBB083371F99943FF938F3B39F6<br>**Authenticode(SHA1):** 9A329362E340FC8363E67FB5F23A8391CB83BF00<br>**Page(SHA1):** 0BC84A62ABD3CA20305FB834592928C2317439D6<br>**Page(SHA256):** 76C7A12CDE2FDC80A6AF0A58E7698FC1F5EC8746EFB461FB07155B7065480715 |
|46|WINIO||**File(SHA1):** AEC96520E85330594D3165C86CB92EAC34C1E095<br>**Authenticode(SHA1):** A7179D7CF5EE58276C3C42A16195A0B733F31B53<br>**Page(SHA1):** AF7FED1C68BB2D459F7778EC6D20459618CF3D26<br>**Page(SHA256):** 490B1FFC374F9CDEC57BBCE9DAD93251516DE93C7A7F3475D8AC55A6DCBB958E|
|47|Original||**File(SHA1):** DA66B66DCA5EA8689DB903EC23E98F2C881DE6F8<br>**Authenticode(SHA1):** A8D16FED8999033126D60C656A3BA359DFAA559F<br>**Page(SHA1):** 082FBFF03465F78276D5A2066398A9D3C73DB9AB<br>**Page(SHA256):** F677A9447400EAEE6E12A88F59AAADCF6DDF8F16EC8F7612BF50AB378A9B9012|
|48|RWEverything||**File(SHA1):** 3F6A997B04D2299BA0E9F505803E8D60D0755F44<br>**Authenticode(SHA1):** E7FAC017B371A43276E03BF5F71D437E8D377930<br>**Page(SHA1):** EE9A5A98C257F2D50030B7F3AB6D7DA805FCC150<br>**Page(SHA256):** D159D969E05C83F27F446BCC5F171A0043CC3DF0B518962CEE7ACBE30BCC02F8|
|49|RWEverything||**File(SHA1):** 6074C2360F5DC74738873A525DFBD67EB6625986<br>**Authenticode(SHA1):** 03C523F31603C460076AD549F985DD9533734E95<br>**Page(SHA1):** 85B6FC43E943C9EB9B3DE1FF82A56870620CC1CF<br>**Page(SHA256):** A3AF7747FAC60B814FA6717B174F1199B9D163081B55AE40CEDD9983B6D033F5|
|50|RWEverything||**File(SHA1):** 11D7E0D29AB17292FD43BDD5CCB7DA0403E50E52<br>**Authenticode(SHA1):** CA06D9FD91F7B681204B35975D5C069D0DABE276<br>**Page(SHA1):** B7693E1170B01F24A824892607C2258CA653805A<br>**Page(SHA256):** B8776F6889CF3D8252F0912DD9745F8EFF4513292DF2B2B1D484CDBC68FBAE4C|
|51|RWEverything||**File(SHA1):** B1FAD5DA173C6A603FFFE20E0CB5F0BDCA823BD5<br>**Authenticode(SHA1):** 268073AD0B17E2161C1A2A6C5B1BDEBB7B3011B4<br>**Page(SHA1):** 0B48F35DAF8B8BC9BA4E413EF222415EAB791AE0<br>**Page(SHA256):** B073907634013A8EB65E4C8AA42535BAD08101E58B7B1489AEE395B7BE9C69E2|
|52|Original||**File(SHA1):** 9E5FCAEA33C9A181C56F7D0E4D9C42F8EDEAD252<br>**Authenticode(SHA1):** 7919108CB1278503EC4A78DD25694C6770EAA989<br>**Page(SHA1):** E1CE5A5E2CEB0AAD9CB588A900BF471462FAC42B<br>**Page(SHA256):** 6991344C8771FC717F878F9A6B0C258BC81FB3BF1F7F3CBED3EF8F86541B253F|
|53|WINRING0||**File(SHA1):** DB8BCB8693DDF715552F85B8E2628F060070F920<br>**Authenticode(SHA1):** 8C40A82DF3D606A87DF243C787283C26CE9B0458<br>**Page(SHA1):** F7362528C0118F895D4D51588102C51A09B1691C<br>**Page(SHA256):** 2A8B9C786DEA17F00E105BFEF82B723E2578150E814DD9A94ED007275C96AC25|
|54|Original|CVE-2025-45737|**File(SHA1):** 7E6DD5F1363C3070C59378EC8B23B6EC7B5671B4<br>**Authenticode(SHA1):** 5C41FA80052C332F7D6323C91E84E1204BA1C1C7<br>**Page(SHA1):** 5670C9130CC8997FBA6BD1C615F0DA97DC1FD43C<br>**Page(SHA256):** 34B6E417ABA41F5C7D7EE260AF1F56D9A74519F64B8E15BB510A295D2F9ED464|

###### *At commit time, data may be inaccurate.

More providers may be added in the future.

# How it works

It uses known vulnerable (or wormhole by design) drivers from legitimate software to access arbitrary kernel memory with read/write primitives.

Depending on the command, KDU will either work as TDL/DSEFix or modify kernel mode process objects (EPROCESS). 

When in -map mode, KDU for most available providers will by default use a 3rd party signed driver from SysInternals Process Explorer and hijack it by placing a small loader shellcode inside its IRP_MJ_DEVICE_CONTROL routine.

# Shellcode versions

KDU uses shellcode to map input drivers and execute their DriverEntry. There are a few shellcode variants embedded into KDU. Shellcode V1, V2, and V3 are used together with 3rd party victim driver (Process Explorer, etc.).

# Build and Notes

KDU comes with full source code.
To build from source, you need Microsoft Visual Studio 2019 or later. For driver builds, you need Microsoft Windows Driver Kit 10 and/or above.

Complete working binaries include: kdu.exe (main executable) and drv64.dll (drivers database). They must reside in the same directory with R/W access enabled for kdu.exe. All binaries MUST be unblocked from the system zone.

# Utils and Notes

GenAsIo2Unlock is a special utility used to generate "unlocking" resources required for working with the AsIO2 driver. Full source of this utility is included in Source\Utils\GenAsIo2Unlock. Compiled binary is not provided.

# Reporting bugs and incompatibilities

If you experience a bug or incompatibility while using KDU with 3rd party software or OS, feel free to fill an issue. However, if this incompatibility is caused by your own actions, such reports will be ignored.

Anticheat, antimalware incompatibilities will be ignored, that's your own responsibility.

# Disclaimer

Using this program might crash your computer with a BSOD. Compiled binary and source code are provided AS-IS in the hope they will be useful BUT WITHOUT WARRANTY OF ANY KIND. Since KDU relies on completely bugged, vulnerable drivers, it is highly recommended to use it on virtual machines only.

# Third party code usage

* TinyAES, https://github.com/kokke/tiny-AES-c
* whirlpool, https://github.com/mabako/mta-whirlpool

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
* DEFCON27: Get off the kernel if you can't drive, https://eclypsium.com/wp-content/uploads/2019/08/EXTERNAL-Get-off-the-kernel-if-you-cant-drive-DEFCON27.pdf
* CVE-2019-8372: Local Privilege Elevation in LG Kernel Driver, http://www.jackson-t.ca/lg-driver-lpe.html
* CVE-2021-21551, https://attackerkb.com/topics/zAHZGAFaQX/cve-2021-21551
* KDU v1.1 release and bonus (AsIO3.sys unlock), https://swapcontext.blogspot.com/2021/04/kdu-v11-release-and-bonus-asio3sys.html
* GhostEmperor: From ProxyLogon to kernel mode, https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/
* KDU v1.2 release and the wonderful world of Microsoft incoherency, https://swapcontext.blogspot.com/2022/02/kdu-v12-release-and-wonderful-world-of.html
* How to exploit a vulnerable Windows driver, https://github.com/stong/CVE-2020-15368
* CVE-2022-3699, https://github.com/alfarom256/CVE-2022-3699
* LOLDrivers, https://www.loldrivers.io
* ECHOH NO, https://github.com/kite03/echoac-poc/
* NVDrv, https://github.com/zer0condition/NVDrv
* CVE-2023-41444, https://blog.dru1d.ninja/windows-driver-exploit-development-irec-sys-a5eb45093945
* CVE-2023-20598, https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6009.html
* CVE-2020-12928, https://h0mbre.github.io/RyzenMaster_CVE/
* CVE-2025-45737, https://github.com/smallzhong/NeacController

# Wormhole drivers code

They are used in multiple products from hardware vendors, mostly in unmodified state. They all break the OS security model and are additionally bugged. Links are for educational purposes on how not to do things in driver development.

* WinIo 3.0 BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/WINIO
* WinRing0 BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/WINRING0
* PhyMem BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/PHYMEM
* MapMem BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/MAPMEM
* InpOut BSOD/CVE generator, https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/INPOUT
* Intel infamous driver, https://github.com/hfiref0x/Misc/tree/master/source/IntelNal

# Authors

(c) 2020 - 2025 KDU Project
