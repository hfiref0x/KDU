Dbpack is a special utility used to generate single KDU database file which is next embedded into Tanikaze dll.

GenAsIo2Unlock is a special utility used to generate the "unlocking" resource required for working with the AsIO2 driver. The full source for this utility is included in Source\Utils\GenAsIo2Unlock. The compiled version is located in Sources\Hamakaze\Utils\GenAsIo2Unlock.exe. **Warning:** This utility is set to execute as a post-build event for both Debug and Release configurations. If you do not want to run the precompiled version, replace it with a newly compiled version from the sources. If you remove this post-build event, newly compiled KDU will NOT BE ABLE to use the AsIO2 driver (provider #13).

PCOMP is an auxiliary utility used to compress provider files. It is not intended for general use and is only used when you need to generate new binary blobs for provider DLLs.

SiPolicyChecker is an auxiliary utility used to check that KDU provider hashes (page SHA1, page SHA256, or file Authenticode) are present in the Microsoft drivers blocklist.
How to use it: 
1) Generate a provider CSV with "kdu -listcsv providers.csv"
2) Download Microsoft Vulnerable Driver Blocklist package (https://www.microsoft.com/en-us/download/details.aspx?id=108667)
3) Extract DriverPolicy_Enforced.xml as SiPolicy.xml
4) Run "SiPolicyChecker.exe providers.csv SiPolicy.xml"
With no arguments, the defaults remain Providers.xml and SiPolicy.xml in the current directory. CSV records with missing
comparison hashes are reported as incomplete. The checker only compares hashes; it does not evaluate signer, filename, or policy applicability rules.