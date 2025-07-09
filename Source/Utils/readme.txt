GenAsIo2Unlock is a special utility used to generate the "unlocking" resource required for working with the AsIO2 driver. The full source for this utility is included in Source\Utils\GenAsIo2Unlock. The compiled version is located in Sources\Hamakaze\Utils\GenAsIo2Unlock.exe. **Warning:** This utility is set to execute as a post-build event for both Debug and Release configurations. If you do not want to run the precompiled version, replace it with a newly compiled version from the sources. If you remove this post-build event, newly compiled KDU will NOT BE ABLE to use the AsIO2 driver (provider #13).

PCOMP is an auxiliary utility used to compress provider files. It is not intended for general use and is only used when you need to generate new binary blobs for provider DLLs.

SiPolicyChecker is an auxiliary utility used to check that KDU provider hashes (page SHA1, page SHA256, or file Authenticode) are present in the Microsoft drivers blocklist.
