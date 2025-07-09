/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2024 - 2025
*
*  TITLE:       PROGRAM.CS
*
*  VERSION:     1.00
*
*  DATE:        14 Jun 2025
*
*  SPC entrypoint, KDU helper module
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

using System.Xml.Serialization;

class Program
{
    static void Main(string[] args)
    {
        string providersPath = "Providers.xml";
        string siPolicyPath = "SiPolicy.xml";
        CProviders? providers;
        CSiPolicy? policy;

        // Process command line arguments
        if (args.Length >= 1)
            providersPath = args[0];

        if (args.Length >= 2)
            siPolicyPath = args[1];

        if (args.Length == 0)
            Console.WriteLine("Using default paths. To specify files: Program.exe [ProvidersXmlPath] [SiPolicyXmlPath]");

        try
        {
            using (var fs = new FileStream(providersPath, FileMode.Open))
            {
                var serializer = new XmlSerializer(typeof(CProviders));
                providers = serializer.Deserialize(fs) as CProviders;
            }

            using (var fs = new FileStream(siPolicyPath, FileMode.Open))
            {
                var serializer = new XmlSerializer(typeof(CSiPolicy));
                policy = serializer.Deserialize(fs) as CSiPolicy;
            }

            if (providers?.Drivers == null || policy?.FileRules?.Deny == null)
            {
                Console.WriteLine("Error: Failed to load XML files or they contain no relevant data.");
                return;
            }

            var denyHashes = policy.FileRules.Deny
                .Where(d => !string.IsNullOrEmpty(d.Hash))
                .Select(d => d.Hash?.ToUpperInvariant())
                .ToHashSet();

            Console.WriteLine($"SiPolicy version {policy.VersionEx}");
            Console.WriteLine("==============================================================================\r\n");

            bool matchesFound = false;
            foreach (var driver in providers.Drivers)
            {
                bool isMatch = false;

                if (driver.Hashes != null)
                {
                    // Check if any hash matches a deny hash
                    if (!string.IsNullOrEmpty(driver.Hashes.PageSHA1) &&
                        denyHashes.Contains(driver.Hashes.PageSHA1))
                    {
                        isMatch = true;
                    }
                    else if (!string.IsNullOrEmpty(driver.Hashes.PageSHA256) &&
                        denyHashes.Contains(driver.Hashes.PageSHA256))
                    {
                        isMatch = true;
                    }
                    else if (!string.IsNullOrEmpty(driver.Hashes.AuthenticodeSHA1) &&
                        denyHashes.Contains(driver.Hashes.AuthenticodeSHA1))
                    {
                        isMatch = true;
                    }
                }

                if (isMatch)
                {
                    matchesFound = true;
                    Console.WriteLine($"Match found for Driver ID: {driver.Id}");
                    Console.WriteLine($"Codebase: {driver.Codebase}");
                    Console.WriteLine($"CVEs: {driver.CVEs}");
                    Console.WriteLine($"Page SHA1: {driver.Hashes?.PageSHA1}");
                    Console.WriteLine($"Page SHA256: {driver.Hashes?.PageSHA256}");
                    Console.WriteLine($"Authenticode SHA1: {driver.Hashes?.AuthenticodeSHA1}");
                    Console.WriteLine($"File SHA1: {driver.Hashes?.FileSHA1}");
                    Console.WriteLine("==============================================================================\r\n");
                }
            }

            if (!matchesFound)
            {
                Console.WriteLine("No matches found between Providers.xml and SiPolicy.xml deny rules.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing files: {ex.Message}");
        }
    }
}
