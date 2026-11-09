/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2024 - 2026
*
*  TITLE:       CPROVIDERCSV.CS
*
*  VERSION:     1.01
*
*  DATE:        07 Nov 2026
*
*  Provider CSV to XML conversion.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
namespace SiPolicyChecker;

using System.Globalization;
using Microsoft.VisualBasic.FileIO;

internal static class CProviderCSV
{
    public static CProviders Load(string path)
    {
        using var parser = new TextFieldParser(path)
        {
            TextFieldType = FieldType.Delimited,
            HasFieldsEnclosedInQuotes = true,
            TrimWhiteSpace = false
        };
        parser.SetDelimiters(",");

        string[] header = parser.ReadFields() ?? throw new InvalidDataException("Provider CSV is empty.");
        var columns = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < header.Length; i++)
        {
            if (!columns.TryAdd(header[i], i))
                throw new InvalidDataException($"Duplicate provider CSV column: {header[i]}.");
        }

        string[] requiredColumns =
        {
            "ProviderId", "DriverName", "AdvisoryId", "FileSHA1",
            "AuthenticodeSHA1", "PageHashSHA1", "PageHashSHA256"
        };
        foreach (string column in requiredColumns)
        {
            if (!columns.ContainsKey(column))
                throw new InvalidDataException($"Missing provider CSV column: {column}.");
        }

        var drivers = new List<Driver>();
        int incompleteHashes = 0;
        while (!parser.EndOfData)
        {
            long line = parser.LineNumber;
            string[] fields = parser.ReadFields() ?? throw new InvalidDataException($"Invalid provider CSV record at line {line}.");
            if (fields.Length != header.Length)
                throw new InvalidDataException($"Provider CSV record at line {line} has {fields.Length} fields; expected {header.Length}.");

            if (!int.TryParse(fields[columns["ProviderId"]], NumberStyles.None, CultureInfo.InvariantCulture, out int id))
                throw new InvalidDataException($"Invalid provider ID at line {line}.");

            var hashes = new Hashes
            {
                FileSHA1 = fields[columns["FileSHA1"]],
                AuthenticodeSHA1 = fields[columns["AuthenticodeSHA1"]],
                PageSHA1 = fields[columns["PageHashSHA1"]],
                PageSHA256 = fields[columns["PageHashSHA256"]]
            };
            if (string.IsNullOrEmpty(hashes.AuthenticodeSHA1) ||
                string.IsNullOrEmpty(hashes.PageSHA1) ||
                string.IsNullOrEmpty(hashes.PageSHA256))
                incompleteHashes++;

            drivers.Add(new Driver
            {
                Id = id,
                Codebase = fields[columns["DriverName"]],
                CVEs = fields[columns["AdvisoryId"]],
                Hashes = hashes
            });
        }

        if (drivers.Count == 0)
            throw new InvalidDataException("Provider CSV contains no provider records.");

        if (incompleteHashes != 0)
            Console.Error.WriteLine($"Warning: {incompleteHashes} provider record(s) have missing comparison hashes; results may be incomplete.");

        return new CProviders { Drivers = drivers };
    }
}
