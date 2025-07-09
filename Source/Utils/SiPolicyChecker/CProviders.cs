/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2024 - 2025
*
*  TITLE:       CPROVIDERS.CS
*
*  VERSION:     1.00
*
*  DATE:        14 Jun 2025
*
*  KDU providers classes layout for XML (de)serialization.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
using System.Xml.Serialization;

[XmlRoot("Drivers")]
public class CProviders
{
    [XmlElement("Driver")]
    public List<Driver>? Drivers { get; set; }
}

public class Driver
{
    [XmlElement("Id")]
    public int? Id { get; set; }

    [XmlElement("Codebase")]
    public string? Codebase { get; set; }

    [XmlElement("CVEs")]
    public string? CVEs { get; set; }

    [XmlElement("Hashes")]
    public Hashes? Hashes { get; set; }
}

public class Hashes
{
    [XmlElement("FileSHA1")]
    public string? FileSHA1 { get; set; }

    [XmlElement("AuthenticodeSHA1")]
    public string? AuthenticodeSHA1 { get; set; }

    [XmlElement("PageSHA1")]
    public string? PageSHA1 { get; set; }

    [XmlElement("PageSHA256")]
    public string? PageSHA256 { get; set; }
}
