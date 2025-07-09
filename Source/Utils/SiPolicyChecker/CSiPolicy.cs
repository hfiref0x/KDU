/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2024 - 2025
*
*  TITLE:       CSIPOLICY.CS
*
*  VERSION:     1.00
*
*  DATE:        14 Jun 2025
*
*  SiPolicy classes layout for XML (de)serialization.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
using System.Xml.Serialization;

[XmlRoot(ElementName = "Rule", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Rule
{
    [XmlElement(ElementName = "Option", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? Option { get; set; }
}

[XmlRoot(ElementName = "Rules", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Rules
{
    [XmlElement(ElementName = "Rule", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<Rule>? Rule { get; set; }
}

[XmlRoot(ElementName = "Allow", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Allow
{
    [XmlAttribute(AttributeName = "ID")]
    public string? ID { get; set; }
    [XmlAttribute(AttributeName = "FriendlyName")]
    public string? FriendlyName { get; set; }
    [XmlAttribute(AttributeName = "FileName")]
    public string? FileName { get; set; }
}

[XmlRoot(ElementName = "Deny", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Deny
{
    [XmlAttribute(AttributeName = "ID")]
    public string? ID { get; set; }
    [XmlAttribute(AttributeName = "FriendlyName")]
    public string? FriendlyName { get; set; }
    [XmlAttribute(AttributeName = "Hash")]
    public string? Hash { get; set; }
    [XmlAttribute(AttributeName = "FileName")]
    public string? FileName { get; set; }
    [XmlAttribute(AttributeName = "MinimumFileVersion")]
    public string? MinimumFileVersion { get; set; }
    [XmlAttribute(AttributeName = "MaximumFileVersion")]
    public string? MaximumFileVersion { get; set; }
}

[XmlRoot(ElementName = "FileAttrib", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class FileAttrib
{
    [XmlAttribute(AttributeName = "ID")]
    public string? ID { get; set; }
    [XmlAttribute(AttributeName = "FriendlyName")]
    public string? FriendlyName { get; set; }
    [XmlAttribute(AttributeName = "FileName")]
    public string? FileName { get; set; }
    [XmlAttribute(AttributeName = "MinimumFileVersion")]
    public string? MinimumFileVersion { get; set; }
    [XmlAttribute(AttributeName = "MaximumFileVersion")]
    public string? MaximumFileVersion { get; set; }
    [XmlAttribute(AttributeName = "InternalName")]
    public string? InternalName { get; set; }
    [XmlAttribute(AttributeName = "ProductName")]
    public string? ProductName { get; set; }
}

[XmlRoot(ElementName = "FileRules", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class FileRules
{
    [XmlElement(ElementName = "Allow", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<Allow>? Allow { get; set; }
    [XmlElement(ElementName = "Deny", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<Deny>? Deny { get; set; }
    [XmlElement(ElementName = "FileAttrib", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<FileAttrib>? FileAttrib { get; set; }
}

[XmlRoot(ElementName = "CertRoot", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class CertRoot
{
    [XmlAttribute(AttributeName = "Type")]
    public string? Type { get; set; }
    [XmlAttribute(AttributeName = "Value")]
    public string? Value { get; set; }
}

[XmlRoot(ElementName = "FileAttribRef", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class FileAttribRef
{
    [XmlAttribute(AttributeName = "RuleID")]
    public string? RuleID { get; set; }
}

[XmlRoot(ElementName = "Signer", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Signer
{
    [XmlElement(ElementName = "CertRoot", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public CertRoot? CertRoot { get; set; }
    [XmlElement(ElementName = "FileAttribRef", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<FileAttribRef>? FileAttribRef { get; set; }
    [XmlAttribute(AttributeName = "ID")]
    public string? ID { get; set; }
    [XmlAttribute(AttributeName = "Name")]
    public string? Name { get; set; }
    [XmlElement(ElementName = "CertPublisher", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public CertPublisher? CertPublisher { get; set; }
    [XmlElement(ElementName = "CertOemID", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public CertOemID? CertOemID { get; set; }
}

[XmlRoot(ElementName = "CertPublisher", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class CertPublisher
{
    [XmlAttribute(AttributeName = "Value")]
    public string? Value { get; set; }
}

[XmlRoot(ElementName = "CertOemID", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class CertOemID
{
    [XmlAttribute(AttributeName = "Value")]
    public string? Value { get; set; }
}

[XmlRoot(ElementName = "Signers", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Signers
{
    [XmlElement(ElementName = "Signer", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<Signer>? Signer { get; set; }
}

[XmlRoot(ElementName = "DeniedSigner", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class DeniedSigner
{
    [XmlAttribute(AttributeName = "SignerId")]
    public string? SignerId { get; set; }
}

[XmlRoot(ElementName = "DeniedSigners", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class DeniedSigners
{
    [XmlElement(ElementName = "DeniedSigner", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<DeniedSigner>? DeniedSigner { get; set; }
}

[XmlRoot(ElementName = "FileRuleRef", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class FileRuleRef
{
    [XmlAttribute(AttributeName = "RuleID")]
    public string? RuleID { get; set; }
}

[XmlRoot(ElementName = "FileRulesRef", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class FileRulesRef
{
    [XmlElement(ElementName = "FileRuleRef", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<FileRuleRef>? FileRuleRef { get; set; }
}

[XmlRoot(ElementName = "ProductSigners", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class ProductSigners
{
    [XmlElement(ElementName = "DeniedSigners", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public DeniedSigners? DeniedSigners { get; set; }
    [XmlElement(ElementName = "FileRulesRef", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public FileRulesRef? FileRulesRef { get; set; }
}

[XmlRoot(ElementName = "SigningScenario", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class SigningScenario
{
    [XmlElement(ElementName = "ProductSigners", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public ProductSigners? ProductSigners { get; set; }
    [XmlAttribute(AttributeName = "Value")]
    public string? Value { get; set; }
    [XmlAttribute(AttributeName = "ID")]
    public string? ID { get; set; }
    [XmlAttribute(AttributeName = "FriendlyName")]
    public string? FriendlyName { get; set; }
}

[XmlRoot(ElementName = "SigningScenarios", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class SigningScenarios
{
    [XmlElement(ElementName = "SigningScenario", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<SigningScenario>? SigningScenario { get; set; }
}

[XmlRoot(ElementName = "Value", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Value
{
    [XmlElement(ElementName = "String", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? String { get; set; }
}

[XmlRoot(ElementName = "Setting", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Setting
{
    [XmlElement(ElementName = "Value", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public Value? Value { get; set; }
    [XmlAttribute(AttributeName = "Provider")]
    public string? Provider { get; set; }
    [XmlAttribute(AttributeName = "Key")]
    public string? Key { get; set; }
    [XmlAttribute(AttributeName = "ValueName")]
    public string? ValueName { get; set; }
}

[XmlRoot(ElementName = "Settings", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class Settings
{
    [XmlElement(ElementName = "Setting", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public List<Setting>? Setting { get; set; }
}

[XmlRoot(ElementName = "SiPolicy", Namespace = "urn:schemas-microsoft-com:sipolicy")]
public class CSiPolicy
{
    [XmlElement(ElementName = "VersionEx", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? VersionEx { get; set; }
    [XmlElement(ElementName = "PlatformID", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? PlatformID { get; set; }
    [XmlElement(ElementName = "Rules", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public Rules? Rules { get; set; }
    [XmlElement(ElementName = "EKUs", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? EKUs { get; set; }
    [XmlElement(ElementName = "FileRules", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public FileRules? FileRules { get; set; }
    [XmlElement(ElementName = "Signers", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public Signers? Signers { get; set; }
    [XmlElement(ElementName = "SigningScenarios", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public SigningScenarios? SigningScenarios { get; set; }
    [XmlElement(ElementName = "UpdatePolicySigners", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? UpdatePolicySigners { get; set; }
    [XmlElement(ElementName = "CiSigners", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? CiSigners { get; set; }
    [XmlElement(ElementName = "HvciOptions", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? HvciOptions { get; set; }
    [XmlElement(ElementName = "Settings", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public Settings? Settings { get; set; }
    [XmlElement(ElementName = "PolicyTypeID", Namespace = "urn:schemas-microsoft-com:sipolicy")]
    public string? PolicyTypeID { get; set; }
    [XmlAttribute(AttributeName = "xmlns")]
    public string? Xmlns { get; set; }
}
