using System;
using System.Collections.Generic;

namespace Certify.Plugin.CertificateManagers.Migration
{
    /// <summary>
    /// Kinds of validation a source can describe. DNS validation names its provider by catalogue key
    /// </summary>
    public static class SourceValidationKinds
    {
        public const string Dns = "dns";
        public const string DnsScript = "dns-script";
        public const string HttpFileSystem = "http-filesystem";
        public const string HttpSelfHosting = "http-selfhosting";

        /// <summary>
        /// http-01 by a method with no equivalent here (FTP, SFTP, WebDAV, REST, script)
        /// </summary>
        public const string HttpUnsupported = "http-unsupported";
        public const string TlsAlpn = "tls-alpn";

        /// <summary>
        /// Manual validation, where a person creates the record
        /// </summary>
        public const string Manual = "manual";

        /// <summary>
        /// No validation, the identifiers are pre-authorized with the CA
        /// </summary>
        public const string None = "none";
        public const string Unknown = "unknown";
    }

    public static class SourceOutputKinds
    {
        public const string CertificateStore = "CertificateStore";
        public const string PemFiles = "PemFiles";
        public const string PfxFile = "PfxFile";
        public const string CentralSsl = "CentralSsl";
        public const string KeyVault = "KeyVault";
        public const string UserStore = "UserStore";
        public const string P7bFile = "P7bFile";
        public const string None = "None";
        public const string Unknown = "Unknown";
    }

    public static class SourceInstallationKinds
    {
        public const string Iis = "IIS";
        public const string IisFtp = "IISFTP";
        public const string Script = "Script";
        public const string None = "None";
        public const string Unknown = "Unknown";
    }

    /// <summary>
    /// A secret held by the source. The value is never part of the description, the source reads it again at import
    /// </summary>
    public class SourceSecret
    {
        /// <summary>
        /// Stable key, shared by every option referring to the same stored secret (e.g. the same vault entry)
        /// </summary>
        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// Where the secret is held, e.g. "vault://json/cf" or "renewal file"
        /// </summary>
        public string Location { get; set; } = string.Empty;
        public bool IsReadable { get; set; }
        public string? Reason { get; set; }

        /// <summary>
        /// True if the secret is a reference shared with other items (a vault entry), so one credential serves all
        /// </summary>
        public bool IsShared { get; set; }

        /// <summary>
        /// True if the value is not held by the source but generated at import (e.g. a wrapper script adapting the
        /// source's script calling convention), so it is not listed as a secret
        /// </summary>
        public bool IsGenerated { get; set; }
    }

    public class SourceValidation
    {
        /// <summary>
        /// Identifiers this validation applies to, or null for all of the item's identifiers
        /// </summary>
        public List<string>? Identifiers { get; set; }

        public string Kind { get; set; } = SourceValidationKinds.Unknown;

        /// <summary>
        /// For DNS validation, the catalogue key of the DNS provider (see <see cref="MigrationCatalogue"/>)
        /// </summary>
        public string? DnsProvider { get; set; }

        /// <summary>
        /// The source's own name for the method, for display
        /// </summary>
        public string SourceName { get; set; } = string.Empty;

        /// <summary>
        /// Option values which are not secret, by parameter key of the provider here (the parser translates the
        /// source's option names). For non DNS kinds, by the names the mapper documents for that kind
        /// </summary>
        public Dictionary<string, string> Parameters { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Secret options, by parameter key here, mapped to a <see cref="SourceSecret.Key"/>
        /// </summary>
        public Dictionary<string, string> SecretParameters { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Source options with no equivalent, which are not migrated
        /// </summary>
        public List<string> UnmappedOptions { get; set; } = new();

        /// <summary>
        /// Set if the source authenticates without a stored secret (e.g. a managed identity or the machine's IAM role),
        /// describing how
        /// </summary>
        public string? AmbientAuthentication { get; set; }

        /// <summary>
        /// Differences in behaviour the parser knows of, shown as assumptions
        /// </summary>
        public List<string> Notes { get; set; } = new();

        /// <summary>
        /// Where these options came from, e.g. "renewal" or "validation.json"
        /// </summary>
        public string Origin { get; set; } = "renewal";
    }

    /// <summary>
    /// Names of the settings of outputs and installations, shared by all parsers
    /// </summary>
    public static class SourceSettingNames
    {
        public const string StoreName = "StoreName";
        public const string Path = "Path";

        /// <summary>
        /// File name without extension
        /// </summary>
        public const string FileName = "FileName";

        /// <summary>
        /// Secret setting: password protecting the written private key
        /// </summary>
        public const string Password = "Password";
        public const string AclFullControl = "AclFullControl";
        public const string AclRead = "AclRead";
        public const string KeepExisting = "KeepExisting";

        public const string VaultName = "VaultName";
        public const string CertificateName = "CertificateName";
        public const string AzureService = "AzureService";
        public const string TenantId = "TenantId";
        public const string ClientId = "ClientId";

        /// <summary>
        /// Secret setting: Azure client secret
        /// </summary>
        public const string ClientSecret = "ClientSecret";

        public const string SiteId = "SiteId";
        public const string BindingIp = "BindingIp";
        public const string BindingPort = "BindingPort";

        /// <summary>
        /// Secret setting: generated wrapper script which runs the source's script with its own arguments
        /// </summary>
        public const string ScriptWrapper = "ScriptWrapper";
        public const string Script = "Script";
    }

    public class SourceOutput
    {
        public string Kind { get; set; } = SourceOutputKinds.Unknown;
        public string SourceName { get; set; } = string.Empty;

        /// <summary>
        /// Settings by <see cref="SourceSettingNames"/>
        /// </summary>
        public Dictionary<string, string> Settings { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Secret settings by <see cref="SourceSettingNames"/>, mapped to a <see cref="SourceSecret.Key"/>
        /// </summary>
        public Dictionary<string, string> SecretSettings { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, List<string>> ListSettings { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Set if the source authenticates without a stored secret (e.g. a managed identity), describing how
        /// </summary>
        public string? AmbientAuthentication { get; set; }
        public List<string> Notes { get; set; } = new();
    }

    public class SourceInstallation
    {
        public string Kind { get; set; } = SourceInstallationKinds.Unknown;
        public string SourceName { get; set; } = string.Empty;

        /// <summary>
        /// Settings by <see cref="SourceSettingNames"/>
        /// </summary>
        public Dictionary<string, string> Settings { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> SecretSettings { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Notes { get; set; } = new();
    }

    /// <summary>
    /// Something in the source the parser did not recognise, so it is not migrated
    /// </summary>
    public class SourceUnrecognised
    {
        public string Category { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// True if migrating without it would change what the certificate does (e.g. an unknown plugin), rather than
        /// lose a detail (e.g. an unknown option)
        /// </summary>
        public bool IsBlocker { get; set; }
    }

    /// <summary>
    /// A tool neutral description of one item of an external certificate manager, produced by the tool's parser and
    /// turned into a migration plan by <see cref="MigrationPlanMapper"/>. Holds no secret values
    /// </summary>
    public class SourceRenewalDescription
    {
        public string ProviderId { get; set; } = string.Empty;
        public string ProviderTitle { get; set; } = string.Empty;
        public string ItemId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string SourcePath { get; set; } = string.Empty;
        public string FileHash { get; set; } = string.Empty;

        /// <summary>
        /// ACME directory URL, or the folder name it is derived from
        /// </summary>
        public List<string?> CaEndpoints { get; set; } = new();

        public List<string> Identifiers { get; set; } = new();

        /// <summary>
        /// Where the identifiers came from: renewal, certificate, request or none
        /// </summary>
        public string IdentifierSource { get; set; } = "renewal";

        /// <summary>
        /// True if the source works the identifiers out again at each renewal, e.g. from IIS bindings
        /// </summary>
        public bool IdentifiersFollowServerBindings { get; set; }

        /// <summary>
        /// IIS site the source targets, if a single one
        /// </summary>
        public string? ServerSiteId { get; set; }

        /// <summary>
        /// PEM of a certificate request supplied to the source, used instead of generating one
        /// </summary>
        public string? CustomCsr { get; set; }

        /// <summary>
        /// Secret key of a custom private key, read at import
        /// </summary>
        public string? CustomPrivateKeySecret { get; set; }
        public bool CsrFromScript { get; set; }

        /// <summary>
        /// "rsa" or "ec", from the CSR plugin
        /// </summary>
        public string? KeyType { get; set; }
        public int? RsaKeyBits { get; set; }
        public string? EcCurve { get; set; }

        /// <summary>
        /// Key algorithm of the issued certificate, if known (a Certify key type id)
        /// </summary>
        public string? IssuedKeyAlgorithm { get; set; }

        public bool ReusePrivateKey { get; set; }
        public bool OcspMustStaple { get; set; }
        public string? PreferredIssuer { get; set; }
        public string? CertificateProfile { get; set; }
        public int? ValidDays { get; set; }

        /// <summary>
        /// Renewal interval in days, if set explicitly in the source's settings
        /// </summary>
        public int? RenewalDays { get; set; }

        /// <summary>
        /// Source settings not migrated because nothing here is equivalent, which differ from the source's defaults
        /// </summary>
        public List<string> UnmappedSettings { get; set; } = new();

        /// <summary>
        /// Order (split) the item is from, if the source split a renewal into several certificates
        /// </summary>
        public string? OrderName { get; set; }

        public List<SourceValidation> Validations { get; set; } = new();
        public List<SourceOutput> Outputs { get; set; } = new();
        public List<SourceInstallation> Installations { get; set; } = new();
        public List<SourceSecret> Secrets { get; set; } = new();
        public List<SourceUnrecognised> Unrecognised { get; set; } = new();

        /// <summary>
        /// Notes on the source's global settings, e.g. which files were read and what was assumed
        /// </summary>
        public List<string> SettingsNotes { get; set; } = new();
        public bool SettingsAssumed { get; set; }

        public bool AccountReadable { get; set; }
        public string? AccountDescription { get; set; }

        public string? CurrentCertificateThumbprint { get; set; }
        public DateTimeOffset? CurrentCertificateExpiry { get; set; }
        public bool CurrentCertificateReadable { get; set; }
        public string? CurrentCertificateNote { get; set; }

        /// <summary>
        /// Errors from the source's latest run, if it failed
        /// </summary>
        public List<string> LastRunErrors { get; set; } = new();

        /// <summary>
        /// Other items of the same source entry (e.g. the other orders of a split renewal), which are disabled and
        /// removed with this one
        /// </summary>
        public List<string> RelatedItemIds { get; set; } = new();

        /// <summary>
        /// The source's own id for the entry, used to name credentials created for it
        /// </summary>
        public string? RenewalId { get; set; }

        /// <summary>
        /// Name of the source's ACME account, if not its default
        /// </summary>
        public string? AccountName { get; set; }
    }
}
