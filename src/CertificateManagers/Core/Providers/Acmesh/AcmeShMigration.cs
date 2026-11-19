using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Migration;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.AcmeSh
{
    /// <summary>
    /// Migration of acme.sh certificates. Reads a domain's conf, the DNS API settings acme.sh saved and its account into a
    /// <see cref="SourceRenewalDescription"/>. Cut over renames the conf to .conf.removed, as acme.sh --remove does, so
    /// acme.sh no longer renews it and it drops out of monitoring
    /// </summary>
    public partial class AcmeSh : ICertificateManagerMigrationSource
    {
        internal const string DisabledSuffix = ".removed";
        private const string AccountConfFile = "account.conf";
        private const string DefaultServer = "https://acme.zerossl.com/v2/DV90";
        private const string Base64Start = "__ACME_BASE64__START_";
        private const string Base64End = "__ACME_BASE64__END_";

        /// <summary>
        /// The item id of a domain's certificate. An ECC certificate is kept in {domain}_ecc, and when an RSA certificate
        /// for the same domain exists too, the RSA one keeps the plain id
        /// </summary>
        internal static string ItemIdFor(string domain, DirectoryInfo? folder)
        {
            var name = domain;

            if (folder?.Parent != null && folder.Name.EndsWith("_ecc", StringComparison.Ordinal))
            {
                var rsaConf = Path.Combine(folder.Parent.FullName, domain, $"{domain}.conf");
                if (File.Exists(rsaConf) || File.Exists(rsaConf + DisabledSuffix))
                {
                    name = $"{domain}_ecc";
                }
            }

            return $"{ManagedCertificate.ExternalItemIdPrefix}acme.sh-{Certify.Management.Util.ToUrlSafeBase64String(name)}";
        }

        public MigrationSourceCapabilities GetMigrationCapabilities() => new()
        {
            DisableMethod = "Renames the domain's conf to .conf.removed, as acme.sh --remove does, so acme.sh no longer renews it",
            DisabledItemHiddenFromMonitoring = true,
            CanDisableSingleItem = true,
            RequiresIdleTool = true
        };

        public async Task<ExternalMigrationPlan?> PrepareMigrationPlan(string itemId, ExternalMigrationContext context, IDictionary<string, string>? inputs)
        {
            var reader = await GetReader(itemId, includeDisabled: false);
            return reader == null ? null : MigrationPlanMapper.Map(reader.Description, context, inputs);
        }

        public async Task<Dictionary<string, string>> ResolveCredentialValues(string itemId, ExternalMigrationCredentialDraft draft)
        {
            var reader = await GetReader(itemId, includeDisabled: false) ?? throw new InvalidOperationException("The acme.sh certificate could not be found.");
            return reader.Secrets.Resolve(draft);
        }

        public async Task<SourceCertificateMaterial?> GetCurrentCertificate(string itemId)
        {
            var reader = await GetReader(itemId, includeDisabled: true);
            return reader?.ReadCertificate(keepData: true, out _);
        }

        public async Task<SourceAccountMaterial?> GetAccount(string itemId)
        {
            var reader = await GetReader(itemId, includeDisabled: true);
            return reader?.ReadAccount(out _);
        }

        public async Task<SourceChangeResult> DisableSourceItem(string itemId)
        {
            var entry = await FindDomain(itemId, includeDisabled: true);
            if (entry == null)
            {
                return new SourceChangeResult(false, "The acme.sh certificate could not be found.");
            }

            if (entry.IsDisabled)
            {
                return new SourceChangeResult(true, "The acme.sh certificate is already removed from renewal.");
            }

            return WhenAcmeShIdle(() =>
            {
                var target = entry.File.FullName + DisabledSuffix;
                if (File.Exists(target))
                {
                    return new SourceChangeResult(false, $"{target} already exists.");
                }

                File.Move(entry.File.FullName, target);
                return new SourceChangeResult(true, $"Renamed {entry.File.Name} to {Path.GetFileName(target)}, as acme.sh --remove does, so acme.sh no longer renews it.");
            });
        }

        public async Task<SourceChangeResult> RestoreSourceItem(string itemId)
        {
            var entry = await FindDomain(itemId, includeDisabled: true);
            if (entry == null)
            {
                return new SourceChangeResult(false, "The acme.sh certificate could not be found.");
            }

            if (!entry.IsDisabled)
            {
                return new SourceChangeResult(true, "The acme.sh certificate is already renewed by acme.sh.");
            }

            return WhenAcmeShIdle(() =>
            {
                var target = entry.File.FullName[..^DisabledSuffix.Length];
                if (File.Exists(target))
                {
                    return new SourceChangeResult(false, $"{target} already exists, so the removed certificate was left as it is.");
                }

                File.Move(entry.File.FullName, target);
                return new SourceChangeResult(true, $"Renamed the conf back to {Path.GetFileName(target)}, so acme.sh renews it again.");
            });
        }

        public async Task<SourceRemovalManifest> PlanSourceRemoval(string itemId)
        {
            var manifest = new SourceRemovalManifest { SourceItemId = itemId };

            var entry = await FindDomain(itemId, includeDisabled: true);
            if (entry == null)
            {
                manifest.BlockedReason = "The acme.sh certificate could not be found.";
                return manifest;
            }

            if (!entry.IsDisabled)
            {
                manifest.BlockedReason = "The certificate is renewed by acme.sh again, so it is not removed. Cut over again first.";
            }

            // files acme.sh installed elsewhere stay, as services read them and the migrated item now writes them
            var installed = RealPaths(entry).Values.Select(p => Path.GetFullPath(p)).ToHashSet(StringComparer.OrdinalIgnoreCase);

            manifest.FilesToDelete.AddRange(Directory.GetFiles(entry.Folder.FullName, "*", SearchOption.AllDirectories)
                .Where(f => !installed.Contains(Path.GetFullPath(f)))
                .OrderBy(f => f));

            manifest.Kept.Add("acme.sh's account.conf and ca folder, which hold the account and DNS API settings other certificates may use");
            manifest.Kept.Add("acme.sh's cron job, which renews any other certificates");

            if (installed.Any())
            {
                manifest.Kept.Add($"The installed files {string.Join(", ", installed)}, which the migrated item now writes");
            }

            return manifest;
        }

        public async Task<SourceChangeResult> RemoveSourceItem(string itemId, SourceRemovalManifest manifest)
        {
            var current = await PlanSourceRemoval(itemId);

            if (current.BlockedReason != null)
            {
                return new SourceChangeResult(false, current.BlockedReason);
            }

            if (!current.FilesToDelete.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(manifest.FilesToDelete))
            {
                return new SourceChangeResult(false, "The files to delete have changed since the removal was previewed. Preview it again.");
            }

            var entry = await FindDomain(itemId, includeDisabled: true);

            return WhenAcmeShIdle(() =>
            {
                foreach (var file in manifest.FilesToDelete.Where(File.Exists))
                {
                    File.Delete(file);
                }

                if (entry != null && entry.Folder.Exists && !entry.Folder.EnumerateFileSystemInfos("*", SearchOption.AllDirectories).Any(f => f is FileInfo))
                {
                    entry.Folder.Delete(true);
                }

                return new SourceChangeResult(true, $"Deleted the acme.sh domain folder's {manifest.FilesToDelete.Count} file{(manifest.FilesToDelete.Count == 1 ? "" : "s")}.");
            });
        }

        private static SourceChangeResult WhenAcmeShIdle(Func<SourceChangeResult> action)
        {
            if (MigrationFiles.IsProcessRunning("acme.sh"))
            {
                return new SourceChangeResult(false, "acme.sh is running. Try again when it has finished.");
            }

            try
            {
                return action();
            }
            catch (Exception exp)
            {
                return new SourceChangeResult(false, exp.Message);
            }
        }

        // the domain conf

        internal sealed class DomainEntry
        {
            public FileInfo File { get; init; } = default!;
            public string Domain { get; init; } = string.Empty;
            public bool IsDisabled { get; init; }
            public string Hash { get; init; } = string.Empty;
            public Dictionary<string, string> Values { get; init; } = new();

            public DirectoryInfo Folder => File.Directory!;
            public string? Get(string name) => Values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
        }

        internal async Task<DomainEntry?> FindDomain(string itemId, bool includeDisabled)
        {
            if (!await IsPresent())
            {
                return null;
            }

            // a conf acme.sh renews is found before a removed one, should the domain have been issued again since
            var files = new DirectoryInfo(_settingsPath).GetFiles("*.conf*", SearchOption.AllDirectories)
                .Where(f => f.Name.EndsWith(".conf", StringComparison.Ordinal) || (includeDisabled && f.Name.EndsWith(".conf" + DisabledSuffix, StringComparison.Ordinal)))
                .OrderBy(f => f.Name.EndsWith(DisabledSuffix, StringComparison.Ordinal));

            foreach (var file in files)
            {
                try
                {
                    var bytes = await File.ReadAllBytesAsync(file.FullName);
                    var values = ParseConf(Encoding.UTF8.GetString(bytes));

                    if (!values.TryGetValue("Le_Domain", out var domain) || string.IsNullOrWhiteSpace(domain) || ItemIdFor(domain, file.Directory) != itemId)
                    {
                        continue;
                    }

                    return new DomainEntry
                    {
                        File = file,
                        Domain = domain,
                        IsDisabled = !file.Name.EndsWith(".conf", StringComparison.Ordinal),
                        Hash = MigrationFiles.FileHash(bytes),
                        Values = values
                    };
                }
                catch (Exception exp)
                {
                    _logger?.LogWarning("acme.sh: could not read {file}: {error}", file.FullName, exp.Message);
                }
            }

            return null;
        }

        private async Task<DomainReader?> GetReader(string itemId, bool includeDisabled)
        {
            var entry = await FindDomain(itemId, includeDisabled);
            if (entry == null)
            {
                return null;
            }

            var item = entry.IsDisabled ? null : (await GetManagedCertificates()).FirstOrDefault(i => i.Id == itemId);
            var reader = new DomainReader(this, entry, item);
            reader.Describe();
            return reader;
        }

        /// <summary>
        /// Variables of an acme.sh conf file (KEY='value'), with quotes removed and base64 encoded values decoded
        /// </summary>
        internal static Dictionary<string, string> ParseConf(string text)
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var raw in text.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                {
                    continue;
                }

                if (line.StartsWith("export ", StringComparison.Ordinal))
                {
                    line = line["export ".Length..].TrimStart();
                }

                var equals = line.IndexOf('=');
                if (equals <= 0)
                {
                    continue;
                }

                values[line[..equals].Trim()] = DecodeValue(line[(equals + 1)..].Trim());
            }

            return values;
        }

        private static string DecodeValue(string value)
        {
            if (value.Length >= 2 && ((value[0] == '\'' && value[^1] == '\'') || (value[0] == '"' && value[^1] == '"')))
            {
                value = value[1..^1];
            }

            if (value.StartsWith(Base64Start, StringComparison.Ordinal) && value.EndsWith(Base64End, StringComparison.Ordinal))
            {
                try
                {
                    return Encoding.UTF8.GetString(Convert.FromBase64String(value[Base64Start.Length..^Base64End.Length]));
                }
                catch (FormatException)
                {
                    return value;
                }
            }

            return value;
        }

        /// <summary>
        /// Where acme.sh installs the certificate (acme.sh --install-cert), by export type here
        /// </summary>
        private static Dictionary<string, string> RealPaths(DomainEntry entry) =>
            new[] { ("pemcrt", "Le_RealCertPath"), ("pemintermediates", "Le_RealCACertPath"), ("pemkey", "Le_RealKeyPath"), ("pemcrtpartialchain", "Le_RealFullChainPath") }
                .Where(p => entry.Get(p.Item2) != null)
                .ToDictionary(p => p.Item1, p => entry.Get(p.Item2)!);

        /// <summary>
        /// Reads one domain's conf and everything it depends on into a description
        /// </summary>
        internal sealed class DomainReader
        {
            private readonly AcmeSh _tool;
            private readonly DomainEntry _entry;
            private readonly ManagedCertificate? _item;
            private readonly Dictionary<string, string> _account;
            private readonly string _accountConfPath;

            public SourceRenewalDescription Description { get; } = new();
            public MigrationSecrets Secrets { get; }

            public DomainReader(AcmeSh tool, DomainEntry entry, ManagedCertificate? item)
            {
                _tool = tool;
                _entry = entry;
                _item = item;
                _accountConfPath = Path.Combine(tool._settingsPath, AccountConfFile);
                _account = File.Exists(_accountConfPath) ? ParseConf(File.ReadAllText(_accountConfPath)) : new();
                Secrets = new MigrationSecrets(Description);
            }

            private static string Tool => Definition.Title;
            private string? Get(string name) => _entry.Get(name) is { } value && value != "no" ? value : null;
            private string Domain => _entry.Domain;
            private string FolderFile(string name) => Path.Combine(_entry.Folder.FullName, name);

            private string Server => Get("Le_API") ?? _account.GetValueOrDefault("DEFAULT_ACME_SERVER") ?? DefaultServer;

            public void Describe()
            {
                var d = Description;
                d.ProviderId = Definition.Id;
                d.ProviderTitle = Tool;
                d.ItemId = ItemIdFor(Domain, _entry.Folder);
                d.Name = Domain;
                d.RenewalId = _entry.Folder.Name;
                d.SourcePath = _entry.File.FullName;
                d.FileHash = _entry.Hash;
                d.CaEndpoints = [Server];

                d.Identifiers = new[] { Domain }.Concat((Get("Le_Alt") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).Distinct().ToList();

                DescribeRequest();
                DescribeValidations();
                DescribeOutputs();
                DescribeInstallations();

                if (_item?.LastRenewalStatus == RequestState.Error && !string.IsNullOrWhiteSpace(_item.RenewalFailureMessage))
                {
                    d.LastRunErrors.Add(_item.RenewalFailureMessage!);
                }

                ReadAccount(out var accountDescription);
                d.AccountDescription = accountDescription;

                ReadCertificate(keepData: false, out var note);
                d.CurrentCertificateNote = note;
            }

            private void DescribeRequest()
            {
                var d = Description;
                var keyLength = Get("Le_Keylength") ?? (_entry.Folder.Name.EndsWith("_ecc", StringComparison.Ordinal) ? "ec-256" : "2048");

                if (keyLength.StartsWith("ec-", StringComparison.OrdinalIgnoreCase))
                {
                    d.KeyType = "ec";
                    d.EcCurve = keyLength[3..] switch { "256" => "secp256r1", "384" => "secp384r1", "521" => "secp521r1", var other => other };
                }
                else
                {
                    d.KeyType = "rsa";
                    d.RsaKeyBits = int.TryParse(keyLength, out var bits) ? bits : 2048;
                }

                // acme.sh keeps the domain key unless told to create a new one at each renewal
                d.ReusePrivateKey = Get("Le_ForceNewDomainKey") != "1";
                d.OcspMustStaple = Get("Le_OCSP_Staple") == "1";
                d.PreferredIssuer = Get("Le_Preferred_Chain");
                d.CertificateProfile = Get("Le_Certificate_Profile");

                if (Get("Le_Valid_To") is { } validTo)
                {
                    var match = Regex.Match(validTo, @"^\+(\d+)d$");
                    if (match.Success)
                    {
                        d.ValidDays = int.Parse(match.Groups[1].Value);
                    }
                    else
                    {
                        d.UnmappedSettings.Add($"The requested validity end {validTo} is not migrated.");
                    }
                }

                if (int.TryParse(Get("Le_RenewalDays"), out var renewalDays) && renewalDays > 0)
                {
                    d.RenewalDays = renewalDays;
                }

                foreach (var alias in new[] { "Le_ChallengeAlias", "Le_DomainAlias" })
                {
                    if (Get(alias) is { } value && value.Split(',').Any(v => v.Length > 0 && v != "no"))
                    {
                        d.Unrecognised.Add(new SourceUnrecognised { Category = "Validation", Description = $"{Tool} validates through DNS alias mode ({alias} {value}), which is not migrated. Set up a challenge delegation on the item instead.", IsBlocker = true });
                    }
                }
            }

            // validation

            private void DescribeValidations()
            {
                // "no" is a method here, standalone mode, so the value is read as it is
                var methods = (_entry.Get("Le_Webroot") ?? "").Split(',', StringSplitOptions.TrimEntries);
                var identifiers = Description.Identifiers;

                // one method for all, or one per identifier in order
                var byMethod = identifiers
                    .Select((identifier, i) => (Identifier: identifier, Method: methods.Length == 1 ? methods[0] : i < methods.Length ? methods[i] : methods.LastOrDefault() ?? ""))
                    .GroupBy(i => i.Method)
                    .ToList();

                foreach (var group in byMethod)
                {
                    var scope = byMethod.Count > 1 ? group.Select(g => g.Identifier).ToList() : null;
                    DescribeValidation(group.Key, scope, group.Select(g => g.Identifier).ToList());
                }
            }

            private void DescribeValidation(string method, List<string>? scope, List<string> identifiers)
            {
                var validation = new SourceValidation { Identifiers = scope, SourceName = method };

                switch (method)
                {
                    case "no":
                        validation.Kind = SourceValidationKinds.HttpSelfHosting;
                        validation.SourceName = "Standalone";
                        validation.Parameters["Port"] = Get("Le_HTTPPort") ?? "80";
                        break;

                    case "dns":
                        validation.Kind = SourceValidationKinds.Manual;
                        validation.SourceName = "Manual DNS";
                        break;

                    case "nginx":
                    case "apache":
                        validation.Kind = SourceValidationKinds.HttpSelfHosting;
                        validation.Notes.Add($"{Tool} answered http-01 challenges through {method}'s own configuration. The http challenge server here needs port 80, which {method} holds, so change the migrated item to a challenge folder {method} serves at /.well-known/acme-challenge/, or to DNS validation, before cut over.");
                        break;

                    case "stateless":
                        validation.Kind = SourceValidationKinds.Unknown;
                        validation.SourceName = "Stateless mode (the web server answers from the account thumbprint)";
                        break;

                    case "alpn":
                    case "tls":
                        validation.Kind = SourceValidationKinds.TlsAlpn;
                        break;

                    case "dns_acmedns":
                        DescribeAcmeDns(scope, identifiers);
                        return;

                    case "dns_nsupdate":
                        DescribeNsUpdate(validation);
                        break;

                    case "dns_gcloud":
                        MigrationDns.Describe(validation, MigrationCatalogue.GetAlias(MigrationCatalogue.AcmeShDnsAliases, method)!, [], o => o, o => o, o => o);
                        validation.AmbientAuthentication = "with the gcloud command line tool's signed in account";
                        break;

                    case var dns when dns.StartsWith("dns_", StringComparison.Ordinal):
                        if (MigrationCatalogue.GetAlias(MigrationCatalogue.AcmeShDnsAliases, dns) is { } alias)
                        {
                            DescribeDns(validation, alias);
                        }
                        else
                        {
                            validation.Kind = SourceValidationKinds.Dns;
                        }

                        break;

                    case "":
                        validation.Kind = SourceValidationKinds.Unknown;
                        validation.SourceName = "none";
                        break;

                    default:
                        validation.Kind = SourceValidationKinds.HttpFileSystem;
                        validation.SourceName = "Webroot";
                        validation.Parameters[SourceSettingNames.Path] = method;
                        break;
                }

                Description.Validations.Add(validation);
            }

            /// <summary>
            /// A saved DNS API setting: the domain's conf first, then account.conf, each as SAVED_name or name
            /// </summary>
            private (string? Value, string Source) Saved(string name)
            {
                foreach (var key in new[] { $"SAVED_{name}", name })
                {
                    if (_entry.Get(key) is { } own)
                    {
                        return (own, _entry.File.FullName);
                    }
                }

                foreach (var key in new[] { $"SAVED_{name}", name })
                {
                    if (_account.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                    {
                        return (value, _accountConfPath);
                    }
                }

                return (null, "");
            }

            private string AddSavedSecret(string name)
            {
                var (_, source) = Saved(name);
                return Secrets.Add($"{source}:{name}", $"{name} ({source})", source == _accountConfPath, () => Saved(name).Value is { } value ? (value, null) : (null, $"{name} is no longer saved"));
            }

            private string AddFileSecret(string path) =>
                Secrets.Add($"file:{path}", path, true, () =>
                {
                    try
                    {
                        return (File.ReadAllText(path), null);
                    }
                    catch (Exception exp)
                    {
                        return (null, exp.Message);
                    }
                });

            private void DescribeDns(SourceValidation validation, DnsProviderAlias alias)
            {
                var names = alias.Options.Keys.Concat(alias.AmbientAuthOptions).Concat(alias.FileOptions.Keys);
                var options = names.Select(n => new KeyValuePair<string, string>(n, Saved(n).Value ?? "")).Where(o => o.Value.Length > 0).ToList();

                MigrationDns.Describe(validation, alias, options, AddSavedSecret, AddFileSecret, _ => "with a managed identity");

                if (alias.Key == "route53" && !options.Any(o => o.Key == "AWS_ACCESS_KEY_ID"))
                {
                    validation.AmbientAuthentication = "with the AWS credentials of its environment or the machine's IAM role";
                }

                if (alias.Key == "azure")
                {
                    validation.Notes.Add("The Azure DNS provider here needs the resource group of the zone, which acme.sh finds itself. Set it on the migrated item.");
                }
            }

            private void DescribeNsUpdate(SourceValidation validation)
            {
                validation.Kind = SourceValidationKinds.Dns;
                validation.DnsProvider = "rfc2136";
                validation.SourceName = MigrationCatalogue.GetDnsProvider("rfc2136")!.Title;

                foreach (var (name, parameter) in new[] { ("NSUPDATE_SERVER", "DDNSNameserver"), ("NSUPDATE_SERVER_PORT", "DDNSPort"), ("NSUPDATE_ZONE", "DDNSZone") })
                {
                    if (Saved(name).Value is { } value)
                    {
                        validation.Parameters[parameter] = value;
                    }
                }

                // the TSIG key file holds the key's name, algorithm and secret
                var keyFile = Saved("NSUPDATE_KEY").Value;
                if (keyFile == null)
                {
                    return;
                }

                (Match? Key, string? Error) ReadKey()
                {
                    try
                    {
                        var match = Regex.Match(File.ReadAllText(keyFile), @"key\s+""?(?<name>[^""\s{]+)""?\s*\{[^}]*?algorithm\s+(?<algorithm>[\w-]+)\s*;[^}]*?secret\s+""(?<secret>[^""]+)""", RegexOptions.Singleline);
                        return match.Success ? (match, null) : (null, "it is not a TSIG key file");
                    }
                    catch (Exception exp)
                    {
                        return (null, exp.Message);
                    }
                }

                var (key, _) = ReadKey();
                if (key != null)
                {
                    validation.Parameters["DDNSKeyName"] = key.Groups["name"].Value;
                    validation.Parameters["DDNSKeyType"] = key.Groups["algorithm"].Value.ToLowerInvariant();
                }

                validation.SecretParameters["DDNSKeyValueInsecure"] = Secrets.Add($"file:{keyFile}:secret", $"TSIG key ({keyFile})", true, () =>
                {
                    var (current, error) = ReadKey();
                    return current == null ? (null, error) : (current.Groups["secret"].Value, null);
                });
            }

            private void DescribeAcmeDns(List<string>? scope, List<string> identifiers)
            {
                var baseUrl = Saved("ACMEDNS_BASE_URL").Value;

                // a registration per domain, given as space separated lists in the same order
                string? Part(string name, int index)
                {
                    var values = (Saved(name).Value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    return values.Length == 0 ? null : index < values.Length ? values[index] : values[^1];
                }

                for (var i = 0; i < identifiers.Count; i++)
                {
                    var identifier = identifiers[i];
                    var index = Description.Identifiers.IndexOf(identifier);

                    var validation = new SourceValidation { Kind = SourceValidationKinds.Dns, DnsProvider = "acme-dns", SourceName = "acme-dns", Identifiers = [identifier] };

                    if (baseUrl != null)
                    {
                        validation.Parameters["api"] = baseUrl;
                    }

                    validation.SecretParameters["credentials_json"] = Secrets.Add($"acme-dns:{identifier}", $"acme-dns registration for {identifier} ({_accountConfPath})", true, () =>
                    {
                        var (username, password, subdomain) = (Part("ACMEDNS_USERNAME", index), Part("ACMEDNS_PASSWORD", index), Part("ACMEDNS_SUBDOMAIN", index));

                        if (username == null || password == null || subdomain == null)
                        {
                            return (null, "the acme-dns registration is not saved");
                        }

                        var host = Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) ? uri.Host : "";
                        return (JsonSerializer.Serialize(new { username, password, subdomain, fulldomain = $"{subdomain}.{host}" }), null);
                    });

                    Description.Validations.Add(validation);
                }
            }

            // outputs and installation

            private void DescribeOutputs()
            {
                var output = new SourceOutput { Kind = SourceOutputKinds.Files, SourceName = "Installed files" };

                foreach (var (type, path) in RealPaths(_entry))
                {
                    output.Settings[type] = path;
                }

                if (!output.Settings.Any())
                {
                    Description.Unrecognised.Add(new SourceUnrecognised
                    {
                        Category = "Store",
                        Description = $"The certificate is not installed anywhere by {Tool} (acme.sh --install-cert). Anything reading {Tool}'s own copies in {_entry.Folder.FullName} needs a deployment task writing the files it reads, as those copies are no longer updated."
                    });
                }

                Description.Outputs.Add(output);
            }

            private void DescribeInstallations()
            {
                var index = 0;

                if (Get("Le_ReloadCmd") is { } reload)
                {
                    AddCommand(index++, "Reload command", reload, $"\"{reload}\" runs after each renewal, given CERT_PATH and the other paths as {Tool} does.", true);
                }

                if (Get("Le_RenewHook") is { } renew)
                {
                    AddCommand(index++, "Renew hook", renew, $"\"{renew}\" runs after each renewal.", true);
                }

                if (Get("Le_PostHook") is { } post)
                {
                    AddCommand(index++, "Post hook", post, $"\"{post}\" runs after each renewal.", false);
                }

                if (Get("Le_PreHook") is { } pre)
                {
                    Description.UnmappedSettings.Add($"The pre hook \"{pre}\" ran before {Tool} renewed, e.g. to free port 80. It is not migrated.");
                }

                foreach (var hook in (Get("Le_DeployHook") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    Description.Unrecognised.Add(new SourceUnrecognised
                    {
                        Category = "Installation",
                        Description = $"The {Tool} deploy hook {hook} is not migrated. Add a deployment task doing the same to the item before cut over."
                    });
                }
            }

            private void AddCommand(int index, string title, string command, string description, bool withPaths)
            {
                var installation = new SourceInstallation { Kind = SourceInstallationKinds.Script, SourceName = title };
                installation.Settings[SourceSettingNames.Script] = command;
                installation.Settings[SourceSettingNames.Description] = description;

                static string Literal(string value) => $"'{value.Replace("'", "''")}'";

                var real = RealPaths(_entry);
                var environment = withPaths
                    ? new[]
                    {
                        ("CERT_PATH", Literal(real.GetValueOrDefault("pemcrt") ?? FolderFile($"{Domain}.cer"))),
                        ("CERT_KEY_PATH", Literal(real.GetValueOrDefault("pemkey") ?? FolderFile($"{Domain}.key"))),
                        ("CA_CERT_PATH", Literal(real.GetValueOrDefault("pemintermediates") ?? FolderFile("ca.cer"))),
                        ("CERT_FULLCHAIN_PATH", Literal(real.GetValueOrDefault("pemcrtpartialchain") ?? FolderFile("fullchain.cer"))),
                        ("Le_Domain", Literal(Domain))
                    }
                    : [];

                if (withPaths && real.Count < 4)
                {
                    installation.Notes.Add($"Paths {Tool} did not install the certificate to are given as {Tool}'s own copies, which are no longer updated.");
                }

                installation.SecretSettings[SourceSettingNames.ScriptWrapper] = Secrets.Add($"{_entry.Folder.Name}:install{index}", $"wrapper for {command}", false, () =>
                    (MigrationScripts.WriteCommandTask(MigrationScripts.WrapperPath("acme.sh", _entry.Folder.Name, $"install{index}", ".ps1"),
                        $"Created by Certify The Web from acme.sh certificate {_entry.Folder.Name}. Runs \"{command}\" as acme.sh did after renewing.", command, environment), null),
                    isGenerated: true, check: () => null);

                Description.Installations.Add(installation);
            }

            // account and certificate

            /// <summary>
            /// The CA's folder, ca/{host}/{path} of the directory URL, or ca/{host} as older versions used
            /// </summary>
            private string? CaFolder()
            {
                if (!Uri.TryCreate(Server, UriKind.Absolute, out var uri))
                {
                    return null;
                }

                var root = Path.Combine(_tool._settingsPath, "ca", uri.Host);
                var withPath = Path.Combine(root, uri.AbsolutePath.Trim('/').Replace('/', Path.DirectorySeparatorChar));
                return Directory.Exists(withPath) ? withPath : Directory.Exists(root) ? root : null;
            }

            public SourceAccountMaterial? ReadAccount(out string description)
            {
                try
                {
                    var folder = CaFolder();
                    if (folder == null)
                    {
                        description = $"no account for {Server} was found in {Path.Combine(_tool._settingsPath, "ca")}";
                        return null;
                    }

                    var keyFile = Path.Combine(folder, "account.key");
                    var caConf = ParseConf(File.ReadAllText(Path.Combine(folder, "ca.conf")));

                    if (!caConf.TryGetValue("ACCOUNT_URL", out var url) || string.IsNullOrWhiteSpace(url))
                    {
                        description = $"{folder}/ca.conf does not include the account URL";
                        return null;
                    }

                    var keyPem = MigrationFiles.NormalizeKeyPem(File.ReadAllText(keyFile));

                    Description.AccountReadable = true;
                    description = url;
                    return new SourceAccountMaterial
                    {
                        AccountUri = url,
                        AccountKeyPem = keyPem,
                        EmailAddress = caConf.GetValueOrDefault("CA_EMAIL") ?? _account.GetValueOrDefault("ACCOUNT_EMAIL")
                    };
                }
                catch (Exception exp) when (exp is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
                {
                    description = $"the account files could not be read: {exp.Message}";
                    return null;
                }
            }

            public SourceCertificateMaterial? ReadCertificate(bool keepData, out string? note) =>
                MigrationFiles.LoadPemCertificate(Description, Tool, FolderFile($"{Domain}.cer"), FolderFile($"{Domain}.key"), FolderFile("ca.cer"), _item?.CertificateThumbprintHash, keepData, out note);
        }
    }
}
