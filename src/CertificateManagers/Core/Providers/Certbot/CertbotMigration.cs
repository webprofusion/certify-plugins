using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Migration;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Providers.CertificateManagers;

namespace Certify.Plugin.CertificateManagers.Providers.Certbot
{
    /// <summary>
    /// Migration of certbot lineages. Reads a renewal configuration and everything it refers to (credentials file, hooks,
    /// account and live certificate) into a <see cref="SourceRenewalDescription"/>. Cut over turns the lineage's
    /// autorenew off, which certbot provides for this, so the lineage stays listed but is no longer renewed
    /// </summary>
    public partial class Certbot : ICertificateManagerMigrationSource
    {
        /// <summary>
        /// Written above the autorenew setting at cut over, recording its previous value so rollback can restore it
        /// </summary>
        internal const string MigratedMarker = "# certify-migrated: autorenew was ";
        private const string UnsetValue = "unset";
        private const string ArchiveFolder = "archive";
        private const string DefaultServer = "https://acme-v02.api.letsencrypt.org/directory";

        internal static string ItemIdFor(string lineageName) =>
            $"{ManagedCertificate.ExternalItemIdPrefix}certbot-{Certify.Management.Util.ToUrlSafeBase64String(lineageName)}";

        public MigrationSourceCapabilities GetMigrationCapabilities() => new()
        {
            DisableMethod = "Sets autorenew = False in the certificate's renewal configuration, so certbot renew skips it",
            DisabledItemHiddenFromMonitoring = false,
            CanDisableSingleItem = true,
            RequiresIdleTool = true
        };

        public async Task<ExternalMigrationPlan?> PrepareMigrationPlan(string itemId, ExternalMigrationContext context, IDictionary<string, string>? inputs)
        {
            var reader = await GetReader(itemId);
            return reader == null ? null : MigrationPlanMapper.Map(reader.Description, context, inputs);
        }

        public async Task<Dictionary<string, string>> ResolveCredentialValues(string itemId, ExternalMigrationCredentialDraft draft)
        {
            var reader = await GetReader(itemId) ?? throw new InvalidOperationException("The certbot lineage could not be found.");
            return reader.Secrets.Resolve(draft);
        }

        public async Task<SourceCertificateMaterial?> GetCurrentCertificate(string itemId)
        {
            var reader = await GetReader(itemId);
            return reader?.ReadCertificate(keepData: true, out _);
        }

        public async Task<SourceAccountMaterial?> GetAccount(string itemId)
        {
            var reader = await GetReader(itemId);
            return reader?.ReadAccount(out _);
        }

        public async Task<SourceChangeResult> DisableSourceItem(string itemId)
        {
            var lineage = await FindLineage(itemId);
            if (lineage == null)
            {
                return new SourceChangeResult(false, "The certbot lineage could not be found.");
            }

            if (lineage.AutoRenewOff)
            {
                return new SourceChangeResult(true, "Automatic renewal is already off for this certificate in certbot.");
            }

            return WhenCertbotIdle(() =>
            {
                File.WriteAllText(lineage.File.FullName, SetAutoRenewOff(lineage.Text));
                return new SourceChangeResult(true, $"Set autorenew = False in {lineage.File.FullName}, so certbot no longer renews it.");
            });
        }

        public async Task<SourceChangeResult> RestoreSourceItem(string itemId)
        {
            var lineage = await FindLineage(itemId);
            if (lineage == null)
            {
                return new SourceChangeResult(false, "The certbot lineage could not be found.");
            }

            if (!lineage.DisabledByMigration)
            {
                return new SourceChangeResult(true, lineage.AutoRenewOff
                    ? "Automatic renewal was turned off in certbot before the migration, so it is left off."
                    : "Automatic renewal is already on for this certificate in certbot.");
            }

            return WhenCertbotIdle(() =>
            {
                File.WriteAllText(lineage.File.FullName, RestoreAutoRenew(lineage.Text));
                return new SourceChangeResult(true, $"Restored the autorenew setting in {lineage.File.FullName}, so certbot renews it again.");
            });
        }

        public async Task<SourceRemovalManifest> PlanSourceRemoval(string itemId)
        {
            var manifest = new SourceRemovalManifest { SourceItemId = itemId };

            var lineage = await FindLineage(itemId);
            if (lineage == null)
            {
                manifest.BlockedReason = "The certbot lineage could not be found.";
                return manifest;
            }

            if (!lineage.AutoRenewOff)
            {
                manifest.BlockedReason = "Automatic renewal is on in certbot again, so the lineage is not removed. Cut over again first.";
            }

            var live = LivePaths(lineage);
            var linked = live.Values
                .Select(p => ResolveLink(p))
                .Where(p => p != null)
                .Select(p => p!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            manifest.FilesToDelete.Add(lineage.File.FullName);

            var archive = ArchivePath(lineage);
            if (Directory.Exists(archive))
            {
                manifest.FilesToDelete.AddRange(Directory.GetFiles(archive).Where(f => !linked.Contains(Path.GetFullPath(f))).OrderBy(f => f));
            }

            var liveFolder = Path.GetDirectoryName(live["cert"]);
            manifest.Kept.Add($"{liveFolder} and the files in {archive} it links to, which services read and the migrated item now writes");
            manifest.Kept.Add("certbot's accounts, cli.ini, credentials files and hooks, which other certificates may use");
            manifest.Kept.Add("certbot's scheduled renewal (systemd timer or cron), which renews any other certificates");

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

            return WhenCertbotIdle(() =>
            {
                foreach (var file in manifest.FilesToDelete.Where(File.Exists))
                {
                    File.Delete(file);
                }

                return new SourceChangeResult(true, $"Deleted the certbot renewal configuration and {manifest.FilesToDelete.Count - 1} superseded archive file{(manifest.FilesToDelete.Count == 2 ? "" : "s")}.");
            });
        }

        private static SourceChangeResult WhenCertbotIdle(Func<SourceChangeResult> action)
        {
            if (MigrationFiles.IsProcessRunning("certbot"))
            {
                return new SourceChangeResult(false, "certbot is running. Try again when it has finished.");
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

        // the renewal configuration

        internal sealed class Lineage
        {
            public FileInfo File { get; init; } = default!;
            public string Name { get; init; } = string.Empty;
            public string Text { get; init; } = string.Empty;
            public string Hash { get; init; } = string.Empty;

            /// <summary>
            /// Settings by section: "" for the top level, renewalparams and webroot_map
            /// </summary>
            public Dictionary<string, Dictionary<string, string>> Sections { get; init; } = new();

            public Dictionary<string, string> Top => Sections.GetValueOrDefault("") ?? new();
            public Dictionary<string, string> Params => Sections.GetValueOrDefault("renewalparams") ?? new(StringComparer.OrdinalIgnoreCase);

            public bool AutoRenewOff => Params.TryGetValue("autorenew", out var value) && FalseValues.Contains(value.Trim());
            public bool DisabledByMigration => Text.Split('\n').Any(l => l.TrimStart().StartsWith(MigratedMarker, StringComparison.Ordinal));
        }

        internal async Task<Lineage?> FindLineage(string itemId)
        {
            if (!await IsPresent())
            {
                return null;
            }

            var folder = new DirectoryInfo(Path.Combine(_settingsPath, RenewalFolder));
            if (!folder.Exists)
            {
                return null;
            }

            foreach (var file in folder.GetFiles(ConfigFilePattern, SearchOption.AllDirectories))
            {
                var name = file.Name.Replace(".conf", string.Empty);
                if (ItemIdFor(name) != itemId)
                {
                    continue;
                }

                var bytes = await File.ReadAllBytesAsync(file.FullName);
                var text = Encoding.UTF8.GetString(bytes);

                return new Lineage
                {
                    File = file,
                    Name = name,
                    Text = text,
                    Hash = MigrationFiles.FileHash(bytes),
                    Sections = ParseConfig(text)
                };
            }

            return null;
        }

        private async Task<LineageReader?> GetReader(string itemId)
        {
            var lineage = await FindLineage(itemId);
            if (lineage == null)
            {
                return null;
            }

            var item = (await GetManagedCertificates()).FirstOrDefault(i => i.Id == itemId);
            var reader = new LineageReader(this, lineage, item);
            reader.Describe();
            return reader;
        }

        /// <summary>
        /// Settings of a configobj file as certbot writes them, by section. Comments are dropped and quotes removed
        /// </summary>
        internal static Dictionary<string, Dictionary<string, string>> ParseConfig(string text)
        {
            var sections = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase) { [""] = new(StringComparer.OrdinalIgnoreCase) };
            var current = sections[""];

            foreach (var raw in text.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                {
                    continue;
                }

                if (line.StartsWith('['))
                {
                    var name = line.Trim('[', ']', ' ');
                    if (!sections.TryGetValue(name, out current!))
                    {
                        current = sections[name] = new(StringComparer.OrdinalIgnoreCase);
                    }

                    continue;
                }

                var equals = line.IndexOf('=');
                if (equals <= 0)
                {
                    continue;
                }

                current[line[..equals].Trim()] = Unquote(StripComment(line[(equals + 1)..]).Trim());
            }

            return sections;
        }

        private static string StripComment(string value)
        {
            char? quote = null;

            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                if (quote == null && c is '"' or '\'')
                {
                    quote = c;
                }
                else if (c == quote)
                {
                    quote = null;
                }
                else if (quote == null && c == '#')
                {
                    return value[..i];
                }
            }

            return value;
        }

        private static string Unquote(string value) =>
            value.Length >= 2 && ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')) ? value[1..^1] : value;

        /// <summary>
        /// The items of a configobj list value, e.g. "/var/www/html, /var/www/other,"
        /// </summary>
        internal static List<string> ListValue(string? value) =>
            (value ?? "").Split(',').Select(v => Unquote(v.Trim())).Where(v => v.Length > 0).ToList();

        private static string LineBreak(string text) => text.Contains("\r\n") ? "\r\n" : "\n";

        /// <summary>
        /// The configuration with autorenew turned off in renewalparams, recording the previous value above it
        /// </summary>
        internal static string SetAutoRenewOff(string text)
        {
            var newline = LineBreak(text);
            var lines = text.Replace("\r\n", "\n").Split('\n').ToList();
            var header = lines.FindIndex(l => string.Equals(l.Trim(), "[renewalparams]", StringComparison.OrdinalIgnoreCase));

            if (header < 0)
            {
                if (lines.Count > 0 && lines[^1].Length == 0)
                {
                    lines.RemoveAt(lines.Count - 1);
                }

                lines.AddRange(["[renewalparams]", MigratedMarker + UnsetValue, "autorenew = False", ""]);
                return string.Join(newline, lines);
            }

            // settings of renewalparams come before its first subsection or the next section
            var end = lines.FindIndex(header + 1, l => l.TrimStart().StartsWith('['));
            end = end < 0 ? lines.Count : end;

            var existing = lines.FindIndex(header + 1, end - header - 1, l => l.Split('=', 2)[0].Trim().Equals("autorenew", StringComparison.OrdinalIgnoreCase));

            if (existing >= 0)
            {
                var previous = Unquote(StripComment(lines[existing].Split('=', 2)[1]).Trim());
                lines[existing] = "autorenew = False";
                lines.Insert(existing, MigratedMarker + previous);
            }
            else
            {
                lines.InsertRange(header + 1, [MigratedMarker + UnsetValue, "autorenew = False"]);
            }

            return string.Join(newline, lines);
        }

        /// <summary>
        /// The configuration with autorenew as it was before <see cref="SetAutoRenewOff"/>
        /// </summary>
        internal static string RestoreAutoRenew(string text)
        {
            var newline = LineBreak(text);
            var lines = text.Replace("\r\n", "\n").Split('\n').ToList();
            var marker = lines.FindIndex(l => l.TrimStart().StartsWith(MigratedMarker, StringComparison.Ordinal));

            if (marker < 0)
            {
                return text;
            }

            var previous = lines[marker].TrimStart()[MigratedMarker.Length..].Trim();
            var setting = lines.FindIndex(marker + 1, l => l.Split('=', 2)[0].Trim().Equals("autorenew", StringComparison.OrdinalIgnoreCase));

            if (setting >= 0)
            {
                if (previous == UnsetValue)
                {
                    lines.RemoveAt(setting);
                }
                else
                {
                    lines[setting] = $"autorenew = {previous}";
                }
            }

            lines.RemoveAt(marker);
            return string.Join(newline, lines);
        }

        /// <summary>
        /// The lineage's live files by name (cert, privkey, chain, fullchain)
        /// </summary>
        private Dictionary<string, string> LivePaths(Lineage lineage)
        {
            var folder = Path.Combine(_settingsPath, LiveFolder, lineage.Name);

            return new[] { "cert", "privkey", "chain", "fullchain" }.ToDictionary(n => n, n =>
            {
                var configured = lineage.Top.GetValueOrDefault(n);
                return string.IsNullOrWhiteSpace(configured) ? Path.Combine(folder, $"{n}.pem") : Path.IsPathRooted(configured) ? configured : Path.Combine(_settingsPath, configured);
            });
        }

        private string ArchivePath(Lineage lineage)
        {
            var configured = lineage.Top.GetValueOrDefault("archive_dir");
            return string.IsNullOrWhiteSpace(configured) ? Path.Combine(_settingsPath, ArchiveFolder, lineage.Name) : configured;
        }

        /// <summary>
        /// The file a live symlink points to, or null if the path is not a link
        /// </summary>
        private static string? ResolveLink(string path)
        {
            try
            {
                var target = new FileInfo(path).LinkTarget;
                return target == null ? null : Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, target));
            }
            catch (IOException)
            {
                return null;
            }
        }

        /// <summary>
        /// Reads one lineage and everything it depends on into a description
        /// </summary>
        internal sealed class LineageReader
        {
            private readonly Certbot _tool;
            private readonly Lineage _lineage;
            private readonly ManagedCertificate? _item;
            private readonly Dictionary<string, string> _live;

            public SourceRenewalDescription Description { get; } = new();
            public MigrationSecrets Secrets { get; }

            public LineageReader(Certbot tool, Lineage lineage, ManagedCertificate? item)
            {
                _tool = tool;
                _lineage = lineage;
                _item = item;
                _live = tool.LivePaths(lineage);
                Secrets = new MigrationSecrets(Description);
            }

            private static string Tool => Definition.Title;
            private Dictionary<string, string> Params => _lineage.Params;
            private string? Param(string name) => Params.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) && value != "None" ? value : null;
            private bool IsTrue(string name) => Param(name) is { } value && !FalseValues.Contains(value);

            public void Describe()
            {
                var d = Description;
                d.ProviderId = Definition.Id;
                d.ProviderTitle = Tool;
                d.ItemId = ItemIdFor(_lineage.Name);
                d.Name = _lineage.Name;
                d.RenewalId = _lineage.Name;
                d.SourcePath = _lineage.File.FullName;
                d.FileHash = _lineage.Hash;
                d.CaEndpoints = [Param("server") ?? DefaultServer];

                DescribeIdentifiers();
                DescribeRequest();
                DescribeValidations();
                DescribeOutputs();
                DescribeInstallations();
                DescribeSettings();

                if (_item?.LastRenewalStatus == RequestState.Error && !string.IsNullOrWhiteSpace(_item.RenewalFailureMessage))
                {
                    d.LastRunErrors.Add(_item.RenewalFailureMessage!);
                }

                ReadAccount(out var accountDescription);
                d.AccountDescription = accountDescription;

                ReadCertificate(keepData: false, out var note);
                d.CurrentCertificateNote = note;
            }

            private void DescribeIdentifiers()
            {
                var d = Description;

                if (File.Exists(_live["cert"]))
                {
                    try
                    {
                        using var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(_live["cert"]);
                        d.Identifiers = GetCertificateDomains(certificate);
                        d.IdentifierSource = "certificate";
                    }
                    catch (Exception)
                    {
                        // falls back to the webroot map below
                    }
                }

                if (!d.Identifiers.Any() && _lineage.Sections.TryGetValue("webroot_map", out var map))
                {
                    d.Identifiers = map.Keys.ToList();
                    d.IdentifierSource = "renewal";
                }
            }

            private void DescribeRequest()
            {
                var d = Description;

                switch (Param("key_type")?.ToLowerInvariant())
                {
                    case "ecdsa":
                        d.KeyType = "ec";
                        d.EcCurve = Param("elliptic_curve") ?? "secp256r1";
                        break;

                    case "rsa":
                        d.KeyType = "rsa";
                        d.RsaKeyBits = int.TryParse(Param("rsa_key_size"), out var bits) ? bits : 2048;
                        break;

                    default:
                        // certbot before 2.0 did not record the key type, and created RSA keys of rsa_key_size bits
                        if (Param("rsa_key_size") is { } size && int.TryParse(size, out var rsaBits))
                        {
                            d.KeyType = "rsa";
                            d.RsaKeyBits = rsaBits;
                        }
                        else
                        {
                            MigrationFiles.DescribeKeyFromCertificate(d, _live["cert"]);
                        }

                        break;
                }

                d.ReusePrivateKey = IsTrue("reuse_key");
                d.OcspMustStaple = IsTrue("must_staple");
                d.PreferredIssuer = Param("preferred_chain");
                d.CertificateProfile = Param("required_profile") ?? Param("preferred_profile");

                if (_lineage.Top.GetValueOrDefault("renew_before_expiry") is { Length: > 0 } before)
                {
                    var parts = before.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    if (parts.Length == 2 && int.TryParse(parts[0], out var count) && parts[1].StartsWith("day", StringComparison.OrdinalIgnoreCase))
                    {
                        d.RenewBeforeExpiryDays = count;
                    }
                    else if (parts.Length == 2 && int.TryParse(parts[0], out var weeks) && parts[1].StartsWith("week", StringComparison.OrdinalIgnoreCase))
                    {
                        d.RenewBeforeExpiryDays = weeks * 7;
                    }
                    else
                    {
                        d.UnmappedSettings.Add($"renew_before_expiry = {before} is not in days, so this instance's renewal interval is used.");
                    }
                }

                if (IsTrue("allow_subset_of_names"))
                {
                    d.UnmappedSettings.Add($"{Tool} is set to renew with the names it can still validate (allow_subset_of_names). Renewals here need every name to validate.");
                }
            }

            // validation

            private void DescribeValidations()
            {
                var authenticator = Param("authenticator") ?? "";

                // plugins installed from other packages may be recorded as "package:name"
                authenticator = authenticator[(authenticator.LastIndexOf(':') + 1)..];

                switch (authenticator)
                {
                    case "webroot":
                        DescribeWebroot();
                        return;

                    case "standalone":
                        {
                            var validation = new SourceValidation { Kind = SourceValidationKinds.HttpSelfHosting, SourceName = "Standalone" };
                            validation.Parameters["Port"] = Param("http01_port") ?? "80";
                            Description.Validations.Add(validation);
                            return;
                        }

                    case "nginx":
                    case "apache":
                        {
                            var validation = new SourceValidation { Kind = SourceValidationKinds.HttpSelfHosting, SourceName = authenticator };
                            validation.Notes.Add($"{Tool} answered http-01 challenges through {authenticator}'s own configuration. The http challenge server here needs port 80, which {authenticator} holds, so change the migrated item to a challenge folder {authenticator} serves at /.well-known/acme-challenge/, or to DNS validation, before cut over.");
                            Description.Validations.Add(validation);
                            return;
                        }

                    case "manual":
                        DescribeManual();
                        return;
                }

                if (MigrationCatalogue.GetAlias(MigrationCatalogue.CertbotDnsAliases, authenticator) is { } alias)
                {
                    DescribeDns(authenticator, alias);
                    return;
                }

                Description.Validations.Add(new SourceValidation
                {
                    Kind = authenticator.StartsWith("dns-", StringComparison.Ordinal) ? SourceValidationKinds.Dns : SourceValidationKinds.Unknown,
                    SourceName = authenticator.Length == 0 ? "none" : authenticator
                });
            }

            private void DescribeWebroot()
            {
                var map = _lineage.Sections.GetValueOrDefault("webroot_map") ?? new();
                var defaultPath = ListValue(Param("webroot_path")).FirstOrDefault();

                var byPath = Description.Identifiers
                    .Select(i => (Identifier: i, Path: map.GetValueOrDefault(i) ?? defaultPath))
                    .GroupBy(i => i.Path ?? "")
                    .ToList();

                foreach (var group in byPath)
                {
                    var validation = new SourceValidation
                    {
                        Kind = SourceValidationKinds.HttpFileSystem,
                        SourceName = "Webroot",
                        Identifiers = byPath.Count > 1 ? group.Select(g => g.Identifier).ToList() : null
                    };

                    if (group.Key.Length > 0)
                    {
                        validation.Parameters[SourceSettingNames.Path] = group.Key;
                    }

                    Description.Validations.Add(validation);
                }
            }

            private void DescribeManual()
            {
                var isDns = ListValue(Param("pref_challs")).Any(c => c.Equals("dns-01", StringComparison.OrdinalIgnoreCase));
                var auth = Param("manual_auth_hook");
                var cleanup = Param("manual_cleanup_hook");

                if (!isDns)
                {
                    Description.Validations.Add(new SourceValidation
                    {
                        Kind = auth == null ? SourceValidationKinds.Unknown : SourceValidationKinds.HttpUnsupported,
                        SourceName = auth == null ? "Manual http-01" : "a manual hook"
                    });
                    return;
                }

                if (auth == null)
                {
                    Description.Validations.Add(new SourceValidation { Kind = SourceValidationKinds.Manual, SourceName = "Manual" });
                    return;
                }

                var validation = new SourceValidation { Kind = SourceValidationKinds.Dns, DnsProvider = "script", SourceName = "Manual hook" };
                validation.Notes.Add("The hooks are given CERTBOT_DOMAIN and CERTBOT_VALIDATION for one name at a time. CERTBOT_REMAINING_CHALLENGES is always 0 and CERTBOT_AUTH_OUTPUT is empty.");
                validation.SecretParameters["createscriptpath"] = AddDnsHook("auth", auth);

                if (cleanup != null)
                {
                    validation.SecretParameters["deletescriptpath"] = AddDnsHook("cleanup", cleanup);
                }

                Description.Validations.Add(validation);
            }

            private string AddDnsHook(string name, string command) =>
                Secrets.Add($"{_lineage.Name}:hook-{name}", $"wrapper for {command}", false, () =>
                {
                    var path = MigrationScripts.WriteDnsHook(MigrationScripts.WrapperPath("certbot", _lineage.Name, $"dns-{name}", ""),
                        $"Created by Certify The Web from certbot lineage {_lineage.Name}. Runs the manual {name} hook as certbot did.", command,
                        [("CERTBOT_DOMAIN", "$IDENTIFIER"), ("CERTBOT_VALIDATION", "$VALUE"), ("CERTBOT_ALL_DOMAINS", "$IDENTIFIER"), ("CERTBOT_REMAINING_CHALLENGES", "0"), ("CERTBOT_AUTH_OUTPUT", "")]);
                    return (path, null);
                }, isGenerated: true, check: () => null);

            private void DescribeDns(string authenticator, DnsProviderAlias alias)
            {
                var validation = new SourceValidation();
                var prefix = authenticator.Replace('-', '_');

                if (Param($"{prefix}_propagation_seconds") is { } propagation)
                {
                    validation.Parameters["propagationdelay"] = propagation;
                }

                if (authenticator == "dns-route53")
                {
                    MigrationDns.Describe(validation, alias, [], o => o, o => o, o => o);
                    validation.AmbientAuthentication = "with the AWS credentials it finds itself (environment variables, ~/.aws/credentials or the machine's IAM role)";
                    Description.Validations.Add(validation);
                    return;
                }

                var credentialsFile = Param($"{prefix}_credentials");

                if (authenticator == "dns-google")
                {
                    // the credentials setting is the service account key file itself, which the provider here reads
                    MigrationDns.Describe(validation, alias, [], o => o, o => o, o => o);

                    if (credentialsFile == null)
                    {
                        validation.AmbientAuthentication = "with the machine's Google Cloud service account";
                    }
                    else
                    {
                        validation.Parameters["GCKeyFile"] = credentialsFile;

                        try
                        {
                            using var key = JsonDocument.Parse(File.ReadAllText(credentialsFile));
                            if (key.RootElement.TryGetProperty("project_id", out var project))
                            {
                                validation.Parameters["GCProjectId"] = project.GetString() ?? "";
                            }
                        }
                        catch (Exception exp)
                        {
                            validation.Notes.Add($"The project could not be read from {credentialsFile}: {exp.Message}. Set it on the migrated item.");
                        }
                    }

                    Description.Validations.Add(validation);
                    return;
                }

                if (credentialsFile == null)
                {
                    MigrationDns.Describe(validation, alias, [], o => o, o => o, o => o);
                    Description.Unrecognised.Add(new SourceUnrecognised { Category = "Validation", Description = $"The {authenticator} credentials file is not set in the renewal configuration.", IsBlocker = true });
                    Description.Validations.Add(validation);
                    return;
                }

                (Dictionary<string, string>? Values, string? Error) ReadCredentials()
                {
                    try
                    {
                        return (ParseConfig(File.ReadAllText(credentialsFile)).GetValueOrDefault("") ?? new(), null);
                    }
                    catch (Exception exp)
                    {
                        return (null, exp.Message);
                    }
                }

                var (values, error) = ReadCredentials();

                // an unreadable file makes every option it should hold unreadable, so the preview asks for a credential instead
                var options = values?.ToList() ?? alias.Options.Where(o => o.Value.Length > 0 && !alias.ValueMaps.ContainsKey(o.Value)).Select(o => new KeyValuePair<string, string>(o.Key, "?")).ToList();

                MigrationDns.Describe(validation, alias, options,
                    option => Secrets.Add($"{credentialsFile}:{option}", $"{option} ({credentialsFile})", true, () =>
                    {
                        var (current, readError) = ReadCredentials();
                        return current == null ? (null, readError) : current.TryGetValue(option, out var value) ? (value, null) : (null, $"{option} is no longer set");
                    }),
                    path => path,
                    option => option);

                if (error != null)
                {
                    validation.Notes.Add($"{credentialsFile} could not be read: {error}");
                }

                Description.Validations.Add(validation);
            }

            // outputs and installation

            private void DescribeOutputs()
            {
                var output = new SourceOutput { Kind = SourceOutputKinds.Files, SourceName = "Live files" };
                output.Settings["pemcrt"] = _live["cert"];
                output.Settings["pemintermediates"] = _live["chain"];
                output.Settings["pemcrtpartialchain"] = _live["fullchain"];
                output.Settings["pemkey"] = _live["privkey"];

                if (_live.Values.Any(p => ResolveLink(p) != null))
                {
                    output.Notes.Add($"The files in {Path.GetDirectoryName(_live["cert"])} link to {Tool}'s archive folder, and are written through those links, so their owner and permissions stay as they are.");
                }

                Description.Outputs.Add(output);
            }

            private void DescribeInstallations()
            {
                var installer = Param("installer");
                var index = 0;

                if (installer is "nginx" or "apache")
                {
                    var command = installer == "nginx" ? "nginx -s reload" : File.Exists("/usr/sbin/apache2ctl") ? "apache2ctl graceful" : "apachectl graceful";
                    AddCommand(index++, installer, command, $"{Tool}'s {installer} installer set {installer} up to use the files above. After each renewal {installer} is reloaded with \"{command}\", as {Tool} does.", false);
                }
                else if (installer != null && installer != "null")
                {
                    Description.Installations.Add(new SourceInstallation { Kind = SourceInstallationKinds.Unknown, SourceName = installer });
                }

                foreach (var (setting, title) in new[] { ("deploy_hook", "Deploy hook"), ("renew_hook", "Deploy hook"), ("post_hook", "Post hook") })
                {
                    if (Param(setting) is { } command)
                    {
                        AddCommand(index++, title, command, $"\"{command}\" runs after each renewal{(setting == "post_hook" ? "" : $", given RENEWED_LINEAGE and RENEWED_DOMAINS as {Tool} does")}.", setting != "post_hook");
                    }
                }

                if (Param("pre_hook") is { } pre)
                {
                    Description.UnmappedSettings.Add($"The pre hook \"{pre}\" ran before {Tool} renewed, e.g. to free port 80. It is not migrated.");
                }

                // certbot runs the scripts in its renewal-hooks folders for every certificate
                foreach (var stage in new[] { "deploy", "post", "pre" })
                {
                    var folder = Path.Combine(_tool._settingsPath, "renewal-hooks", stage);
                    var scripts = Directory.Exists(folder)
                        ? Directory.GetFiles(folder).Where(f => !Path.GetFileName(f).StartsWith('.') && !Path.GetFileName(f).StartsWith("README", StringComparison.OrdinalIgnoreCase)).OrderBy(f => f).ToList()
                        : [];

                    foreach (var script in scripts)
                    {
                        if (stage == "pre")
                        {
                            Description.UnmappedSettings.Add($"{script} runs before {Tool} renews any certificate. It is not migrated.");
                        }
                        else
                        {
                            AddCommand(index++, $"{stage} hook", script, $"{script}, which {Tool} runs after renewing any certificate, runs after each renewal{(stage == "deploy" ? ", given RENEWED_LINEAGE and RENEWED_DOMAINS" : "")}.", stage == "deploy");
                        }
                    }
                }
            }

            private void AddCommand(int index, string title, string command, string description, bool withRenewedVariables)
            {
                var installation = new SourceInstallation { Kind = SourceInstallationKinds.Script, SourceName = title };
                installation.Settings[SourceSettingNames.Script] = command;
                installation.Settings[SourceSettingNames.Description] = description;

                var environment = withRenewedVariables
                    ? new[] { ("RENEWED_LINEAGE", $"'{Path.GetDirectoryName(_live["cert"])!.Replace("'", "''")}'"), ("RENEWED_DOMAINS", "@($item.RequestConfig.SubjectAlternativeNames) -join ' '") }
                    : [];

                installation.SecretSettings[SourceSettingNames.ScriptWrapper] = Secrets.Add($"{_lineage.Name}:install{index}", $"wrapper for {command}", false, () =>
                    (MigrationScripts.WriteCommandTask(MigrationScripts.WrapperPath("certbot", _lineage.Name, $"install{index}", ".ps1"),
                        $"Created by Certify The Web from certbot lineage {_lineage.Name}. Runs \"{command}\" as certbot did after renewing.", command, environment), null),
                    isGenerated: true, check: () => null);

                Description.Installations.Add(installation);
            }

            private void DescribeSettings()
            {
                // certbot also reads cli.ini at every run, which can change what a renewal does
                foreach (var cli in new[] { Path.Combine(_tool._settingsPath, "cli.ini"), ConfigLocatorHome(".config/letsencrypt/cli.ini") })
                {
                    if (cli == null || !File.Exists(cli))
                    {
                        continue;
                    }

                    try
                    {
                        var keys = ParseConfig(File.ReadAllText(cli)).GetValueOrDefault("")?.Keys.ToList() ?? [];
                        if (keys.Any())
                        {
                            Description.SettingsAssumed = true;
                            Description.SettingsNotes.Add($"{Tool} also reads {cli} at each run, setting {string.Join(", ", keys)}. These are not migrated.");
                        }
                    }
                    catch (Exception exp)
                    {
                        Description.SettingsNotes.Add($"{cli} could not be read: {exp.Message}.");
                    }
                }
            }

            private static string? ConfigLocatorHome(string relative) => ConfigLocator.ExpandHome("~/" + relative);

            // account and certificate

            public SourceAccountMaterial? ReadAccount(out string description)
            {
                var accountId = Param("account");
                var accounts = Path.Combine(_tool._settingsPath, "accounts");

                try
                {
                    if (accountId == null || !Directory.Exists(accounts))
                    {
                        description = "the renewal does not name its account";
                        return null;
                    }

                    var folder = Directory.GetDirectories(accounts, accountId, SearchOption.AllDirectories).FirstOrDefault();
                    if (folder == null)
                    {
                        description = $"the account {accountId} was not found in {accounts}";
                        return null;
                    }

                    var keyPem = MigrationFiles.ConvertJwkToPem(File.ReadAllText(Path.Combine(folder, "private_key.json")));

                    using var registration = JsonDocument.Parse(File.ReadAllText(Path.Combine(folder, "regr.json")));
                    var uri = registration.RootElement.TryGetProperty("uri", out var u) ? u.GetString() : null;

                    if (string.IsNullOrWhiteSpace(uri))
                    {
                        description = $"{folder}/regr.json does not include the account URL";
                        return null;
                    }

                    string? email = null;
                    if (registration.RootElement.TryGetProperty("body", out var body) && body.TryGetProperty("contact", out var contact) && contact.ValueKind == JsonValueKind.Array)
                    {
                        email = contact.EnumerateArray().Select(c => c.GetString()).FirstOrDefault(c => c?.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) == true)?["mailto:".Length..];
                    }

                    Description.AccountReadable = true;
                    description = uri!;
                    return new SourceAccountMaterial { AccountUri = uri!, AccountKeyPem = keyPem, EmailAddress = email };
                }
                catch (Exception exp)
                {
                    description = $"the account files could not be read: {exp.Message}";
                    return null;
                }
            }

            public SourceCertificateMaterial? ReadCertificate(bool keepData, out string? note) =>
                MigrationFiles.LoadPemCertificate(Description, Tool, _live["cert"], _live["privkey"], _live["chain"], _item?.CertificateThumbprintHash, keepData, out note);
        }
    }
}
