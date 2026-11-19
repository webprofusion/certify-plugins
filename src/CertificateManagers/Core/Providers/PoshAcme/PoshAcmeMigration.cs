using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Migration;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.PoshAcme
{
    /// <summary>
    /// Migration of Posh-ACME orders. Reads an order, the plugin arguments Posh-ACME saved for it and its account into a
    /// <see cref="SourceRenewalDescription"/>. Cut over renames order.json, so Posh-ACME no longer lists or renews the order
    /// </summary>
    public partial class PoshAcme : ICertificateManagerMigrationSource
    {
        internal const string DisabledSuffix = ".certify-migrated";
        private const string PluginArgsFileName = "pluginargs.json";

        /// <summary>
        /// The prefix of a SecureString exported with a key (ConvertFrom-SecureString -Key)
        /// </summary>
        private const string SecureStringHeader = "76492d1116743f0423413b16050a5345";

        /// <summary>
        /// The start of a Windows DPAPI blob, as hex, which ConvertFrom-SecureString writes without a key on Windows
        /// </summary>
        private const string DpapiHexPrefix = "01000000d08c9ddf";

        internal static string ItemIdFor(string? orderLocation) =>
            $"{ManagedCertificate.ExternalItemIdPrefix}posh-acme-{Certify.Management.Util.ToUrlSafeBase64String(orderLocation)}";

        public MigrationSourceCapabilities GetMigrationCapabilities() => new()
        {
            DisableMethod = $"Renames the order's {OrderFileName} to {OrderFileName}{DisabledSuffix}, so Posh-ACME no longer lists or renews it",
            DisabledItemHiddenFromMonitoring = true,
            CanDisableSingleItem = true,
            RequiresIdleTool = false
        };

        public async Task<ExternalMigrationPlan?> PrepareMigrationPlan(string itemId, ExternalMigrationContext context, IDictionary<string, string>? inputs)
        {
            var reader = await GetReader(itemId, includeDisabled: false);
            return reader == null ? null : MigrationPlanMapper.Map(reader.Description, context, inputs);
        }

        public async Task<Dictionary<string, string>> ResolveCredentialValues(string itemId, ExternalMigrationCredentialDraft draft)
        {
            var reader = await GetReader(itemId, includeDisabled: false) ?? throw new InvalidOperationException("The Posh-ACME order could not be found.");
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
            var order = await FindOrder(itemId, includeDisabled: true);
            if (order == null)
            {
                return new SourceChangeResult(false, "The Posh-ACME order could not be found.");
            }

            if (order.IsDisabled)
            {
                return new SourceChangeResult(true, "The Posh-ACME order is already set aside.");
            }

            return Change(() =>
            {
                var target = order.File.FullName + DisabledSuffix;
                if (File.Exists(target))
                {
                    return new SourceChangeResult(false, $"{target} already exists.");
                }

                File.Move(order.File.FullName, target);
                return new SourceChangeResult(true, $"Renamed {order.File.FullName} to {Path.GetFileName(target)}, so Posh-ACME no longer lists or renews the order.");
            });
        }

        public async Task<SourceChangeResult> RestoreSourceItem(string itemId)
        {
            var order = await FindOrder(itemId, includeDisabled: true);
            if (order == null)
            {
                return new SourceChangeResult(false, "The Posh-ACME order could not be found.");
            }

            if (!order.IsDisabled)
            {
                return new SourceChangeResult(true, "The Posh-ACME order is already renewed by Posh-ACME.");
            }

            return Change(() =>
            {
                var target = order.File.FullName[..^DisabledSuffix.Length];
                if (File.Exists(target))
                {
                    return new SourceChangeResult(false, $"{target} already exists, so the set aside order was left as it is.");
                }

                File.Move(order.File.FullName, target);
                return new SourceChangeResult(true, $"Renamed the order back to {OrderFileName}, so Posh-ACME renews it again.");
            });
        }

        public async Task<SourceRemovalManifest> PlanSourceRemoval(string itemId)
        {
            var manifest = new SourceRemovalManifest { SourceItemId = itemId };

            var order = await FindOrder(itemId, includeDisabled: true);
            if (order == null)
            {
                manifest.BlockedReason = "The Posh-ACME order could not be found.";
                return manifest;
            }

            if (!order.IsDisabled)
            {
                manifest.BlockedReason = "The order is renewed by Posh-ACME again, so it is not removed. Cut over again first.";
            }

            manifest.FilesToDelete.AddRange(Directory.GetFiles(order.Folder.FullName, "*", SearchOption.AllDirectories).OrderBy(f => f));
            manifest.Kept.Add($"The Posh-ACME account in {order.Folder.Parent?.FullName}, and its other orders");
            manifest.Kept.Add("Any script or scheduled task running Submit-Renewal, which renews any other orders");

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

            var order = await FindOrder(itemId, includeDisabled: true);

            return Change(() =>
            {
                foreach (var file in manifest.FilesToDelete.Where(File.Exists))
                {
                    File.Delete(file);
                }

                if (order != null && order.Folder.Exists && !order.Folder.EnumerateFiles("*", SearchOption.AllDirectories).Any())
                {
                    order.Folder.Delete(true);
                }

                return new SourceChangeResult(true, $"Deleted the Posh-ACME order folder's {manifest.FilesToDelete.Count} file{(manifest.FilesToDelete.Count == 1 ? "" : "s")}.");
            });
        }

        private static SourceChangeResult Change(Func<SourceChangeResult> action)
        {
            try
            {
                return action();
            }
            catch (Exception exp)
            {
                return new SourceChangeResult(false, exp.Message);
            }
        }

        // the order

        internal sealed class OrderEntry
        {
            public FileInfo File { get; init; } = default!;
            public bool IsDisabled { get; init; }
            public string Hash { get; init; } = string.Empty;
            public JsonElement Order { get; init; }

            public DirectoryInfo Folder => File.Directory!;

            /// <summary>
            /// Orders are kept in {server}\{account}\{order}
            /// </summary>
            public DirectoryInfo? AccountFolder => Folder.Parent;
            public DirectoryInfo? ServerFolder => Folder.Parent?.Parent;

            public string? Get(string name) =>
                Order.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString()) ? value.GetString() : null;

            public bool IsTrue(string name) => Order.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;

            public int? GetInt(string name) =>
                Order.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) ? number : null;

            public List<string> GetList(string name) =>
                !Order.TryGetProperty(name, out var value) ? []
                : value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
                : value.ValueKind == JsonValueKind.String ? [value.GetString()!]
                : [];
        }

        internal async Task<OrderEntry?> FindOrder(string itemId, bool includeDisabled)
        {
            if (!await IsPresent())
            {
                return null;
            }

            // an order Posh-ACME renews is found before a set aside one, should the order have been created again since
            var files = new DirectoryInfo(_settingsPath).GetFiles(OrderFileName + "*", SearchOption.AllDirectories)
                .Where(f => f.Name == OrderFileName || (includeDisabled && f.Name == OrderFileName + DisabledSuffix))
                .OrderBy(f => f.Name != OrderFileName);

            foreach (var file in files)
            {
                try
                {
                    var bytes = await File.ReadAllBytesAsync(file.FullName);
                    using var json = JsonDocument.Parse(bytes);

                    if (!json.RootElement.TryGetProperty("location", out var location) || ItemIdFor(location.GetString()) != itemId)
                    {
                        continue;
                    }

                    return new OrderEntry
                    {
                        File = file,
                        IsDisabled = file.Name != OrderFileName,
                        Hash = MigrationFiles.FileHash(bytes),
                        Order = json.RootElement.Clone()
                    };
                }
                catch (Exception exp)
                {
                    _logger?.LogWarning("Posh-ACME: could not read {file}: {error}", file.FullName, exp.Message);
                }
            }

            return null;
        }

        private async Task<OrderReader?> GetReader(string itemId, bool includeDisabled)
        {
            var order = await FindOrder(itemId, includeDisabled);
            if (order == null)
            {
                return null;
            }

            var reader = new OrderReader(order);
            reader.Describe();
            return reader;
        }

        /// <summary>
        /// A SecureString as exported by ConvertFrom-SecureString: AES encrypted with the account's key, Windows DPAPI
        /// encrypted for the user who exported it, or (outside Windows) only hex encoded
        /// </summary>
        internal static (string? Value, string? Error) DecodeSecureString(string exported, string? sskey)
        {
            try
            {
                if (sskey == "VAULT")
                {
                    return (null, "Posh-ACME encrypted it with a key kept in a SecretManagement vault, which cannot be read here");
                }

                if (exported.StartsWith(SecureStringHeader, StringComparison.Ordinal))
                {
                    if (string.IsNullOrWhiteSpace(sskey))
                    {
                        return (null, "it is encrypted with a key the account no longer has");
                    }

                    // Base64 of UTF-16 "2|{IV as base64}|{encrypted UTF-16 as hex}"
                    var parts = Encoding.Unicode.GetString(Convert.FromBase64String(exported[SecureStringHeader.Length..])).Split('|');
                    if (parts.Length != 3)
                    {
                        return (null, "the encrypted value is not in a recognised form");
                    }

                    using var aes = Aes.Create();
                    aes.Key = MigrationFiles.Base64UrlDecode(sskey);
                    var data = IsHex(parts[2]) ? Convert.FromHexString(parts[2]) : Convert.FromBase64String(parts[2]);
                    return (Encoding.Unicode.GetString(aes.DecryptCbc(data, Convert.FromBase64String(parts[1]))), null);
                }

                if (!IsHex(exported))
                {
                    return (null, "the value is not in a recognised form");
                }

                var bytes = Convert.FromHexString(exported);

                if (exported.StartsWith(DpapiHexPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        return (null, "it is encrypted with Windows DPAPI, which only Windows can read");
                    }

                    try
                    {
                        return (Encoding.Unicode.GetString(ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser)), null);
                    }
                    catch (CryptographicException)
                    {
                        return (null, "Posh-ACME encrypted it with Windows DPAPI for the user who ran it, so only that user can read it. Run the migration as that user, or set the account to use its own key (Set-PAAccount -UseAltPluginEncryption) and preview again");
                    }
                }

                // exported outside Windows, where the value is only hex encoded
                return (Encoding.Unicode.GetString(bytes), null);
            }
            catch (Exception exp) when (exp is FormatException or CryptographicException or ArgumentException)
            {
                return (null, $"it could not be decrypted: {exp.Message}");
            }
        }

        private static bool IsHex(string value) => value.Length > 0 && value.Length % 2 == 0 && value.All(Uri.IsHexDigit);

        /// <summary>
        /// Reads one order and everything it depends on into a description
        /// </summary>
        internal sealed class OrderReader
        {
            private readonly OrderEntry _order;
            private readonly JsonElement? _account;
            private readonly string? _accountFile;

            public SourceRenewalDescription Description { get; } = new();
            public MigrationSecrets Secrets { get; }

            public OrderReader(OrderEntry order)
            {
                _order = order;
                Secrets = new MigrationSecrets(Description);

                if (order.AccountFolder != null)
                {
                    _accountFile = Path.Combine(order.AccountFolder.FullName, "acct.json");
                    _account = ReadJson(_accountFile);
                }
            }

            private static string Tool => ProviderTitle;
            private string Folder(string name) => Path.Combine(_order.Folder.FullName, name);

            private static JsonElement? ReadJson(string path)
            {
                try
                {
                    if (!File.Exists(path))
                    {
                        return null;
                    }

                    using var json = JsonDocument.Parse(File.ReadAllText(path));
                    return json.RootElement.Clone();
                }
                catch (Exception exp) when (exp is IOException or UnauthorizedAccessException or JsonException)
                {
                    return null;
                }
            }

            private string? AccountValue(string name) =>
                _account is { } account && account.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

            private string? Server()
            {
                if (_order.ServerFolder == null)
                {
                    return null;
                }

                var dir = ReadJson(Path.Combine(_order.ServerFolder.FullName, "dir.json"));
                return dir is { } d && d.TryGetProperty("location", out var location) ? location.GetString() : null;
            }

            public void Describe()
            {
                var d = Description;
                d.ProviderId = Definition.Id;
                d.ProviderTitle = Tool;
                d.ItemId = ItemIdFor(_order.Get("location"));
                d.Name = _order.Get("FriendlyName") ?? _order.Get("MainDomain") ?? _order.Folder.Name;
                d.RenewalId = _order.Folder.Name;
                d.OrderName = _order.Folder.Name;
                d.SourcePath = _order.File.FullName;
                d.FileHash = _order.Hash;
                d.CaEndpoints = [Server()];

                d.Identifiers = new[] { _order.Get("MainDomain") }.Concat(_order.GetList("SANs")).Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

                DescribeRequest();
                DescribeValidations();
                DescribeOutputs();

                if (_order.Get("status") == "invalid")
                {
                    d.LastRunErrors.Add($"The last {Tool} order for these identifiers is invalid, so its last renewal failed.");
                }

                ReadAccount(out var accountDescription);
                d.AccountDescription = accountDescription;

                ReadCertificate(keepData: false, out var note);
                d.CurrentCertificateNote = note;
            }

            private void DescribeRequest()
            {
                var d = Description;
                var keyLength = _order.Get("KeyLength") ?? "2048";

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

                d.ReusePrivateKey = !_order.IsTrue("AlwaysNewKey");
                d.OcspMustStaple = _order.IsTrue("OCSPMustStaple");
                d.PreferredIssuer = _order.Get("PreferredChain");
                d.CertificateProfile = _order.Get("Profile");
                d.ValidDays = _order.GetInt("LifetimeDays");

                var aliases = _order.GetList("DnsAlias").Where(a => !string.IsNullOrWhiteSpace(a)).ToList();
                if (aliases.Any())
                {
                    d.Unrecognised.Add(new SourceUnrecognised
                    {
                        Category = "Validation",
                        Description = $"{Tool} validates through DNS aliases ({string.Join(", ", aliases.Distinct())}), which are not migrated. Set up a challenge delegation on the item instead.",
                        IsBlocker = true
                    });
                }

                if (_order.Get("Subject") is { } subject)
                {
                    d.UnmappedSettings.Add($"The custom certificate subject {subject} is not migrated.");
                }

                // Posh-ACME renews from a script or scheduled task the user set up, which may do more after renewing
                d.Unrecognised.Add(new SourceUnrecognised
                {
                    Category = "Installation",
                    Description = $"{Tool} renews from a script or scheduled task running Submit-Renewal, and anything that script does with the new certificate (copying it, binding it, restarting services) is not visible here. Add deployment tasks doing the same to the item before cut over."
                });
            }

            // validation

            /// <summary>
            /// The plugin of each identifier: one per identifier in order, with the last repeating
            /// </summary>
            private void DescribeValidations()
            {
                var plugins = _order.GetList("Plugin");
                if (!plugins.Any())
                {
                    plugins = _order.GetList("DnsPlugin");
                }

                if (!plugins.Any())
                {
                    plugins = ["Manual"];
                }

                var identifiers = Description.Identifiers;
                var byPlugin = identifiers
                    .Select((identifier, i) => (Identifier: identifier, Plugin: i < plugins.Count ? plugins[i] : plugins[^1]))
                    .GroupBy(i => i.Plugin, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var args = PluginArgs.Read(_order, _account);

                foreach (var group in byPlugin)
                {
                    var scope = byPlugin.Count > 1 ? group.Select(g => g.Identifier).ToList() : null;
                    DescribeValidation(group.Key, scope, group.Select(g => g.Identifier).ToList(), args);
                }
            }

            private void DescribeValidation(string plugin, List<string>? scope, List<string> identifiers, PluginArgs args)
            {
                var validation = new SourceValidation { Identifiers = scope, SourceName = plugin };

                switch (plugin.ToLowerInvariant())
                {
                    case "manual":
                        validation.Kind = SourceValidationKinds.Manual;
                        validation.SourceName = "Manual DNS";
                        break;

                    case "webroot":
                        DescribeWebRoot(validation, args);
                        break;

                    case "webselfhost":
                        validation.Kind = SourceValidationKinds.HttpSelfHosting;
                        validation.Parameters["Port"] = args.Plain("WSHPort") ?? "80";
                        break;

                    case "acmedns":
                        DescribeAcmeDns(scope, identifiers, args);
                        return;

                    default:
                        if (MigrationCatalogue.GetAlias(MigrationCatalogue.PoshAcmeDnsAliases, plugin) is { } alias)
                        {
                            // only whether each is set is inspected here, so a secure value is not decrypted until import
                            var options = args.Names.Select(n => new KeyValuePair<string, string>(n, args.Plain(n) ?? (args.IsSet(n) ? "set" : "")));
                            MigrationDns.Describe(validation, alias, options, args.AddSecret(Secrets), _ => "", option => $"with {option}");
                            DescribeAmbient(validation, alias.Key, args);
                        }
                        else
                        {
                            // the same Posh-ACME plugin runs here, so its arguments carry over by name
                            validation.Kind = SourceValidationKinds.Dns;
                            validation.ScriptPlugin = plugin;
                            validation.SourceName = $"{plugin} (Posh-ACME plugin)";

                            var addSecret = args.AddSecret(Secrets);
                            foreach (var name in args.Names.Where(args.IsSet))
                            {
                                validation.SecretParameters[name] = addSecret(name);
                            }
                        }

                        if ((args.Plain("DnsSleep") ?? _order.GetInt("DnsSleep")?.ToString()) is { } sleep)
                        {
                            validation.Parameters["propagationdelay"] = sleep;
                        }

                        break;
                }

                Description.Validations.Add(validation);
            }

            private static void DescribeAmbient(SourceValidation validation, string provider, PluginArgs args)
            {
                if (provider == "route53" && validation.AmbientAuthentication != null)
                {
                    validation.AmbientAuthentication = args.Plain("R53ProfileName") is { } profile
                        ? $"with the AWS profile {profile} of the user who ran {Tool}"
                        : "with the machine's IAM role";
                }
                else if (provider == "azure" && validation.AmbientAuthentication != null)
                {
                    validation.AmbientAuthentication = args.IsSet("AZUseIMDS") ? "with the machine's managed identity" : "with an access token or certificate, which is not migrated";
                }
            }

            private void DescribeWebRoot(SourceValidation validation, PluginArgs args)
            {
                validation.Kind = SourceValidationKinds.HttpFileSystem;
                validation.SourceName = "Webroot";

                var paths = args.List("WRPath");
                if (!paths.Any())
                {
                    validation.Kind = SourceValidationKinds.Unknown;
                    validation.SourceName = "Webroot with no path";
                    return;
                }

                var path = paths[0];

                // with WRExactPath the challenge files went straight into the path rather than under .well-known/acme-challenge
                if (args.Plain("WRExactPath") is { } exact && bool.TryParse(exact, out var isExact) && isExact)
                {
                    var trimmed = path.TrimEnd('/', '\\');
                    var suffix = Path.Combine(".well-known", "acme-challenge");

                    if (trimmed.Replace('\\', '/').EndsWith(".well-known/acme-challenge", StringComparison.OrdinalIgnoreCase))
                    {
                        path = trimmed[..^suffix.Length].TrimEnd('/', '\\');
                    }
                    else
                    {
                        validation.Notes.Add($"{Tool} wrote challenge files straight into {path}, but challenge files here go under .well-known/acme-challenge in the web root. Check the web root of the migrated item.");
                    }
                }

                validation.Parameters[SourceSettingNames.Path] = path;

                if (paths.Count > 1)
                {
                    validation.Notes.Add($"{Tool} wrote challenge files to {paths.Count} web roots ({string.Join(", ", paths)}), and only {path} is migrated.");
                }
            }

            private void DescribeAcmeDns(List<string>? scope, List<string> identifiers, PluginArgs args)
            {
                var server = args.Plain("ACMEServer");
                var api = server == null ? null : server.Contains("://", StringComparison.Ordinal) ? server : $"https://{server}";

                foreach (var identifier in identifiers)
                {
                    var record = $"_acme-challenge.{identifier.TrimStart('*', '.')}";
                    var validation = new SourceValidation { Kind = SourceValidationKinds.Dns, DnsProvider = "acme-dns", SourceName = "acme-dns", Identifiers = [identifier] };

                    if (api != null)
                    {
                        validation.Parameters["api"] = api;
                    }

                    validation.SecretParameters["credentials_json"] = Secrets.Add($"acme-dns:{record}", $"acme-dns registration for {identifier} ({args.Location})", args.IsShared, () =>
                    {
                        var registration = args.Read().Registration(record);
                        if (registration == null || registration.Count < 4)
                        {
                            return (null, $"no acme-dns registration for {record} is saved");
                        }

                        return (JsonSerializer.Serialize(new { subdomain = registration[0], username = registration[1], password = registration[2], fulldomain = registration[3] }), null);
                    });

                    Description.Validations.Add(validation);
                }
            }

            // output

            private void DescribeOutputs()
            {
                if (_order.IsTrue("Install"))
                {
                    var output = new SourceOutput { Kind = SourceOutputKinds.CertificateStore, SourceName = "Certificate store" };
                    output.Settings[SourceSettingNames.StoreName] = "My";
                    Description.Outputs.Add(output);
                }
                else
                {
                    Description.Outputs.Add(new SourceOutput { Kind = SourceOutputKinds.None, SourceName = "None" });
                }
            }

            // account and certificate

            public SourceAccountMaterial? ReadAccount(out string description)
            {
                try
                {
                    if (_account is not { } account)
                    {
                        description = $"the account file {_accountFile} could not be read";
                        return null;
                    }

                    var url = AccountValue("location");
                    if (string.IsNullOrWhiteSpace(url))
                    {
                        description = $"{_accountFile} does not include the account URL";
                        return null;
                    }

                    if (!account.TryGetProperty("key", out var key))
                    {
                        description = $"{_accountFile} does not include the account key";
                        return null;
                    }

                    var jwk = key.ValueKind == JsonValueKind.String ? key.GetString()! : key.GetRawText();
                    var email = account.TryGetProperty("contact", out var contact) && contact.ValueKind == JsonValueKind.Array
                        ? contact.EnumerateArray().Select(c => c.GetString()).FirstOrDefault(c => c?.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) == true)?["mailto:".Length..]
                        : null;

                    var material = new SourceAccountMaterial { AccountUri = url, AccountKeyPem = MigrationFiles.ConvertJwkToPem(jwk), EmailAddress = email };

                    Description.AccountReadable = true;
                    description = url;
                    return material;
                }
                catch (Exception exp) when (exp is InvalidOperationException or JsonException or FormatException or CryptographicException)
                {
                    description = $"the account key could not be read: {exp.Message}";
                    return null;
                }
            }

            public SourceCertificateMaterial? ReadCertificate(bool keepData, out string? note) =>
                MigrationFiles.LoadPemCertificate(Description, Tool, Folder("cert.cer"), Folder("cert.key"), Folder("chain.cer"), null, keepData, out note);
        }

        /// <summary>
        /// The plugin arguments Posh-ACME saved for an order (pluginargs.json in the order folder, or the account folder
        /// in Posh-ACME 3). Secure values stay encrypted until read for import
        /// </summary>
        internal sealed class PluginArgs
        {
            private readonly Dictionary<string, JsonElement> _values;
            private readonly OrderEntry _order;
            private readonly JsonElement? _account;

            public string Location { get; }
            public bool IsShared { get; }

            private PluginArgs(OrderEntry order, JsonElement? account, string location, bool isShared, Dictionary<string, JsonElement> values)
            {
                _order = order;
                _account = account;
                Location = location;
                IsShared = isShared;
                _values = values;
            }

            public static PluginArgs Read(OrderEntry order, JsonElement? account)
            {
                foreach (var (folder, isShared) in new[] { (order.Folder, false), (order.AccountFolder, true) })
                {
                    if (folder == null)
                    {
                        continue;
                    }

                    var path = Path.Combine(folder.FullName, PluginArgsFileName);

                    try
                    {
                        if (File.Exists(path))
                        {
                            using var json = JsonDocument.Parse(File.ReadAllText(path));
                            var values = json.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone(), StringComparer.OrdinalIgnoreCase);
                            return new PluginArgs(order, account, path, isShared, values);
                        }
                    }
                    catch (Exception exp) when (exp is IOException or UnauthorizedAccessException or JsonException)
                    {
                        return new PluginArgs(order, account, path, isShared, new(StringComparer.OrdinalIgnoreCase));
                    }
                }

                return new PluginArgs(order, account, Path.Combine(order.Folder.FullName, PluginArgsFileName), false, new(StringComparer.OrdinalIgnoreCase));
            }

            /// <summary>
            /// The arguments again, as they are now
            /// </summary>
            public PluginArgs Read() => Read(_order, _account);

            /// <summary>
            /// Argument names, with a credential's user name and password as name.user and name.pass
            /// </summary>
            public IEnumerable<string> Names => _values.SelectMany(v => OrigType(v.Value) == "pscredential" ? [$"{v.Key}.user", $"{v.Key}.pass"] : new[] { v.Key });

            public bool IsSet(string name) => Element(name, out _) is { } value && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined or JsonValueKind.False);

            /// <summary>
            /// The value of an argument that is not secure, or null
            /// </summary>
            public string? Plain(string name)
            {
                if (Element(name, out var part) is not { } value)
                {
                    return null;
                }

                return value.ValueKind switch
                {
                    JsonValueKind.String => value.GetString(),
                    JsonValueKind.Number => value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Object when part == "user" => value.TryGetProperty("user", out var user) ? user.GetString() : null,
                    _ => null
                };
            }

            public List<string> List(string name) =>
                Element(name, out _) is { } value
                    ? value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList()
                    : value.ValueKind == JsonValueKind.String ? [value.GetString()!] : []
                    : [];

            /// <summary>
            /// An acme-dns registration: subdomain, username, password and full domain
            /// </summary>
            public List<string>? Registration(string record)
            {
                if (Element("ACMERegistration", out _) is not { ValueKind: JsonValueKind.Object } registrations)
                {
                    return null;
                }

                var match = registrations.EnumerateObject().FirstOrDefault(r => string.Equals(r.Name, record, StringComparison.OrdinalIgnoreCase));
                return match.Value.ValueKind == JsonValueKind.Array ? match.Value.EnumerateArray().Select(v => v.ToString()).ToList() : null;
            }

            /// <summary>
            /// The value of an argument, decrypting a secure one
            /// </summary>
            public (string? Value, string? Error) Value(string name)
            {
                if (Element(name, out var part) is not { } value)
                {
                    return (null, $"{name} is no longer saved");
                }

                var sskey = _account is { } account && account.TryGetProperty("sskey", out var key) && key.ValueKind == JsonValueKind.String ? key.GetString() : null;

                return OrigType(value) switch
                {
                    "securestring" => DecodeSecureString(value.GetProperty("value").GetString() ?? "", sskey),
                    "pscredential" when part == "pass" => DecodeSecureString(value.GetProperty("pass").GetString() ?? "", sskey),
                    "pscredential" => (value.TryGetProperty("user", out var user) ? user.GetString() : null, null),
                    _ => value.ValueKind switch
                    {
                        JsonValueKind.String => (value.GetString(), null),
                        JsonValueKind.Array => (string.Join(",", value.EnumerateArray().Select(v => v.ToString())), null),
                        JsonValueKind.True => ("true", null),
                        JsonValueKind.False => ("false", null),
                        _ => (value.GetRawText(), null)
                    }
                };
            }

            public Func<string, string> AddSecret(MigrationSecrets secrets) =>
                name => secrets.Add($"{Location}:{name}", $"{name} ({Location})", IsShared, () => Read().Value(name));

            private JsonElement? Element(string name, out string? part)
            {
                part = null;

                if (_values.TryGetValue(name, out var value))
                {
                    return value;
                }

                var dot = name.LastIndexOf('.');
                if (dot > 0 && _values.TryGetValue(name[..dot], out var credential) && OrigType(credential) == "pscredential")
                {
                    part = name[(dot + 1)..];
                    return credential;
                }

                return null;
            }

            private static string? OrigType(JsonElement value) =>
                value.ValueKind == JsonValueKind.Object && value.TryGetProperty("origType", out var type) ? type.GetString()?.ToLowerInvariant() : null;
        }
    }
}
