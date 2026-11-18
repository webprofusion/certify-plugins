using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Migration;
using Certify.Plugin.CertificateManagers.Utils;
using Certify.Plugin.CertificateManagers.WinAcme;
using Certify.Providers.CertificateManagers;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Providers.WinAcme
{
    /// <summary>
    /// Migration of win-acme and simple-acme renewals. Reads a renewal and everything it depends on (settings,
    /// validation.json, secrets, the account and the cached certificate) into a <see cref="SourceRenewalDescription"/>,
    /// and disables, restores and removes renewals at cut over, rollback and removal
    /// </summary>
    public partial class WinAcme : ICertificateManagerMigrationSource
    {
        /// <summary>
        /// Appended to a renewal file at cut over. The tool only loads *.renewal.json, so the renewal stops renewing and
        /// drops out of monitoring, and renaming it back restores it unchanged
        /// </summary>
        internal const string DisabledSuffix = ".certify-migrated";

        private const string ToolProcessName = "wacs";
        private const string ToolMutexName = "wacs.exe";
        private const string RenewalFileSuffix = ".renewal.json";

        private static readonly JsonDocumentOptions JsonReadOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

        /// <summary>
        /// Options holding a ProtectedString, which may be encrypted, encoded or a vault reference
        /// </summary>
        private static readonly HashSet<string> ProtectedOptions = new(StringComparer.OrdinalIgnoreCase)
        {
            "ApiToken", "SecretSafe", "ApiKey", "ApiSecret", "ClientSecret", "APIKeySafe", "TsigKeySecret", "SecretAccessKeySafe",
            "ApiID", "PrivateKey", "DNSApiKey", "KeyID", "KeySecret", "APIKey", "PemPassword", "PfxPassword", "PfxPasswordProtected", "CertificatePassword"
        };

        public MigrationSourceCapabilities GetMigrationCapabilities() => new()
        {
            DisableMethod = $"Renames the renewal file so {ProviderTitle} no longer loads it",
            DisabledItemHiddenFromMonitoring = true,
            CanDisableSingleItem = false,
            RequiresIdleTool = true
        };

        public async Task<ExternalMigrationPlan?> PrepareMigrationPlan(string itemId, ExternalMigrationContext context, IDictionary<string, string>? inputs)
        {
            var entry = await FindRenewalEntry(itemId, includeDisabled: false);
            if (entry == null)
            {
                return null;
            }

            var description = new RenewalReader(this, entry).Describe();
            return MigrationPlanMapper.Map(description, context, inputs);
        }

        public async Task<Dictionary<string, string>> ResolveCredentialValues(string itemId, ExternalMigrationCredentialDraft draft)
        {
            var entry = await FindRenewalEntry(itemId, includeDisabled: false)
                ?? throw new InvalidOperationException("The renewal could not be found.");

            var reader = new RenewalReader(this, entry);
            reader.Describe();

            var values = new Dictionary<string, string>();

            foreach (var (parameter, reference) in draft.Values)
            {
                if (reference.StartsWith(ExternalMigrationCredentialDraft.LiteralPrefix, StringComparison.Ordinal))
                {
                    values[parameter] = reference[ExternalMigrationCredentialDraft.LiteralPrefix.Length..];
                    continue;
                }

                if (!reader.Secrets.TryGetValue(reference, out var secret))
                {
                    throw new InvalidOperationException($"{draft.Title} refers to a setting the renewal no longer has.");
                }

                values[parameter] = secret.Resolve();
            }

            return values;
        }

        public async Task<SourceCertificateMaterial?> GetCurrentCertificate(string itemId)
        {
            var entry = await FindRenewalEntry(itemId, includeDisabled: true);
            if (entry == null)
            {
                return null;
            }

            var reader = new RenewalReader(this, entry);
            reader.Describe();

            return reader.FindCachedCertificate(out _, keepData: true);
        }

        public async Task<SourceAccountMaterial?> GetAccount(string itemId)
        {
            var entry = await FindRenewalEntry(itemId, includeDisabled: true);
            if (entry == null)
            {
                return null;
            }

            var reader = new RenewalReader(this, entry);
            reader.Describe();

            return reader.ReadAccount(out _);
        }

        public async Task<SourceChangeResult> DisableSourceItem(string itemId)
        {
            var entry = await FindRenewalEntry(itemId, includeDisabled: true);
            if (entry == null)
            {
                return new SourceChangeResult(false, "The renewal could not be found.");
            }

            if (entry.IsDisabled)
            {
                return new SourceChangeResult(true, $"The {ProviderTitle} renewal is already disabled.");
            }

            return WithToolIdle(() =>
            {
                var target = entry.File.FullName + DisabledSuffix;
                if (File.Exists(target))
                {
                    return new SourceChangeResult(false, $"{target} already exists.");
                }

                File.Move(entry.File.FullName, target);
                return new SourceChangeResult(true, $"Renamed {entry.File.Name} to {Path.GetFileName(target)}, so {ProviderTitle} no longer renews it.");
            });
        }

        public async Task<SourceChangeResult> RestoreSourceItem(string itemId)
        {
            var entry = await FindRenewalEntry(itemId, includeDisabled: true);
            if (entry == null)
            {
                return new SourceChangeResult(false, "The renewal could not be found.");
            }

            if (!entry.IsDisabled)
            {
                return new SourceChangeResult(true, $"The {ProviderTitle} renewal is already active.");
            }

            return WithToolIdle(() =>
            {
                var target = entry.File.FullName[..^DisabledSuffix.Length];
                if (File.Exists(target))
                {
                    return new SourceChangeResult(false, $"{target} already exists, so the disabled renewal was left as it is.");
                }

                File.Move(entry.File.FullName, target);
                return new SourceChangeResult(true, $"Renamed the renewal back to {Path.GetFileName(target)}, so {ProviderTitle} renews it again.");
            });
        }

        public async Task<SourceRemovalManifest> PlanSourceRemoval(string itemId)
        {
            var manifest = new SourceRemovalManifest { SourceItemId = itemId };

            var entry = await FindRenewalEntry(itemId, includeDisabled: true);
            if (entry == null)
            {
                manifest.BlockedReason = "The renewal could not be found.";
                return manifest;
            }

            if (!entry.IsDisabled)
            {
                manifest.BlockedReason = $"The renewal is active in {ProviderTitle} again, so it is not removed. Cut over again first.";
            }

            var reader = new RenewalReader(this, entry);
            reader.Describe();

            manifest.FilesToDelete.Add(entry.File.FullName);
            manifest.FilesToDelete.AddRange(reader.FindCacheFiles().Select(f => f.FullName));

            manifest.Kept.Add($"{ProviderTitle}'s ACME account, settings, validation.json and secrets.json, which other renewals may use");
            manifest.Kept.Add($"The {ProviderTitle} scheduled task, which renews any other renewals");
            manifest.Kept.Add("Certificates already installed in certificate stores, exported files and IIS bindings, which the migrated item now maintains");

            if (entry.Renewal.ValidationPluginOptions?.Plugin?.Equals(AcmeDnsValidationPlugin, StringComparison.OrdinalIgnoreCase) == true)
            {
                manifest.Kept.Add("acme-dns registrations, which the migrated item was given a copy of");
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

            // only what was shown is deleted
            if (!current.FilesToDelete.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(manifest.FilesToDelete))
            {
                return new SourceChangeResult(false, "The files to delete have changed since the removal was previewed. Preview it again.");
            }

            return WithToolIdle(() =>
            {
                foreach (var file in manifest.FilesToDelete.Where(File.Exists))
                {
                    File.Delete(file);
                }

                return new SourceChangeResult(true, $"Deleted the {ProviderTitle} renewal and its {manifest.FilesToDelete.Count - 1} cached file{(manifest.FilesToDelete.Count == 2 ? "" : "s")}.");
            });
        }

        /// <summary>
        /// Change the tool's files only while it is not running, holding its own lock so it cannot start meanwhile
        /// </summary>
        private SourceChangeResult WithToolIdle(Func<SourceChangeResult> action)
        {
            try
            {
                if (Process.GetProcessesByName(ToolProcessName).Any())
                {
                    return new SourceChangeResult(false, $"{ProviderTitle} is running. Try again when it has finished.");
                }
            }
            catch (Exception exp)
            {
                _logger?.LogDebug($"{ProviderTitle}: could not list processes: {exp.Message}");
            }

            Mutex? mutex = null;
            var acquired = false;

            try
            {
                if (OperatingSystem.IsWindows())
                {
                    mutex = new Mutex(false, ToolMutexName);

                    try
                    {
                        acquired = mutex.WaitOne(0);
                    }
                    catch (AbandonedMutexException)
                    {
                        acquired = true;
                    }

                    if (!acquired)
                    {
                        return new SourceChangeResult(false, $"{ProviderTitle} is running. Try again when it has finished.");
                    }
                }

                return action();
            }
            catch (Exception exp)
            {
                return new SourceChangeResult(false, exp.Message);
            }
            finally
            {
                if (acquired)
                {
                    mutex?.ReleaseMutex();
                }

                mutex?.Dispose();
            }
        }

        internal sealed class RenewalEntry
        {
            public FileInfo File { get; init; } = default!;
            public WinAcmeRenewal Renewal { get; init; } = default!;
            public bool IsDisabled { get; init; }
            public string Hash { get; init; } = string.Empty;

            /// <summary>
            /// The renewal's items in order, with the order each is for
            /// </summary>
            public List<(ManagedCertificate Item, string OrderName)> Items { get; init; } = new();
            public int Index { get; init; }

            public DirectoryInfo Folder => File.Directory!;
            public ManagedCertificate Item => Items[Index].Item;
            public string OrderName => Items[Index].OrderName;
        }

        /// <summary>
        /// The renewal an item id was listed from. Ids are recomputed from each candidate renewal, as renewal ids can
        /// contain the separator
        /// </summary>
        internal async Task<RenewalEntry?> FindRenewalEntry(string itemId, bool includeDisabled)
        {
            if (!await IsPresent())
            {
                return null;
            }

            var prefix = $"{ManagedCertificate.ExternalItemIdPrefix}{IdPrefix}-";
            if (!itemId.StartsWith(prefix, StringComparison.Ordinal))
            {
                return null;
            }

            var files = new DirectoryInfo(_settingsPath).GetFiles($"*{RenewalFileSuffix}*", SearchOption.AllDirectories)
                .Where(f => f.Name.EndsWith(RenewalFileSuffix, StringComparison.OrdinalIgnoreCase)
                    || (includeDisabled && f.Name.EndsWith(RenewalFileSuffix + DisabledSuffix, StringComparison.OrdinalIgnoreCase)));

            foreach (var file in files)
            {
                var fileRenewalId = file.Name[..file.Name.IndexOf(RenewalFileSuffix, StringComparison.OrdinalIgnoreCase)];
                if (!itemId[prefix.Length..].StartsWith(fileRenewalId, StringComparison.Ordinal))
                {
                    continue;
                }

                try
                {
                    var bytes = await File.ReadAllBytesAsync(file.FullName);
                    var renewal = JsonUtils.Deserialize<WinAcmeRenewal>(Encoding.UTF8.GetString(bytes));

                    if (renewal?.Id == null)
                    {
                        continue;
                    }

                    var orderNames = GetOrderNames(renewal.History ?? []);
                    var items = GetRenewalItems(renewal, file.Directory!).ToList();
                    var index = items.FindIndex(i => i.Id == itemId);

                    if (index >= 0)
                    {
                        return new RenewalEntry
                        {
                            File = file,
                            Renewal = renewal,
                            IsDisabled = !file.Name.EndsWith(RenewalFileSuffix, StringComparison.OrdinalIgnoreCase),
                            Hash = Convert.ToHexString(SHA256.HashData(bytes)),
                            Items = items.Select((item, i) => (item, i < orderNames.Count ? orderNames[i] : WinAcmeRenewal.MainOrderName)).ToList(),
                            Index = index
                        };
                    }
                }
                catch (Exception exp)
                {
                    _logger?.LogWarning($"{ProviderTitle}: could not read {file.FullName}: {exp.Message}");
                }
            }

            return null;
        }

        /// <summary>
        /// The tools' cached PFX files repeat bag attributes, which the default PKCS#12 loader limits refuse
        /// </summary>
        private static readonly Pkcs12LoaderLimits SourcePfxLimits = new() { AllowDuplicateAttributes = true };

        // plugin ids, see the win-acme and simple-acme sources
        private const string ManualTargetPlugin = "e239db3b-b42f-48aa-b64f-46d4f3e9941b";
        private const string CsrTargetPlugin = "5c3db0fb-840b-469f-b5a7-0635d8e9a93d";
        private const string IisTargetPlugin = "54deb3ee-b5df-4381-8485-fe386054055b";
        private static readonly string[] LegacyIisTargetPlugins = ["2f5dd428-0f5d-4c8a-8fd0-56fc1b5985ce", "d7940b23-f570-460e-ab15-2c822a79009b", "cdd79a68-4a87-4039-bee8-5a0ebdca41cb"];

        private const string FileSystemValidationPlugin = "1c77b3a4-5310-4c46-92c6-00d866e84d6b";
        private const string SelfHostingValidationPlugin = "c7d5e050-9363-4ba1-b3a8-931b31c618b7";
        private const string TlsValidationPlugin = "a1565064-b208-4467-8ca1-1bd3c08aa500";
        private const string AcmeDnsValidationPlugin = "c13acc1b-7571-432b-9652-7a68a5f506c5";
        private const string ManualDnsValidationPlugin = "e45d62b9-f9a8-441e-b95f-c5ee0dcd8040";
        private const string ScriptValidationPlugin = "8f1da72e-f727-49f0-8546-ef69e5ecec32";
        private const string NoValidationPlugin = "a37b41dc-b45a-42fe-8d81-82ca409a5491";
        private const string HetznerValidationPlugin = "7176cc8f-ba08-4b07-aa39-2f5d012c1d5a";
        private const string Route53ValidationPlugin = "4e5dc595-45c7-4461-929a-8f96a0c96b3d";

        private static readonly Dictionary<string, string> UnsupportedHttpValidationPlugins = new(StringComparer.OrdinalIgnoreCase)
        {
            ["bc27d719-dcf2-41ff-bf08-54db7ea49c48"] = "FTP",
            ["048aa2e7-2bce-4d3e-b731-6e0ed8b8170d"] = "SFTP",
            ["7e191d0e-30d1-47b3-ae2e-442499d33e16"] = "WebDAV",
            ["11ba2994-ea59-4f2f-b9eb-0eaa2fa3cbfa"] = "REST"
        };

        private const string RsaCsrPlugin = "b9060d4b-c2d3-49ac-b37f-962e7c3cbe9d";
        private const string EcCsrPlugin = "9aadcf71-5241-4c4f-aee1-bfe3f6be3489";

        private static readonly Dictionary<string, string> SplitOrderPlugins = new(StringComparer.OrdinalIgnoreCase)
        {
            ["874a86e4-29c7-4294-9ab6-6908866847a0"] = "host",
            ["b7c331d4-d875-453e-b83a-2b537ca12535"] = "domain",
            ["74a42b2d-8eaa-4f40-ab6a-f55304254143"] = "site"
        };

        private static readonly Dictionary<string, string> StorePlugins = new(StringComparer.OrdinalIgnoreCase)
        {
            ["e30adc8e-d756-4e16-a6f2-450f784b1a97"] = SourceOutputKinds.CertificateStore,
            ["e57c70e4-cd60-4ba6-80f6-a41703e21031"] = SourceOutputKinds.PemFiles,
            ["2a2c576f-7637-4ade-b8db-e8613b0bb33e"] = SourceOutputKinds.PfxFile,
            ["af1f77b6-4e7b-4f96-bba5-c2eeb4d0dd42"] = SourceOutputKinds.CentralSsl,
            ["cfdd7caa-ba34-4e9e-b9de-2a3d64c4f4ec"] = SourceOutputKinds.None,
            ["95ee94e7-c8e2-40e6-a26f-c9fc3afa9fa5"] = SourceOutputKinds.UserStore,
            ["dbfa91e2-28c0-4b37-857c-df6575dbb388"] = SourceOutputKinds.KeyVault,
            ["221310a3-14d8-4478-a0f1-3c6d90f2ea51"] = SourceOutputKinds.P7bFile
        };

        private static readonly Dictionary<string, string> InstallationPlugins = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ea6a5be3-f8de-4d27-a6bd-750b619b2ee2"] = SourceInstallationKinds.Iis,
            ["13058a79-5084-48af-b047-634e0ee222f4"] = SourceInstallationKinds.IisFtp,
            ["3bb22c70-358d-4251-86bd-11858363d913"] = SourceInstallationKinds.Script,
            ["aecc502c-5f75-43d2-b578-f95d50c79ea1"] = SourceInstallationKinds.None
        };

        /// <summary>
        /// Settings handled by the migration, so a renewal's own override of them is not reported as unmigrated
        /// </summary>
        private static readonly string[] HandledSettingPrefixes =
        [
            "Csr.", "Security.RSAKeyBits", "Security.ECCurve", "Security.EncryptConfig", "Acme.PreferredIssuer", "Acme.CertificateProfile",
            "Order.DefaultValidDays", "ScheduledTask.RenewalDays", "Store.", "Cache.", "Secrets."
        ];

        /// <summary>
        /// A secret the reader found, which is checked at preview and read at import
        /// </summary>
        internal sealed class SecretValue
        {
            public Func<string?> CheckError { get; init; } = () => null;
            public Func<string> Resolve { get; init; } = () => "";
        }

        /// <summary>
        /// Reads one renewal and everything it depends on into a description
        /// </summary>
        internal sealed class RenewalReader
        {
            private readonly WinAcme _tool;
            private readonly RenewalEntry _entry;
            private readonly SourceRenewalDescription _d = new();
            private readonly List<(string Source, JsonElement Root)> _settings = new();

            public Dictionary<string, SecretValue> Secrets { get; } = new();

            public RenewalReader(WinAcme tool, RenewalEntry entry)
            {
                _tool = tool;
                _entry = entry;
            }

            private WinAcmeRenewal Renewal => _entry.Renewal;
            private string Tool => _tool.ProviderTitle;
            private ManagedCertificate Item => _entry.Item;

            public SourceRenewalDescription Describe()
            {
                _d.ProviderId = _tool.ProviderId;
                _d.ProviderTitle = Tool;
                _d.ItemId = Item.Id!;
                _d.Name = Item.Name ?? Renewal.Id!;
                _d.SourcePath = _entry.File.FullName;
                _d.FileHash = _entry.Hash;
                _d.RenewalId = Renewal.Id;
                _d.AccountName = Renewal.Account;
                _d.CaEndpoints = [Renewal.EndPoint, _entry.Folder.Name];
                _d.RelatedItemIds = _entry.Items.Select(i => i.Item.Id!).Where(id => id != Item.Id).ToList();

                if (!IsMainOrder(_entry.OrderName) || _entry.Items.Count > 1)
                {
                    _d.OrderName = _entry.OrderName;
                }

                LoadSettings();
                DescribeTarget();
                DescribeOrder();
                DescribeCsr();
                DescribeSettings();
                DescribeValidations();

                for (var i = 0; i < (Renewal.StorePluginOptions?.Count ?? 0); i++)
                {
                    DescribeStore(Renewal.StorePluginOptions![i], i);
                }

                for (var i = 0; i < (Renewal.InstallationPluginOptions?.Count ?? 0); i++)
                {
                    DescribeInstallation(Renewal.InstallationPluginOptions![i], i);
                }

                foreach (var field in Renewal.OtherFields?.Keys.Where(k => k != "$schema") ?? [])
                {
                    _d.Unrecognised.Add(new SourceUnrecognised { Category = "Source", Description = $"The renewal field {field} is not recognised and is not migrated." });
                }

                if (Item.LastRenewalStatus == RequestState.Error && !string.IsNullOrWhiteSpace(Item.RenewalFailureMessage))
                {
                    _d.LastRunErrors.Add(Item.RenewalFailureMessage!);
                }

                ReadAccount(out var accountDescription);
                _d.AccountDescription = accountDescription;

                FindCachedCertificate(out var certificateNote, keepData: false);
                _d.CurrentCertificateNote = certificateNote;

                return _d;
            }

            // settings

            /// <summary>
            /// Settings are layered: the renewal's own, then the settings.json beside its config, then the settings.json
            /// beside the program
            /// </summary>
            private void LoadSettings()
            {
                if (Renewal.Settings is { ValueKind: JsonValueKind.Object } own)
                {
                    _settings.Add(("the renewal", own));
                }

                var candidates = new List<string> { Path.Combine(_entry.Folder.FullName, "settings.json") };
                if (_entry.Folder.Parent != null)
                {
                    candidates.Add(Path.Combine(_entry.Folder.Parent.FullName, "settings.json"));
                }

                var programFolders = _tool.FindScheduledProgramFolders().ToList();
                candidates.AddRange(programFolders.Select(f => Path.Combine(f, "settings.json")));

                var foundGlobal = false;

                foreach (var file in candidates.Distinct(StringComparer.OrdinalIgnoreCase).Where(File.Exists))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(file), JsonReadOptions);
                        _settings.Add((file, doc.RootElement.Clone()));
                        foundGlobal |= programFolders.Any(f => file.StartsWith(f, StringComparison.OrdinalIgnoreCase));
                    }
                    catch (Exception exp)
                    {
                        _d.SettingsNotes.Add($"{file} could not be read: {exp.Message}.");
                    }
                }

                var read = _settings.Where(s => s.Source != "the renewal").Select(s => s.Source).ToList();
                if (read.Any())
                {
                    _d.SettingsNotes.Add($"Settings read from {string.Join(", ", read)}.");
                }

                if (!foundGlobal)
                {
                    _d.SettingsAssumed = true;
                    _d.SettingsNotes.Add($"{Tool}'s settings.json beside the program could not be found, so its defaults are assumed where no other settings say otherwise (e.g. RSA 3072 bit keys).");
                }
            }

            private JsonElement? FindSetting(params string[] paths)
            {
                foreach (var (_, root) in _settings)
                {
                    foreach (var path in paths)
                    {
                        var current = root;
                        var found = true;

                        foreach (var part in path.Split('.'))
                        {
                            if (current.ValueKind != JsonValueKind.Object)
                            {
                                found = false;
                                break;
                            }

                            var match = current.EnumerateObject().FirstOrDefault(p => string.Equals(p.Name, part, StringComparison.OrdinalIgnoreCase));
                            if (match.Value.ValueKind == JsonValueKind.Undefined)
                            {
                                found = false;
                                break;
                            }

                            current = match.Value;
                        }

                        if (found && current.ValueKind != JsonValueKind.Null)
                        {
                            return current;
                        }
                    }
                }

                return null;
            }

            private string? GetSetting(params string[] paths) => FindSetting(paths) is { } value ? Text(value) : null;

            private int? GetIntSetting(params string[] paths) => int.TryParse(GetSetting(paths), out var value) ? value : null;

            private static string? Text(JsonElement value) => value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number => value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => null
            };

            private static string? Option(PluginOptions? options, string name) =>
                options?.Options?.FirstOrDefault(o => string.Equals(o.Key, name, StringComparison.OrdinalIgnoreCase)) is { Key: not null } match ? Text(match.Value) : null;

            private static bool IsTrue(PluginOptions? options, string name) => string.Equals(Option(options, name), "true", StringComparison.OrdinalIgnoreCase);

            private static bool Is(PluginOptions? options, string id) => string.Equals(options?.Plugin, id, StringComparison.OrdinalIgnoreCase);

            // secrets

            /// <summary>
            /// Record a ProtectedString option as a secret. A vault reference is keyed by the reference, so every option
            /// using the same entry shares one credential
            /// </summary>
            private string? AddProtectedSecret(string key, string? raw, string location)
            {
                if (string.IsNullOrEmpty(raw))
                {
                    return null;
                }

                var isVault = raw.StartsWith("vault://", StringComparison.OrdinalIgnoreCase);
                if (isVault)
                {
                    key = "vault:" + raw["vault://".Length..].ToLowerInvariant();
                    location = raw;
                }

                return AddSecret(key, location, isVault, () => isVault ? ReadVault(raw) : DecodeProtectedString(raw));
            }

            private string AddSecret(string key, string location, bool isShared, Func<(string? Value, string? Error)> read, bool isGenerated = false, Func<string?>? check = null)
            {
                if (!Secrets.ContainsKey(key))
                {
                    var secret = new SecretValue
                    {
                        CheckError = check ?? (() => read().Error),
                        Resolve = () =>
                        {
                            var (value, error) = read();
                            return value ?? throw new InvalidOperationException($"{location} could not be read: {error}");
                        }
                    };

                    Secrets[key] = secret;

                    var error = secret.CheckError();
                    _d.Secrets.Add(new SourceSecret { Key = key, Location = location, IsReadable = error == null, Reason = error, IsShared = isShared, IsGenerated = isGenerated });
                }

                return key;
            }

            private string SecretKey(string part) => $"{Renewal.Id}:{part}";

            internal static (string? Value, string? Error) DecodeProtectedString(string raw)
            {
                if (raw.StartsWith("enc-", StringComparison.Ordinal))
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        return (null, "it is encrypted with Windows data protection, which can only be read on Windows");
                    }

                    try
                    {
                        var bytes = ProtectedData.Unprotect(Convert.FromBase64String(raw["enc-".Length..]), null, DataProtectionScope.LocalMachine);
                        return (Encoding.UTF8.GetString(bytes), null);
                    }
                    catch (Exception exp) when (exp is CryptographicException || exp is FormatException)
                    {
                        return (null, "it is encrypted for another machine, so it cannot be read here");
                    }
                }

                if (raw.StartsWith("clear-", StringComparison.Ordinal))
                {
                    return (raw["clear-".Length..], null);
                }

                try
                {
                    return (Encoding.UTF8.GetString(Convert.FromBase64String(raw)), null);
                }
                catch (FormatException)
                {
                    return (null, "it is not in a recognised format");
                }
            }

            private (string? Value, string? Error) ReadVault(string reference)
            {
                var rest = reference["vault://".Length..];
                var slash = rest.IndexOf('/');
                if (slash <= 0)
                {
                    return (null, "the vault reference is not valid");
                }

                var provider = rest[..slash].ToLowerInvariant();
                var key = rest[(slash + 1)..];

                switch (provider)
                {
                    case "json":
                        {
                            var files = new List<string?> { GetSetting("Secrets.Json.FilePath"), Path.Combine(_entry.Folder.FullName, "secrets.json"), _entry.Folder.Parent == null ? null : Path.Combine(_entry.Folder.Parent.FullName, "secrets.json") };
                            var file = files.FirstOrDefault(f => !string.IsNullOrWhiteSpace(f) && File.Exists(f));

                            if (file == null)
                            {
                                return (null, "secrets.json was not found");
                            }

                            using var doc = JsonDocument.Parse(File.ReadAllText(file), JsonReadOptions);
                            var entries = doc.RootElement.ValueKind == JsonValueKind.Array
                                ? doc.RootElement
                                : doc.RootElement.EnumerateObject().FirstOrDefault(p => string.Equals(p.Name, "Entries", StringComparison.OrdinalIgnoreCase)).Value;

                            if (entries.ValueKind != JsonValueKind.Array)
                            {
                                return (null, $"{file} is not in a recognised format");
                            }

                            foreach (var item in entries.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Object))
                            {
                                var props = item.EnumerateObject().ToList();
                                var entryKey = props.FirstOrDefault(p => string.Equals(p.Name, "Key", StringComparison.OrdinalIgnoreCase)).Value;

                                if (entryKey.ValueKind == JsonValueKind.String && string.Equals(entryKey.GetString(), key, StringComparison.OrdinalIgnoreCase))
                                {
                                    var secret = props.FirstOrDefault(p => string.Equals(p.Name, "Secret", StringComparison.OrdinalIgnoreCase)).Value;
                                    return secret.ValueKind == JsonValueKind.String ? DecodeProtectedString(secret.GetString()!) : (null, "the entry has no secret");
                                }
                            }

                            return (null, $"there is no entry {key} in {file}");
                        }

                    case "environment":
                        {
                            var value = Environment.GetEnvironmentVariable(key);
                            return string.IsNullOrEmpty(value) ? (null, $"the environment variable {key} is not set for this service") : (value, null);
                        }

                    case "script":
                        return (null, $"{Tool} gets it by running a script, which is not run here");

                    default:
                        return (null, $"the secret store {provider} is not recognised");
                }
            }

            // target, order and request

            private void DescribeTarget()
            {
                var target = Renewal.TargetPluginOptions;

                _d.Identifiers = (Item.RequestConfig?.SubjectAlternativeNames ?? [])
                    .Concat(Item.RequestConfig?.SubjectIPAddresses ?? [])
                    .Prepend(Item.RequestConfig?.PrimaryDomain)
                    .Where(i => !string.IsNullOrWhiteSpace(i))
                    .Select(i => i!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                _d.IdentifierSource = target?.AlternativeNames?.Count > 0 && IsMainOrder(_entry.OrderName) ? "renewal" : !string.IsNullOrWhiteSpace(Item.CertificateThumbprintHash) ? "certificate" : "request";

                if (Is(target, ManualTargetPlugin))
                {
                    return;
                }

                if (Is(target, IisTargetPlugin) || LegacyIisTargetPlugins.Any(p => Is(target, p)))
                {
                    _d.IdentifiersFollowServerBindings = true;

                    var sites = target!.GetStringList("IncludeSiteIds") ?? (Option(target, "SiteId") is { } site ? [site] : []);
                    if (sites.Count == 1)
                    {
                        _d.ServerSiteId = sites[0];
                    }

                    return;
                }

                if (Is(target, CsrTargetPlugin))
                {
                    var csrFile = Option(target, "CsrFile");
                    var pkFile = Option(target, "PkFile");

                    try
                    {
                        _d.CustomCsr = File.ReadAllText(csrFile!);
                    }
                    catch (Exception exp)
                    {
                        _d.Unrecognised.Add(new SourceUnrecognised { Category = "Certificate", Description = $"The certificate request file {csrFile} could not be read: {exp.Message}", IsBlocker = true });
                    }

                    if (!string.IsNullOrWhiteSpace(pkFile))
                    {
                        _d.CustomPrivateKeySecret = AddSecret($"file:{pkFile}", pkFile!, false, () =>
                        {
                            try
                            {
                                return (File.ReadAllText(pkFile!), null);
                            }
                            catch (Exception exp)
                            {
                                return (null, exp.Message);
                            }
                        });
                    }
                    else
                    {
                        _d.Unrecognised.Add(new SourceUnrecognised { Category = "Certificate", Description = "The renewal uses a certificate request without a private key file, which cannot migrate.", IsBlocker = true });
                    }

                    return;
                }

                _d.Unrecognised.Add(new SourceUnrecognised { Category = "Certificate", Description = $"The target plugin {target?.Plugin} is not recognised.", IsBlocker = true });
            }

            private void DescribeOrder()
            {
                var order = Renewal.OrderPluginOptions;
                if (order?.Plugin != null && !SplitOrderPlugins.ContainsKey(order.Plugin) && !Is(order, "b705fa7c-1152-4436-8913-e433d7f84c82"))
                {
                    _d.Unrecognised.Add(new SourceUnrecognised { Category = "Certificate", Description = $"The order plugin {order.Plugin} is not recognised.", IsBlocker = true });
                }
            }

            private void DescribeCsr()
            {
                var csr = Renewal.CsrPluginOptions;
                if (csr == null)
                {
                    return;
                }

                _d.ReusePrivateKey = IsTrue(csr, "ReusePrivateKey");
                _d.OcspMustStaple = IsTrue(csr, "OcspMustStaple");

                if (Is(csr, RsaCsrPlugin))
                {
                    _d.KeyType = "rsa";
                    _d.RsaKeyBits = GetIntSetting("Csr.Rsa.KeyBits", "Security.RSAKeyBits");
                }
                else if (Is(csr, EcCsrPlugin))
                {
                    _d.KeyType = "ec";
                    _d.EcCurve = GetSetting("Csr.Ec.CurveName", "Security.ECCurve");
                }
                else
                {
                    _d.Unrecognised.Add(new SourceUnrecognised { Category = "Certificate", Description = $"The CSR plugin {csr.Plugin} is not recognised.", IsBlocker = true });
                }
            }

            private void DescribeSettings()
            {
                _d.PreferredIssuer = GetSetting("Acme.PreferredIssuer");
                _d.CertificateProfile = GetSetting("Acme.CertificateProfile");
                _d.ValidDays = GetIntSetting("Order.DefaultValidDays");
                _d.RenewalDays = GetIntSetting("ScheduledTask.RenewalDays");

                if (Renewal.Settings is { ValueKind: JsonValueKind.Object } own)
                {
                    foreach (var path in Flatten(own, ""))
                    {
                        if (!HandledSettingPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                        {
                            _d.UnmappedSettings.Add($"The renewal sets {path}, which has no equivalent here.");
                        }
                    }
                }
            }

            private static IEnumerable<string> Flatten(JsonElement element, string prefix)
            {
                foreach (var property in element.EnumerateObject())
                {
                    var path = prefix.Length == 0 ? property.Name : $"{prefix}.{property.Name}";

                    if (property.Value.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var child in Flatten(property.Value, path))
                        {
                            yield return child;
                        }
                    }
                    else if (property.Value.ValueKind != JsonValueKind.Null)
                    {
                        yield return path;
                    }
                }
            }

            // validation

            /// <summary>
            /// validation.json chooses validation per identifier, overriding the renewal's own validation for the
            /// identifiers an entry matches
            /// </summary>
            private void DescribeValidations()
            {
                var rules = LoadValidationRules();
                var remaining = _d.Identifiers.ToList();

                foreach (var rule in rules)
                {
                    var matched = remaining.Where(rule.Matches).ToList();
                    if (!matched.Any())
                    {
                        continue;
                    }

                    remaining = remaining.Except(matched).ToList();
                    DescribeValidation(rule.Options, matched, $"validation.json entry {rule.Index + 1}", $"validation.json:{rule.Index}", isShared: true);
                }

                if (remaining.Any())
                {
                    DescribeValidation(Renewal.ValidationPluginOptions, remaining.Count == _d.Identifiers.Count ? null : remaining, "renewal", SecretKey("validation"), isShared: false);
                }
            }

            private sealed record ValidationRule(int Index, int Priority, Regex? Regex, PluginOptions Options)
            {
                public bool Matches(string identifier) => Regex?.IsMatch(identifier) == true;
            }

            private List<ValidationRule> LoadValidationRules()
            {
                var rules = new List<ValidationRule>();
                var file = new[] { _entry.Folder.FullName, _entry.Folder.Parent?.FullName }
                    .Where(f => f != null)
                    .Select(f => Path.Combine(f!, "validation.json"))
                    .FirstOrDefault(File.Exists);

                if (file == null)
                {
                    return rules;
                }

                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(file), JsonReadOptions);
                    var entries = doc.RootElement.ValueKind == JsonValueKind.Array
                        ? doc.RootElement
                        : doc.RootElement.EnumerateObject().FirstOrDefault(p => string.Equals(p.Name, "Options", StringComparison.OrdinalIgnoreCase)).Value;

                    if (entries.ValueKind != JsonValueKind.Array)
                    {
                        return rules;
                    }

                    var index = 0;
                    foreach (var entry in entries.EnumerateArray())
                    {
                        var props = entry.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.OrdinalIgnoreCase);
                        var priority = props.TryGetValue("Priority", out var p) && p.TryGetInt32(out var value) ? value : 0;
                        var regexText = props.TryGetValue("Regex", out var r) ? Text(r) : null;
                        var pattern = props.TryGetValue("Pattern", out var pt) ? Text(pt) : null;

                        if (string.IsNullOrWhiteSpace(regexText) && !string.IsNullOrWhiteSpace(pattern))
                        {
                            var parts = pattern!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                .Select(x => Regex.Escape(x).Replace("\\*", ".*").Replace("\\?", "."));
                            regexText = $"^({string.Join("|", parts)})$";
                        }

                        if (props.TryGetValue("ValidationPluginOptions", out var options) && options.ValueKind == JsonValueKind.Object && !string.IsNullOrWhiteSpace(regexText))
                        {
                            rules.Add(new ValidationRule(index, priority, new Regex(regexText!), JsonUtils.Deserialize<PluginOptions>(options.GetRawText())!));
                        }

                        index++;
                    }
                }
                catch (Exception exp)
                {
                    _d.Unrecognised.Add(new SourceUnrecognised { Category = "Validation", Description = $"{file} could not be read: {exp.Message}. Any validation it sets is not migrated.", IsBlocker = true });
                }

                return rules.OrderBy(r => r.Priority).ThenBy(r => r.Index).ToList();
            }

            private void DescribeValidation(PluginOptions? options, List<string>? identifiers, string origin, string secretPrefix, bool isShared)
            {
                var validation = new SourceValidation { Identifiers = identifiers, Origin = origin, SourceName = options?.Plugin ?? "none" };
                var plugin = options?.Plugin ?? "";

                if (Is(options, FileSystemValidationPlugin))
                {
                    validation.Kind = SourceValidationKinds.HttpFileSystem;
                    validation.SourceName = "File system";

                    if (Option(options, "Path") is { Length: > 0 } path)
                    {
                        validation.Parameters[SourceSettingNames.Path] = path;
                    }

                    if (IsTrue(options, "CopyWebConfig"))
                    {
                        validation.Notes.Add($"{Tool} copies a web.config into the challenge folder. This instance configures the folder for extensionless files itself, with its own web.config.");
                    }
                }
                else if (Is(options, SelfHostingValidationPlugin))
                {
                    validation.Kind = SourceValidationKinds.HttpSelfHosting;
                    validation.SourceName = "Self-hosting";
                    validation.Parameters["Port"] = Option(options, "Port") ?? "80";

                    if (IsTrue(options, "Https"))
                    {
                        validation.Notes.Add($"{Tool} answers challenges over https. The http challenge server here answers over http on port 80.");
                    }
                }
                else if (UnsupportedHttpValidationPlugins.TryGetValue(plugin, out var name))
                {
                    validation.Kind = SourceValidationKinds.HttpUnsupported;
                    validation.SourceName = name;
                }
                else if (Is(options, TlsValidationPlugin))
                {
                    validation.Kind = SourceValidationKinds.TlsAlpn;
                    validation.SourceName = "tls-alpn-01";
                }
                else if (Is(options, NoValidationPlugin))
                {
                    validation.Kind = SourceValidationKinds.None;
                    validation.SourceName = "None";
                }
                else if (Is(options, ManualDnsValidationPlugin))
                {
                    validation.Kind = SourceValidationKinds.Manual;
                    validation.SourceName = "Manual";
                }
                else if (Is(options, AcmeDnsValidationPlugin))
                {
                    DescribeAcmeDns(options!, identifiers ?? _d.Identifiers, origin);
                    return;
                }
                else if (Is(options, ScriptValidationPlugin))
                {
                    DescribeScriptDns(options!, validation);
                }
                else if (MigrationCatalogue.GetWinAcmeDnsAlias(plugin) is { } alias)
                {
                    DescribeDns(options!, alias, validation, secretPrefix, isShared);
                }
                else
                {
                    validation.Kind = SourceValidationKinds.Unknown;
                }

                _d.Validations.Add(validation);
            }

            private void DescribeDns(PluginOptions options, DnsProviderAlias alias, SourceValidation validation, string secretPrefix, bool isShared)
            {
                validation.Kind = SourceValidationKinds.Dns;
                validation.DnsProvider = alias.Key;
                validation.SourceName = MigrationCatalogue.GetDnsProvider(alias.Key)?.Title ?? alias.Key;

                var map = new Dictionary<string, string>(alias.Options, StringComparer.OrdinalIgnoreCase);

                // simple-acme's Hetzner plugin can use the Hetzner Cloud API instead
                if (Is(options, HetznerValidationPlugin) && IsTrue(options, "UseHetznerCloud"))
                {
                    validation.DnsProvider = "hetznercloud";
                    validation.SourceName = "Hetzner Cloud DNS";
                    map["ApiToken"] = "HCToken";
                    map["UseHetznerCloud"] = "";
                }

                foreach (var (optionName, value) in options.Options ?? [])
                {
                    if (alias.AmbientAuthOptions.Contains(optionName, StringComparer.OrdinalIgnoreCase))
                    {
                        var text = Text(value);
                        var isSet = value.ValueKind == JsonValueKind.True || (value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(text));

                        if (isSet && (optionName != "IAMRole" || string.IsNullOrWhiteSpace(Option(options, "AccessKeyId"))))
                        {
                            validation.AmbientAuthentication = optionName == "UseMsi" ? "with a managed identity" : $"with the machine's IAM role {text}";
                        }

                        continue;
                    }

                    if (!map.TryGetValue(optionName, out var parameter))
                    {
                        validation.UnmappedOptions.Add(optionName);
                        continue;
                    }

                    if (parameter.Length == 0 || value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }

                    var raw = Text(value);
                    if (raw == null)
                    {
                        validation.UnmappedOptions.Add(optionName);
                        continue;
                    }

                    if (ProtectedOptions.Contains(optionName))
                    {
                        var key = AddProtectedSecret($"{secretPrefix}.{optionName}", raw, $"{validation.SourceName} {optionName} ({(isShared ? validation.Origin : "renewal file")})");
                        if (key != null)
                        {
                            validation.SecretParameters[parameter] = key;
                        }
                    }
                    else
                    {
                        if (alias.ValueMaps.TryGetValue(parameter, out var values))
                        {
                            if (values.TryGetValue(raw, out var mapped))
                            {
                                raw = mapped;
                            }
                            else
                            {
                                validation.Notes.Add($"{optionName} {raw} is not recognised, so {values.Values.First()} is assumed.");
                                raw = values.Values.First();
                            }
                        }

                        validation.Parameters[parameter] = raw;
                    }
                }

                if (Is(options, Route53ValidationPlugin) && validation.Parameters.ContainsKey("rolearn"))
                {
                    validation.Parameters["useassumerole"] = "true";
                }
            }

            private void DescribeAcmeDns(PluginOptions options, List<string> identifiers, string origin)
            {
                var baseUri = Option(options, "BaseUri");

                foreach (var identifier in identifiers)
                {
                    var validation = new SourceValidation
                    {
                        Kind = SourceValidationKinds.Dns,
                        DnsProvider = "acme-dns",
                        SourceName = "acme-dns",
                        Identifiers = [identifier],
                        Origin = origin
                    };

                    if (!string.IsNullOrWhiteSpace(baseUri))
                    {
                        validation.Parameters["api"] = baseUri!;
                    }

                    var registration = FindAcmeDnsRegistration(baseUri, identifier);
                    validation.SecretParameters["credentials_json"] = AddSecret($"acme-dns:{identifier}", registration ?? $"acme-dns registration for {identifier}", true, () =>
                    {
                        if (registration == null)
                        {
                            return (null, $"no acme-dns registration was found for {identifier}");
                        }

                        try
                        {
                            return (File.ReadAllText(registration), null);
                        }
                        catch (Exception exp)
                        {
                            return (null, exp.Message);
                        }
                    });

                    _d.Validations.Add(validation);
                }
            }

            private string? FindAcmeDnsRegistration(string? baseUri, string identifier)
            {
                var name = identifier.StartsWith("*.", StringComparison.Ordinal) ? identifier[2..] : identifier;
                var server = baseUri == null ? null : CleanUri(baseUri);

                try
                {
                    var matches = Directory.GetFiles(_tool._settingsPath, $"{name}.json", SearchOption.AllDirectories)
                        .Where(f => f.Contains($"{Path.DirectorySeparatorChar}acme-dns{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    return matches.FirstOrDefault(f => server != null && f.Contains(server, StringComparison.OrdinalIgnoreCase)) ?? matches.FirstOrDefault();
                }
                catch (Exception)
                {
                    return null;
                }
            }

            private static string CleanUri(string uri)
            {
                var text = Regex.Replace(uri, "^https?://", "", RegexOptions.IgnoreCase).TrimEnd('/');
                return string.Concat(text.Split(Path.GetInvalidFileNameChars())).Replace("/", "");
            }

            private void DescribeScriptDns(PluginOptions options, SourceValidation validation)
            {
                validation.SourceName = "Script";

                if (string.Equals(Option(options, "ChallengeType"), "http-01", StringComparison.OrdinalIgnoreCase))
                {
                    validation.Kind = SourceValidationKinds.HttpUnsupported;
                    validation.SourceName = "Script (http-01)";
                    return;
                }

                validation.Kind = SourceValidationKinds.Dns;
                validation.DnsProvider = "script";

                var common = Option(options, "Script");
                var create = Option(options, "CreateScript") ?? common;
                var delete = Option(options, "DeleteScript") ?? common;
                var createArgs = Option(options, "CreateScriptArguments") ?? "create {Identifier} {RecordName} {Token}";
                var deleteArgs = Option(options, "DeleteScriptArguments") ?? "delete {Identifier} {RecordName} {Token}";

                foreach (var args in new[] { createArgs, deleteArgs })
                {
                    if (args.Contains("vault://", StringComparison.OrdinalIgnoreCase))
                    {
                        _d.Unrecognised.Add(new SourceUnrecognised { Category = "Validation", Description = "The DNS script's arguments include a secret from the secret store, which would have to be written into a script here in plain text. Change the script to read the secret itself.", IsBlocker = true });
                        return;
                    }

                    if (args.Contains("{NodeName}", StringComparison.OrdinalIgnoreCase))
                    {
                        validation.Notes.Add("The script's {NodeName} argument is passed the full record name, as the zone is not known here.");
                    }

                    if (args.Contains("{ZoneName}", StringComparison.OrdinalIgnoreCase))
                    {
                        validation.Notes.Add("The script's {ZoneName} argument is passed the item's DNS zone id, which is empty unless set on the item.");
                    }
                }

                if (string.IsNullOrWhiteSpace(create))
                {
                    _d.Unrecognised.Add(new SourceUnrecognised { Category = "Validation", Description = "The DNS script validation has no script.", IsBlocker = true });
                    return;
                }

                validation.SecretParameters["createscriptpath"] = AddWrapper("dns-create", create!, () => WriteDnsWrapper("create", create!, createArgs));

                if (!string.IsNullOrWhiteSpace(delete))
                {
                    validation.SecretParameters["deletescriptpath"] = AddWrapper("dns-delete", delete!, () => WriteDnsWrapper("delete", delete!, deleteArgs));
                }
            }

            private string AddWrapper(string name, string script, Func<string> write) =>
                AddSecret(SecretKey($"wrapper-{name}"), $"wrapper for {script}", false, () => (write(), null), isGenerated: true,
                    check: () => File.Exists(script) ? null : $"the script {script} was not found");

            private string WrapperPath(string name, string extension)
            {
                var folder = Path.Combine(EnvironmentUtil.EnsuredAppDataPath(), "scripts", "migrated");
                Directory.CreateDirectory(folder);
                return Path.Combine(folder, $"{_tool.ClientName}-{Renewal.Id}-{name}{extension}");
            }

            /// <summary>
            /// The script DNS provider here runs a program with "{identifier} {record name} {record value} {zone id}", so
            /// the wrapper runs the source's script with the arguments it was set up with instead
            /// </summary>
            private string WriteDnsWrapper(string action, string script, string arguments)
            {
                var isPowerShell = script.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase);
                string path;
                string content;

                if (OperatingSystem.IsWindows())
                {
                    var args = arguments.Replace("%", "%%")
                        .Replace("{Identifier}", "%1", StringComparison.OrdinalIgnoreCase)
                        .Replace("{RecordName}", "%2", StringComparison.OrdinalIgnoreCase)
                        .Replace("{NodeName}", "%2", StringComparison.OrdinalIgnoreCase)
                        .Replace("{Token}", "%3", StringComparison.OrdinalIgnoreCase)
                        .Replace("{ZoneName}", "%4", StringComparison.OrdinalIgnoreCase);

                    var command = isPowerShell ? $"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{script}\" {args}" : $"\"{script}\" {args}";

                    path = WrapperPath($"dns-{action}", ".cmd");
                    content = $"@echo off\r\nrem Created by Certify The Web from {Tool} renewal {Renewal.Id}.\r\nrem Runs the original DNS script with its original arguments.\r\n{command}\r\nexit /b %ERRORLEVEL%\r\n";
                }
                else
                {
                    var args = arguments
                        .Replace("{Identifier}", "\"$1\"", StringComparison.OrdinalIgnoreCase)
                        .Replace("{RecordName}", "\"$2\"", StringComparison.OrdinalIgnoreCase)
                        .Replace("{NodeName}", "\"$2\"", StringComparison.OrdinalIgnoreCase)
                        .Replace("{Token}", "\"$3\"", StringComparison.OrdinalIgnoreCase)
                        .Replace("{ZoneName}", "\"$4\"", StringComparison.OrdinalIgnoreCase);

                    var command = isPowerShell ? $"pwsh -NoProfile -File '{script}' {args}" : $"'{script}' {args}";

                    path = WrapperPath($"dns-{action}", ".sh");
                    content = $"#!/bin/sh\n# Created by Certify The Web from {Tool} renewal {Renewal.Id}.\n# Runs the original DNS script with its original arguments.\nexec {command}\n";
                }

                File.WriteAllText(path, content);

                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
                }

                return path;
            }

            // stores and installation

            private (string Type, string Path)? _firstStore;

            private void DescribeStore(PluginOptions options, int index)
            {
                var kind = options.Plugin != null && StorePlugins.TryGetValue(options.Plugin, out var k) ? k : SourceOutputKinds.Unknown;
                var output = new SourceOutput { Kind = kind, SourceName = kind == SourceOutputKinds.Unknown ? options.Plugin ?? "unknown" : kind };
                var prefix = SecretKey($"store{index}");

                if (IsTrue(options, "KeepExisting"))
                {
                    output.Settings[SourceSettingNames.KeepExisting] = "true";
                }

                switch (kind)
                {
                    case SourceOutputKinds.CertificateStore:
                        {
                            var store = Option(options, "StoreName") ?? GetSetting("Store.CertificateStore.DefaultStore", "Store.DefaultCertificateStore");

                            if (store == null)
                            {
                                var hasIis = Renewal.InstallationPluginOptions?.Any(i => InstallationPlugins.GetValueOrDefault(i.Plugin ?? "") == SourceInstallationKinds.Iis) == true;
                                store = hasIis ? "WebHosting" : "My";
                                output.Notes.Add($"{Tool} chooses the store itself, presumably {store}.");
                            }

                            output.Settings[SourceSettingNames.StoreName] = store;
                            output.ListSettings[SourceSettingNames.AclFullControl] = options.GetStringList("AclFullControl") ?? [];
                            output.ListSettings[SourceSettingNames.AclRead] = options.GetStringList("AclRead") ?? [];
                            _firstStore ??= ("CertificateStore", store);
                            break;
                        }

                    case SourceOutputKinds.PemFiles:
                    case SourceOutputKinds.PfxFile:
                    case SourceOutputKinds.CentralSsl:
                        {
                            var setting = kind switch
                            {
                                SourceOutputKinds.PemFiles => "Store.PemFiles.DefaultPath",
                                SourceOutputKinds.PfxFile => "Store.PfxFile.DefaultPath",
                                _ => "Store.CentralSsl.DefaultPath"
                            };

                            var path = Option(options, "Path") ?? GetSetting(setting);
                            if (path != null)
                            {
                                output.Settings[SourceSettingNames.Path] = path;
                                _firstStore ??= (kind, path);
                            }

                            if (Option(options, "FileName") is { Length: > 0 } fileName)
                            {
                                output.Settings[SourceSettingNames.FileName] = fileName;
                            }

                            var passwordOption = kind switch
                            {
                                SourceOutputKinds.PemFiles => "PemPassword",
                                SourceOutputKinds.PfxFile => "PfxPassword",
                                _ => "PfxPasswordProtected"
                            };

                            if (AddProtectedSecret($"{prefix}.{passwordOption}", Option(options, passwordOption), $"{kind} password (renewal file)") is { } password)
                            {
                                output.SecretSettings[SourceSettingNames.Password] = password;
                            }

                            break;
                        }

                    case SourceOutputKinds.KeyVault:
                        {
                            var environment = Option(options, "AzureEnvironment");
                            var service = environment == null ? "global" : MigrationCatalogue.GetWinAcmeDnsAlias("aa57b028-45fb-4aca-9cac-a63d94c76b4a")!.ValueMaps["service"].GetValueOrDefault(environment);

                            if (service == null)
                            {
                                output.Notes.Add($"AzureEnvironment {environment} is not recognised, so the global Azure cloud is assumed.");
                                service = "global";
                            }

                            output.Settings[SourceSettingNames.AzureService] = service;
                            output.Settings[SourceSettingNames.VaultName] = Option(options, "VaultName") ?? "";
                            output.Settings[SourceSettingNames.CertificateName] = Option(options, "CertificateName") ?? "";
                            output.Settings[SourceSettingNames.TenantId] = Option(options, "TenantId") ?? "";
                            output.Settings[SourceSettingNames.ClientId] = Option(options, "ClientId") ?? "";

                            if (IsTrue(options, "UseMsi"))
                            {
                                output.AmbientAuthentication = "with a managed identity";
                            }
                            else if (AddProtectedSecret($"{prefix}.SecretSafe", Option(options, "SecretSafe"), "Key Vault client secret (renewal file)") is { } secret)
                            {
                                output.SecretSettings[SourceSettingNames.ClientSecret] = secret;
                            }

                            if (Option(options, "CertificatePassword") != null)
                            {
                                output.Notes.Add("The certificate is uploaded to Key Vault without the password set on it.");
                            }

                            break;
                        }
                }

                _d.Outputs.Add(output);
            }

            private void DescribeInstallation(PluginOptions options, int index)
            {
                var kind = options.Plugin != null && InstallationPlugins.TryGetValue(options.Plugin, out var k) ? k : SourceInstallationKinds.Unknown;
                var installation = new SourceInstallation { Kind = kind, SourceName = kind == SourceInstallationKinds.Unknown ? options.Plugin ?? "unknown" : kind };

                switch (kind)
                {
                    case SourceInstallationKinds.Iis:
                        foreach (var (option, setting) in new[] { ("SiteId", SourceSettingNames.SiteId), ("NewBindingIp", SourceSettingNames.BindingIp), ("NewBindingPort", SourceSettingNames.BindingPort) })
                        {
                            if (Option(options, option) is { Length: > 0 } value)
                            {
                                installation.Settings[setting] = value;
                            }
                        }

                        break;

                    case SourceInstallationKinds.Script:
                        {
                            var script = Option(options, "Script");
                            var parameters = Option(options, "ScriptParameters") ?? "";

                            if (string.IsNullOrWhiteSpace(script))
                            {
                                break;
                            }

                            installation.Settings[SourceSettingNames.Script] = script!;

                            if (parameters.Contains("vault://", StringComparison.OrdinalIgnoreCase))
                            {
                                _d.Unrecognised.Add(new SourceUnrecognised { Category = "Installation", Description = "The installation script's arguments include a secret from the secret store, which would have to be written into a script here in plain text. Change the script to read the secret itself.", IsBlocker = true });
                                break;
                            }

                            if (Regex.IsMatch(parameters, @"\{(CachePassword|1)\}", RegexOptions.IgnoreCase))
                            {
                                installation.Notes.Add("The script is passed the certificate file's password, which is empty unless a certificate password is set on the item.");
                            }

                            if (Regex.IsMatch(parameters, @"\{(StorePath|StoreType|3)\}", RegexOptions.IgnoreCase))
                            {
                                installation.Notes.Add($"The script is passed {Tool}'s store type and path as they were, which may no longer be where the certificate is written.");
                            }

                            installation.SecretSettings[SourceSettingNames.ScriptWrapper] = AddWrapper($"install{index}", script!, () => WriteInstallWrapper(index, script!, parameters));
                            break;
                        }
                }

                _d.Installations.Add(installation);
            }

            /// <summary>
            /// A PowerShell task script which runs the source's installation script with the arguments the source would
            /// give it, from the result of the renewal here
            /// </summary>
            private string WriteInstallWrapper(int index, string script, string parameters)
            {
                static string Quote(string? value) => $"'{(value ?? "").Replace("'", "''")}'";

                var content = $@"# Created by Certify The Web from {Tool} renewal {Renewal.Id}.
# Runs the original installation script with the arguments {Tool} gave it.
param($result)

$item = $result.ManagedItem
$cacheFile = [string]$item.CertificatePath
$tokens = [ordered]@{{
    'CertCommonName' = [string]$item.RequestConfig.PrimaryDomain
    'CachePassword' = ''
    'CacheFile' = $cacheFile
    'StorePath' = {Quote(_firstStore?.Path)}
    'CertFriendlyName' = [string]$item.CertificateFriendlyName
    'CertThumbprint' = [string]$item.CertificateThumbprintHash
    'CacheFolder' = $(if ($cacheFile) {{ Split-Path $cacheFile }} else {{ '' }})
    'RenewalId' = {Quote(Renewal.Id)}
    'StoreType' = {Quote(_firstStore?.Type)}
    'OldCertCommonName' = [string]$item.RequestConfig.PrimaryDomain
    'OldCertFriendlyName' = ''
    'OldCertThumbprint' = [string]$item.CertificatePreviousThumbprintHash
}}

$arguments = {Quote(parameters)}
$names = @($tokens.Keys)
for ($i = 0; $i -lt 8; $i++) {{ $arguments = $arguments.Replace(""{{$i}}"", $tokens[$names[$i]]) }}
foreach ($name in $names) {{ $arguments = $arguments -ireplace [regex]::Escape(""{{$name}}""), $tokens[$name].Replace('$', '$$') }}

$script = {Quote(script)}
if ($script.EndsWith('.ps1', [StringComparison]::OrdinalIgnoreCase)) {{
    $exe = $(if ($IsLinux -or $IsMacOS) {{ 'pwsh' }} else {{ 'powershell.exe' }})
    $exeArgs = ""-NoProfile -ExecutionPolicy Bypass -File `""$script`"" $arguments""
}} else {{
    $exe = $script
    $exeArgs = $arguments
}}

$psi = New-Object System.Diagnostics.ProcessStartInfo $exe, $exeArgs
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$process = [System.Diagnostics.Process]::Start($psi)
$output = $process.StandardOutput.ReadToEndAsync()
$errors = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()

if ($output.Result) {{ Write-Output $output.Result }}
if ($process.ExitCode -ne 0) {{ throw ""$script exited with code $($process.ExitCode). $($errors.Result)"" }}
";

                var path = WrapperPath($"install{index}", ".ps1");
                File.WriteAllText(path, content);
                return path;
            }

            // account and certificate

            /// <summary>
            /// The account the renewal uses, as a PEM key and account URL
            /// </summary>
            internal SourceAccountMaterial? ReadAccount(out string description)
            {
                var name = string.IsNullOrWhiteSpace(Renewal.Account) ? "" : $"{Renewal.Account}.";
                var signerFile = Path.Combine(_entry.Folder.FullName, $"{name}Signer_v2");
                var registrationFile = Path.Combine(_entry.Folder.FullName, $"{name}Registration_v2");

                try
                {
                    if (!File.Exists(signerFile) || !File.Exists(registrationFile))
                    {
                        description = $"{signerFile} or {registrationFile} was not found";
                        return null;
                    }

                    var (signerJson, signerError) = DecodeProtectedString(File.ReadAllText(signerFile).Trim());
                    if (signerJson == null)
                    {
                        description = $"{signerFile}: {signerError}";
                        return null;
                    }

                    var keyPem = ConvertAccountKey(signerJson);

                    var registrationText = File.ReadAllText(registrationFile).Trim();
                    if (!registrationText.StartsWith('{'))
                    {
                        registrationText = DecodeProtectedString(registrationText).Value ?? registrationText;
                    }

                    using var registration = JsonDocument.Parse(registrationText, JsonReadOptions);
                    var props = registration.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.OrdinalIgnoreCase);

                    var accountUri = props.TryGetValue("Kid", out var kid) ? Text(kid) : props.TryGetValue("Location", out var location) ? Text(location) : null;
                    if (string.IsNullOrWhiteSpace(accountUri))
                    {
                        description = $"{registrationFile} does not include the account URL";
                        return null;
                    }

                    string? email = null;
                    if (props.TryGetValue("Payload", out var payload) && payload.ValueKind == JsonValueKind.Object)
                    {
                        var contact = payload.EnumerateObject().FirstOrDefault(p => string.Equals(p.Name, "Contact", StringComparison.OrdinalIgnoreCase)).Value;
                        if (contact.ValueKind == JsonValueKind.Array)
                        {
                            email = contact.EnumerateArray().Select(Text).FirstOrDefault(c => c?.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) == true)?["mailto:".Length..];
                        }
                    }

                    _d.AccountReadable = true;
                    description = string.IsNullOrWhiteSpace(Renewal.Account) ? accountUri! : $"{Renewal.Account}, {accountUri}";

                    return new SourceAccountMaterial { AccountUri = accountUri!, AccountKeyPem = keyPem, EmailAddress = email };
                }
                catch (Exception exp)
                {
                    description = $"the account files could not be read: {exp.Message}";
                    return null;
                }
            }

            /// <summary>
            /// Convert an exported account signer ({"KeyType","KeyExport"}) to a PKCS#8 PEM key. EC keys export as JSON of
            /// the curve size and key values, RSA keys as .NET's RSA key XML
            /// </summary>
            internal static string ConvertAccountKey(string signerJson)
            {
                using var signer = JsonDocument.Parse(signerJson, JsonReadOptions);
                var props = signer.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.OrdinalIgnoreCase);

                var keyType = props.TryGetValue("KeyType", out var kt) ? Text(kt) ?? "" : "";
                var export = props.TryGetValue("KeyExport", out var ke) ? (ke.ValueKind == JsonValueKind.String ? ke.GetString() : ke.GetRawText()) : null;

                if (string.IsNullOrWhiteSpace(export))
                {
                    throw new InvalidOperationException("The account key was not found in the signer.");
                }

                if (keyType.StartsWith("ES", StringComparison.OrdinalIgnoreCase))
                {
                    using var ec = JsonDocument.Parse(export, JsonReadOptions);
                    var values = ec.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.OrdinalIgnoreCase);
                    var hashSize = values.TryGetValue("HashSize", out var hs) && hs.TryGetInt32(out var size) ? size : int.Parse(keyType[2..]);

                    var curve = hashSize switch
                    {
                        256 => ECCurve.NamedCurves.nistP256,
                        384 => ECCurve.NamedCurves.nistP384,
                        512 or 521 => ECCurve.NamedCurves.nistP521,
                        _ => throw new InvalidOperationException($"The account key curve size {hashSize} is not supported.")
                    };

                    using var key = ECDsa.Create(new ECParameters
                    {
                        Curve = curve,
                        D = values["D"].GetBytesFromBase64(),
                        Q = new ECPoint { X = values["X"].GetBytesFromBase64(), Y = values["Y"].GetBytesFromBase64() }
                    });

                    return key.ExportPkcs8PrivateKeyPem();
                }

                if (keyType.StartsWith("RS", StringComparison.OrdinalIgnoreCase))
                {
                    using var rsa = RSA.Create();

                    if (export.TrimStart().StartsWith('<'))
                    {
                        rsa.FromXmlString(export);
                    }
                    else
                    {
                        using var json = JsonDocument.Parse(export, JsonReadOptions);
                        var values = json.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.OrdinalIgnoreCase);
                        byte[] Get(string name) => values[name].GetBytesFromBase64();

                        rsa.ImportParameters(new RSAParameters
                        {
                            Modulus = Get("Modulus"),
                            Exponent = Get("Exponent"),
                            D = Get("D"),
                            P = Get("P"),
                            Q = Get("Q"),
                            DP = Get("DP"),
                            DQ = Get("DQ"),
                            InverseQ = Get("InverseQ")
                        });
                    }

                    return rsa.ExportPkcs8PrivateKeyPem();
                }

                throw new InvalidOperationException($"The account key type {keyType} is not supported.");
            }

            private DirectoryInfo CacheFolder => new(GetSetting("Cache.Path") is { Length: > 0 } path ? path : Path.Combine(_entry.Folder.FullName, CertificateCacheFolder));

            /// <summary>
            /// Every cached file of the renewal: certificates, keys and requests
            /// </summary>
            internal List<FileInfo> FindCacheFiles()
            {
                var folder = CacheFolder;
                return folder.Exists ? folder.GetFiles($"{Renewal.Id}-*").Concat(folder.GetFiles($"{Renewal.Id}.*")).ToList() : [];
            }

            /// <summary>
            /// The certificate last issued for this item, with its key, from the tool's cache
            /// </summary>
            internal SourceCertificateMaterial? FindCachedCertificate(out string? note, bool keepData)
            {
                note = null;

                var reuseDays = GetIntSetting("Cache.ReuseDays");
                var orderPrefix = $"{Renewal.Id}-{_entry.OrderName}-";

                var candidates = FindCacheFiles()
                    .Where(f => f.Extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase))
                    .Where(f => f.Name.StartsWith(orderPrefix, StringComparison.OrdinalIgnoreCase) || (IsMainOrder(_entry.OrderName) && f.Name.Equals($"{Renewal.Id}-cache.pfx", StringComparison.OrdinalIgnoreCase)))
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .ToList();

                if (!candidates.Any())
                {
                    note = $"{Tool} has no cached copy of the certificate.";
                    return null;
                }

                var (password, passwordError) = string.IsNullOrEmpty(Renewal.PfxPasswordProtected) ? ("", null) : DecodeProtectedString(Renewal.PfxPasswordProtected);
                if (password == null)
                {
                    note = $"The cached certificate's password could not be read: {passwordError}.";
                    return null;
                }

                var thumbprint = Item.CertificateThumbprintHash;

                foreach (var file in candidates)
                {
                    try
                    {
                        var data = File.ReadAllBytes(file.FullName);
                        var collection = X509CertificateLoader.LoadPkcs12Collection(data, password, X509KeyStorageFlags.EphemeralKeySet, SourcePfxLimits);

                        try
                        {
                            var leaf = collection.FirstOrDefault(c => c.HasPrivateKey);

                            if (leaf == null)
                            {
                                note = reuseDays <= 0
                                    ? $"{Tool} is set not to cache private keys (Cache.ReuseDays), so the current certificate's key is not available."
                                    : $"{file.Name} has no private key.";
                                continue;
                            }

                            if (!string.IsNullOrWhiteSpace(thumbprint) && !leaf.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                            {
                                note = $"The cached certificate is not the one {Tool} last installed.";
                                continue;
                            }

                            _d.CurrentCertificateReadable = true;
                            _d.CurrentCertificateThumbprint = leaf.Thumbprint;
                            _d.CurrentCertificateExpiry = new DateTimeOffset(leaf.NotAfter);

                            return new SourceCertificateMaterial
                            {
                                PfxData = keepData ? data : null,
                                PfxPassword = keepData ? password : null,
                                Thumbprint = leaf.Thumbprint,
                                SourcePath = file.FullName
                            };
                        }
                        finally
                        {
                            foreach (var c in collection)
                            {
                                c.Dispose();
                            }
                        }
                    }
                    catch (CryptographicException exp)
                    {
                        note = $"{file.Name} could not be opened: {exp.Message}";
                    }
                }

                return null;
            }
        }
    }
}
