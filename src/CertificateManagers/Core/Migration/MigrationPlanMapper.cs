using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using Certify.Config;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Config.Migration;
using Certify.Plugin.CertificateManagers.Utils;

namespace Certify.Plugin.CertificateManagers.Migration
{
    /// <summary>
    /// Turns a <see cref="SourceRenewalDescription"/> into a migration plan: the item import would create, the
    /// credentials it would create, and a finding for every setting which maps, is assumed, needs input or blocks. Shared
    /// by all migration sources, so it knows nothing of any one tool
    /// </summary>
    public class MigrationPlanMapper
    {
        private readonly SourceRenewalDescription _source;
        private readonly ExternalMigrationContext _context;
        private readonly IDictionary<string, string> _inputs;
        private readonly ExternalMigrationPlan _plan;
        private readonly ManagedCertificate _item;

        private MigrationPlanMapper(SourceRenewalDescription source, ExternalMigrationContext context, IDictionary<string, string>? inputs)
        {
            _source = source;
            _context = context;
            _inputs = inputs ?? new Dictionary<string, string>();

            _item = new ManagedCertificate
            {
                Name = source.Name,
                ItemType = ManagedCertificateType.SSL_ACME,
                IncludeInAutoRenew = false,
                RequestConfig = new CertRequestConfig { Challenges = new ObservableCollection<CertRequestChallengeConfig>() },
                PostRequestTasks = new ObservableCollection<DeploymentTaskConfig>()
            };

            _plan = new ExternalMigrationPlan
            {
                SourceItemId = source.ItemId,
                SourceProviderId = source.ProviderId,
                SourceProviderTitle = source.ProviderTitle,
                SourceItemName = source.Name,
                SourcePath = source.SourcePath,
                SourceFileHash = source.FileHash,
                ProposedItem = _item,
                RelatedSourceItemIds = source.RelatedItemIds.ToList()
            };
        }

        public static ExternalMigrationPlan Map(SourceRenewalDescription source, ExternalMigrationContext context, IDictionary<string, string>? inputs = null)
        {
            var mapper = new MigrationPlanMapper(source, context, inputs);
            mapper.MapAll();
            return mapper._plan;
        }

        private string Tool => _source.ProviderTitle;

        private void MapAll()
        {
            if (_context.MigratedItems.TryGetValue(_source.ItemId, out var existing))
            {
                _plan.ExistingMigratedItemId = existing;
            }

            _plan.Secrets = _source.Secrets
                .Where(s => !s.IsGenerated)
                .Select(s => new ExternalMigrationSecretReference { Key = s.Key, Label = s.Location, IsReadable = s.IsReadable, Reason = s.Reason })
                .ToList();

            MapCertificateAuthority();
            MapIdentifiers();
            MapRequest();

            for (var i = 0; i < _source.Validations.Count; i++)
            {
                MapValidation(_source.Validations[i], i);
            }

            var hasStore = false;
            for (var i = 0; i < _source.Outputs.Count; i++)
            {
                hasStore |= MapOutput(_source.Outputs[i], i);
            }

            var hasIis = false;
            for (var i = 0; i < _source.Installations.Count; i++)
            {
                hasIis |= MapInstallation(_source.Installations[i], i);
            }

            if (!hasIis)
            {
                // without an IIS installation the source never touched bindings, so neither does the migrated item
                _item.RequestConfig.DeploymentSiteOption = hasStore ? DeploymentOption.DeploymentStoreOnly : DeploymentOption.NoDeployment;
                _item.RequestConfig.PerformAutomatedCertBinding = false;
            }

            MapSourceState();

            _plan.Steps = _plan.Findings.Select(f => new ActionStep(f.Category, f.Title, f.Description)
            {
                Key = f.Key,
                HasError = f.Level == ExternalMigrationFindingLevel.Blocker && f.IsUnresolved,
                HasWarning = f.Level == ExternalMigrationFindingLevel.Assumption || (f.Level == ExternalMigrationFindingLevel.InputNeeded && f.IsUnresolved)
            }).ToList();
        }

        private void MapCertificateAuthority()
        {
            // a built in CA, otherwise one added on this instance
            var match = _source.CaEndpoints.Select(e => CertificateAuthorityLookup.FromEndpoint(e)).FirstOrDefault(m => m != null)
                ?? _source.CaEndpoints.Select(e => CertificateAuthorityLookup.FromEndpoint(e, _context.CertificateAuthorities)).FirstOrDefault(m => m != null);

            var endpointText = _source.CaEndpoints.FirstOrDefault(e => !string.IsNullOrWhiteSpace(e)) ?? "unknown";

            if (match == null)
            {
                Add("ca", ExternalMigrationFindingLevel.Blocker, "Certificate Authority", "Certificate authority not configured",
                    $"The ACME server {endpointText} does not match a certificate authority on this instance. Add it as a custom certificate authority, then preview again.");
                return;
            }

            _item.CertificateAuthorityId = match.Value.CertificateAuthorityId;
            _item.UseStagingMode = match.Value.IsStaging;

            var caTitle = _context.CertificateAuthorities.FirstOrDefault(c => c.Id == match.Value.CertificateAuthorityId)?.Title ?? match.Value.CertificateAuthorityId;
            Add("ca", ExternalMigrationFindingLevel.Mapped, "Certificate Authority", "Certificate authority",
                $"{caTitle}{(match.Value.IsStaging ? " (staging)" : "")}, from {endpointText}.");

            var hasAccount = _context.Accounts.Any(a => a.CertificateAuthorityId == match.Value.CertificateAuthorityId && a.IsStagingAccount == match.Value.IsStaging);

            if (hasAccount)
            {
                Add("account", ExternalMigrationFindingLevel.Mapped, "Account", "Existing ACME account used",
                    $"This instance already has an account for {caTitle}, which is used instead of {Tool}'s account. A CAA record with accounturi bound to {Tool}'s account would refuse the new account.");
            }
            else if (_source.AccountReadable)
            {
                Add("account", ExternalMigrationFindingLevel.Mapped, "Account", "ACME account imported",
                    $"{Tool}'s account{(string.IsNullOrWhiteSpace(_source.AccountDescription) ? "" : $" ({_source.AccountDescription})")} is imported at import, as there is no account for {caTitle} here yet.");
            }
            else
            {
                Add("account", ExternalMigrationFindingLevel.Blocker, "Account", "No ACME account",
                    $"There is no account for {caTitle} on this instance and {Tool}'s account could not be read{(string.IsNullOrWhiteSpace(_source.AccountDescription) ? "" : $": {_source.AccountDescription}")}. Add an account for this CA, then preview again.");
            }
        }

        private void MapIdentifiers()
        {
            var names = _source.Identifiers
                .Where(i => !string.IsNullOrWhiteSpace(i))
                .Select(i => i.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (names.Count == 0)
            {
                Add("identifiers", ExternalMigrationFindingLevel.Blocker, "Certificate", "No identifiers",
                    $"The domains of this certificate could not be determined from {Tool}'s files or the certificate.");
                return;
            }

            var ips = names.Where(n => IPAddress.TryParse(n, out _)).ToList();
            var dns = names.Except(ips).ToList();

            var config = _item.RequestConfig;
            config.PrimaryDomain = dns.FirstOrDefault() ?? ips.First();
            config.SubjectAlternativeNames = dns.ToArray();
            config.SubjectIPAddresses = ips.ToArray();

            _item.DomainOptions = new ObservableCollection<DomainOption>(names.Select((n, i) => new DomainOption
            {
                Domain = n,
                IsPrimaryDomain = n == config.PrimaryDomain,
                IsManualEntry = true,
                IsSelected = true,
                Type = ips.Contains(n) ? CertIdentifierType.Ip : CertIdentifierType.Dns
            }));

            var origin = _source.IdentifierSource switch
            {
                "certificate" => "the current certificate",
                "request" => $"{Tool}'s last certificate request",
                _ => $"the {Tool} renewal"
            };

            Add("identifiers", ExternalMigrationFindingLevel.Mapped, "Certificate", "Identifiers", $"{string.Join(", ", names)}, from {origin}.");

            if (_source.IdentifiersFollowServerBindings)
            {
                Add("identifiers-fixed", ExternalMigrationFindingLevel.Assumption, "Certificate", "Identifiers become a fixed list",
                    $"{Tool} works out the identifiers again from the server's bindings at each renewal. The migrated item uses the identifiers above, so hosts bound later are not added automatically.");
            }

            if (!string.IsNullOrWhiteSpace(_source.ServerSiteId))
            {
                _item.ServerSiteId = _source.ServerSiteId;
            }

            if (!string.IsNullOrWhiteSpace(_source.OrderName))
            {
                Add("order", ExternalMigrationFindingLevel.Assumption, "Certificate", "Part of a split renewal",
                    $"{Tool} splits this renewal into {_source.RelatedItemIds.Count + 1} certificates ({_source.OrderName} is this one). Each becomes its own managed certificate, and as {Tool} disables the renewal as a whole, all of them are cut over, rolled back and removed together.");
            }
        }

        private void MapRequest()
        {
            var config = _item.RequestConfig;

            if (_source.CsrFromScript)
            {
                Add("csr", ExternalMigrationFindingLevel.Blocker, "Certificate", "Certificate request from a script",
                    $"{Tool} gets this certificate's request from a script, which cannot migrate.");
            }
            else if (!string.IsNullOrWhiteSpace(_source.CustomCsr))
            {
                config.CustomCSR = _source.CustomCsr;

                if (_source.CustomPrivateKeySecret != null)
                {
                    config.CustomPrivateKey = InlineDraft(_source.CustomPrivateKeySecret, "Custom private key");
                }

                Add("csr", ExternalMigrationFindingLevel.Assumption, "Certificate", "Custom certificate request",
                    "The certificate request and private key are copied into the item at import. A later change to the files is not picked up.");
            }
            else if (string.Equals(_source.KeyType, "ec", StringComparison.OrdinalIgnoreCase))
            {
                var keyType = MigrationCatalogue.GetEcKeyType(_source.EcCurve);

                if (keyType == null)
                {
                    config.CSRKeyAlg = "ECDSA384";
                    Add("key", ExternalMigrationFindingLevel.Assumption, "Certificate", "Key type changed",
                        $"The EC curve {_source.EcCurve} is not supported here, so new keys use P-384.");
                }
                else
                {
                    MapKeyType(keyType);
                }
            }
            else
            {
                var (keyType, isExact) = MigrationCatalogue.GetRsaKeyType(_source.RsaKeyBits);

                if (isExact)
                {
                    MapKeyType(keyType);
                }
                else
                {
                    config.CSRKeyAlg = keyType;
                    Add("key", ExternalMigrationFindingLevel.Assumption, "Certificate", "Key type changed",
                        $"RSA {_source.RsaKeyBits} bit keys are not supported here, so new keys use {StandardKeyTypes.GetDisplayName(keyType)}.");
                }
            }

            if (_source.ReusePrivateKey)
            {
                var reuse = UseSource("reuse-key", true);
                config.ReusePrivateKey = reuse;

                AddChoice("reuse-key", "Certificate", "Private key", reuse,
                    $"Reuse the key ({Tool})", "New key at each renewal (default)",
                    $"Renewals keep the same private key, as in {Tool}. When the current certificate is adopted, {Tool}'s key is kept.",
                    $"Each renewal creates a new private key. {Tool} reuses the key.");
            }

            if (_source.OcspMustStaple)
            {
                config.RequireOcspMustStaple = true;
                Add("must-staple", ExternalMigrationFindingLevel.Assumption, "Certificate", "OCSP Must-Staple",
                    "Requested as before. Some CAs no longer run OCSP and refuse orders which ask for it.");
            }

            if (!string.IsNullOrWhiteSpace(_source.PreferredIssuer))
            {
                var keep = UseSource("chain", true);
                config.PreferredChain = keep ? _source.PreferredIssuer : null;

                AddChoice("chain", "Certificate", "Preferred chain", keep,
                    $"{_source.PreferredIssuer} ({Tool})", "The CA's default chain",
                    $"{_source.PreferredIssuer}, as in {Tool}.",
                    $"The CA's default chain. {Tool} prefers {_source.PreferredIssuer}.");
            }

            if (!string.IsNullOrWhiteSpace(_source.CertificateProfile))
            {
                var keep = UseSource("profile", true);
                config.AcmeProfile = keep ? _source.CertificateProfile : null;

                AddChoice("profile", "Certificate", "Certificate profile", keep,
                    $"{_source.CertificateProfile} ({Tool})", "The CA's default profile",
                    $"{_source.CertificateProfile}, as in {Tool}.",
                    $"The CA's default profile. {Tool} requests {_source.CertificateProfile}.");
            }

            if (_source.ValidDays > 0)
            {
                var keep = UseSource("valid-days", true);
                config.PreferredExpiryDays = keep ? _source.ValidDays : null;

                AddChoice("valid-days", "Certificate", "Requested lifetime", keep,
                    $"{_source.ValidDays} days ({Tool})", "The CA's default lifetime",
                    $"{_source.ValidDays} days, as in {Tool}.",
                    $"The CA's default lifetime. {Tool} requests {_source.ValidDays} days.");
            }

            var defaultRenewal = DefaultRenewalInterval();

            if (_source.RenewalDays > 0)
            {
                // this instance's own setting by default, as the source's fixed day count does not follow shorter lifetimes
                var keep = UseSource("renewal-days", false);

                if (keep)
                {
                    _item.CustomRenewalTarget = _source.RenewalDays;
                    _item.CustomRenewalIntervalMode = "DaysAfterLastRenewal";
                }

                AddChoice("renewal-days", "Renewal", "Renewal interval", keep,
                    $"{_source.RenewalDays} days after last renewal ({Tool})", $"{DefaultRenewalInterval(brief: true)} (default)",
                    $"Renews {_source.RenewalDays} days after the last renewal, as {Tool} is set to.",
                    $"Renews {defaultRenewal}, as set for this instance. {Tool} is set to renew {_source.RenewalDays} days after the last renewal.");
            }
            else if (_source.RenewBeforeExpiryDays > 0)
            {
                var keep = UseSource("renewal-days", false);

                if (keep)
                {
                    _item.CustomRenewalTarget = _source.RenewBeforeExpiryDays;
                    _item.CustomRenewalIntervalMode = "DaysBeforeExpiry";
                }

                AddChoice("renewal-days", "Renewal", "Renewal interval", keep,
                    $"{_source.RenewBeforeExpiryDays} days before expiry ({Tool})", $"{DefaultRenewalInterval(brief: true)} (default)",
                    $"Renews {_source.RenewBeforeExpiryDays} days before expiry, as {Tool} is set to.",
                    $"Renews {defaultRenewal}, as set for this instance. {Tool} is set to renew {_source.RenewBeforeExpiryDays} days before expiry.");
            }
            else
            {
                Add("renewal-days", ExternalMigrationFindingLevel.Mapped, "Renewal", "Renewal interval",
                    $"Renews {defaultRenewal}, as set for this instance. {Tool}'s own default interval is not carried over.");
            }

            foreach (var setting in _source.UnmappedSettings)
            {
                Add($"setting-{Slug(setting)}", ExternalMigrationFindingLevel.Assumption, "Settings", "Setting not migrated", setting);
            }

            if (_source.SettingsAssumed || _source.SettingsNotes.Any())
            {
                Add("settings", _source.SettingsAssumed ? ExternalMigrationFindingLevel.Assumption : ExternalMigrationFindingLevel.Mapped, "Settings", $"{Tool} settings",
                    string.Join(" ", _source.SettingsNotes));
            }
        }

        private void MapKeyType(string keyType)
        {
            var config = _item.RequestConfig;
            var defaultKeyType = string.IsNullOrWhiteSpace(_context.DefaultKeyType) ? StandardKeyTypes.RSA256 : _context.DefaultKeyType;
            var name = StandardKeyTypes.GetDisplayName(keyType);
            var defaultName = StandardKeyTypes.GetDisplayName(defaultKeyType);

            if (keyType == defaultKeyType)
            {
                config.CSRKeyAlg = keyType;
                Add("key", ExternalMigrationFindingLevel.Mapped, "Certificate", "Key type", $"{name}, as in {Tool}.");
                return;
            }

            var keep = UseSource("key", true);

            // the default leaves the key type unset, so the item follows this instance's setting
            config.CSRKeyAlg = keep ? keyType : null;

            AddChoice("key", "Certificate", "Key type", keep,
                $"{name} ({Tool})", $"{defaultName} (default)",
                $"{name}, as in {Tool}.",
                $"{defaultName}, this instance's default. {Tool} uses {name}.");
        }

        /// <summary>
        /// This instance's renewal interval, as text following "Renews", or briefly for an option label
        /// </summary>
        private string DefaultRenewalInterval(bool brief = false)
        {
            var days = _context.RenewalIntervalDays;

            return _context.RenewalIntervalMode switch
            {
                "DaysAfterLastRenewal" => brief ? $"{days} days after last renewal" : $"{days} days after the last renewal",
                "DaysBeforeExpiry" => $"{days} days before expiry",
                _ => brief
                    ? $"At {(days > 0 ? days : RenewalIntervalModes.DefaultPercentageLifetime)}% of lifetime"
                    : $"after {(days > 0 ? days : RenewalIntervalModes.DefaultPercentageLifetime)}% of the certificate's lifetime"
            };
        }

        /// <summary>
        /// Whether a setting which can keep the source's value or use this instance's default keeps the source's value
        /// </summary>
        private bool UseSource(string key, bool sourceByDefault) =>
            _inputs.TryGetValue(key, out var value) && (value == ExternalMigrationChoices.Source || value == ExternalMigrationChoices.Default)
                ? value == ExternalMigrationChoices.Source
                : sourceByDefault;

        private void AddChoice(string key, string category, string title, bool useSource, string sourceOption, string defaultOption, string sourceDescription, string defaultDescription)
        {
            Add(key, ExternalMigrationFindingLevel.Mapped, category, title, useSource ? sourceDescription : defaultDescription);

            var finding = _plan.Findings[^1];
            finding.InputType = ExternalMigrationInputTypes.Choice;
            finding.Options =
            [
                new ExternalMigrationInputOption(ExternalMigrationChoices.Default, defaultOption),
                new ExternalMigrationInputOption(ExternalMigrationChoices.Source, sourceOption)
            ];
            finding.AppliedInput = useSource ? ExternalMigrationChoices.Source : ExternalMigrationChoices.Default;
        }

        private void MapValidation(SourceValidation validation, int index)
        {
            var key = $"validation-{index}";
            var scope = validation.Identifiers?.Any() == true ? $" for {string.Join(", ", validation.Identifiers)}" : "";
            var origin = validation.Origin == "renewal" ? "" : $" (from {validation.Origin})";
            var title = $"{validation.SourceName}{origin}";

            var challenge = new CertRequestChallengeConfig
            {
                DomainMatch = validation.Identifiers?.Any() == true ? string.Join(";", validation.Identifiers) : null,
                Parameters = new ObservableCollection<ProviderParameter>()
            };

            foreach (var note in validation.Notes)
            {
                Add($"{key}-note-{Slug(note)}", ExternalMigrationFindingLevel.Assumption, "Validation", title, note);
            }

            switch (validation.Kind)
            {
                case SourceValidationKinds.HttpFileSystem:
                    challenge.ChallengeType = SupportedChallengeTypes.CHALLENGE_TYPE_HTTP;

                    if (validation.Parameters.TryGetValue(SourceSettingNames.Path, out var root) && !string.IsNullOrWhiteSpace(root))
                    {
                        challenge.ChallengeRootPath = root;
                        _item.RequestConfig.WebsiteRootPath = root;
                    }

                    Add(key, ExternalMigrationFindingLevel.Mapped, "Validation", "http-01 validation",
                        string.IsNullOrWhiteSpace(root) ? $"Challenge files are written to the IIS site's folder{scope}." : $"Challenge files are written to {root}{scope}.");
                    break;

                case SourceValidationKinds.HttpSelfHosting:
                    challenge.ChallengeType = SupportedChallengeTypes.CHALLENGE_TYPE_HTTP;
                    Add(key, ExternalMigrationFindingLevel.Mapped, "Validation", "http-01 validation", $"Answered by this instance's http challenge server{scope}.");

                    if (!_context.HttpChallengeServerEnabled)
                    {
                        Add($"{key}-server", ExternalMigrationFindingLevel.Assumption, "Validation", "Http challenge server is off",
                            $"{Tool} answers http-01 with its own listener. The http challenge server is off on this instance, so challenges are answered from the web server's files instead. Enable the http challenge server if nothing serves port 80.");
                    }

                    if (validation.Parameters.TryGetValue("Port", out var port) && port != "80")
                    {
                        Add($"{key}-port", ExternalMigrationFindingLevel.Assumption, "Validation", "Challenge port",
                            $"{Tool} listens on port {port}, which presumably receives port 80 traffic through a proxy or port forward. The http challenge server here listens on port 80.");
                    }

                    break;

                case SourceValidationKinds.Manual:
                    challenge.ChallengeType = SupportedChallengeTypes.CHALLENGE_TYPE_DNS;
                    challenge.ChallengeProvider = MigrationCatalogue.ManualDnsProviderId;
                    Add(key, ExternalMigrationFindingLevel.Assumption, "Validation", "Manual DNS validation",
                        $"Each renewal waits for someone to create the DNS record{scope}, as with {Tool}. Manual validation cannot renew unattended.");
                    break;

                case SourceValidationKinds.Dns:
                    if (!MapDnsValidation(validation, challenge, key, scope))
                    {
                        return;
                    }

                    break;

                case SourceValidationKinds.HttpUnsupported:
                    Add(key, ExternalMigrationFindingLevel.Blocker, "Validation", $"{validation.SourceName} validation",
                        $"{Tool} uploads http-01 challenge files with {validation.SourceName}{scope}, which is not supported here. Change the renewal in {Tool} to another validation method, or configure the migrated item yourself.");
                    return;

                case SourceValidationKinds.TlsAlpn:
                    Add(key, ExternalMigrationFindingLevel.Blocker, "Validation", "tls-alpn-01 validation", $"tls-alpn-01{scope} is not supported here.");
                    return;

                case SourceValidationKinds.None:
                    Add(key, ExternalMigrationFindingLevel.Blocker, "Validation", "No validation",
                        $"{Tool} relies on the identifiers being pre-authorized with the CA{scope}, which is not supported here.");
                    return;

                default:
                    Add(key, ExternalMigrationFindingLevel.Blocker, "Validation", "Unknown validation",
                        $"The validation method {validation.SourceName}{scope} is not recognised.");
                    return;
            }

            _item.RequestConfig.Challenges!.Add(challenge);
        }

        private bool MapDnsValidation(SourceValidation validation, CertRequestChallengeConfig challenge, string key, string scope)
        {
            var entry = MigrationCatalogue.GetDnsProvider(validation.DnsProvider);

            if (entry == null && !string.IsNullOrWhiteSpace(validation.ScriptPlugin))
            {
                // a Posh-ACME plugin maps to the provider here which runs the same plugin script
                var byScript = _context.ChallengeProviders.FirstOrDefault(p => string.Equals(GetConfigValue(p.Config, "Script"), validation.ScriptPlugin, StringComparison.OrdinalIgnoreCase));
                entry = new DnsProviderEntry { Key = validation.ScriptPlugin!, Title = validation.SourceName, ProviderId = byScript?.Id };
            }

            var name = entry?.Title ?? validation.SourceName;

            if (entry?.ProviderId == null)
            {
                Add(key, ExternalMigrationFindingLevel.Blocker, "Validation", $"{name} DNS",
                    $"There is no DNS provider for {name} here{scope}. Use another DNS provider for these domains, or acme-dns delegation.");
                return false;
            }

            var definition = _context.ChallengeProviders.FirstOrDefault(p => p.Id == entry.ProviderId);
            if (definition == null)
            {
                Add(key, ExternalMigrationFindingLevel.Blocker, "Validation", $"{name} DNS",
                    $"The {name} DNS provider is not available on this instance{scope}.");
                return false;
            }

            challenge.ChallengeType = SupportedChallengeTypes.CHALLENGE_TYPE_DNS;
            challenge.ChallengeProvider = entry.ProviderId;

            var parameters = (definition.ProviderParameters ?? []).ToList();
            bool IsCredential(string parameterKey) => parameters.FirstOrDefault(p => string.Equals(p.Key, parameterKey, StringComparison.OrdinalIgnoreCase))?.IsCredential ?? true;

            // values by the provider's own parameter keys, so an option it has no parameter for is reported rather than stored
            var values = new List<(string Key, string Value, bool IsSecret)>();

            foreach (var (sourceKey, value, isSecret) in validation.Parameters.Select(p => (p.Key, ExternalMigrationCredentialDraft.LiteralPrefix + p.Value, false))
                .Concat(validation.SecretParameters.Select(p => (p.Key, p.Value, true))))
            {
                var parameter = FindParameter(parameters, sourceKey);

                if (parameter?.Key == null)
                {
                    validation.UnmappedOptions.Add(sourceKey);
                }
                else
                {
                    values.Add((parameter.Key, value, isSecret));
                }
            }

            values.AddRange(entry.FixedValues.Select(p => (p.Key, ExternalMigrationCredentialDraft.LiteralPrefix + p.Value, false)));

            var credentialValues = values.Where(v => IsCredential(v.Key)).ToList();
            var secretKeys = values.Where(v => v.IsSecret).Select(v => v.Value).ToList();
            var unreadable = _source.Secrets.Where(s => secretKeys.Contains(s.Key) && !s.IsReadable).ToList();

            // non-credential parameters keep their definitions, so the item edits as one set up here would
            foreach (var definitionParameter in parameters.Where(p => !p.IsCredential))
            {
                var parameter = (ProviderParameter)definitionParameter.Clone();
                var value = values.FirstOrDefault(v => string.Equals(v.Key, parameter.Key, StringComparison.OrdinalIgnoreCase));

                if (value.Key != null)
                {
                    parameter.Value = value.IsSecret ? InlineDraft(value.Value, $"{name} {parameter.Name ?? parameter.Key}") : value.Value[ExternalMigrationCredentialDraft.LiteralPrefix.Length..];
                }

                challenge.Parameters!.Add(parameter);
            }

            var unreadableCredential = unreadable.Where(u => credentialValues.Any(c => c.Value == u.Key)).ToList();
            var replacementKey = $"{key}-credential";

            if (validation.AmbientAuthentication != null || unreadableCredential.Any())
            {
                var reason = validation.AmbientAuthentication != null
                    ? $"{Tool} authenticates to {name} {validation.AmbientAuthentication}, which cannot migrate."
                    : $"{Tool}'s {name} credentials could not be read: {string.Join(" ", unreadableCredential.Select(u => $"{u.Location}: {u.Reason}"))}";

                var input = GetCredentialInput(replacementKey, entry.ProviderId);

                AddInput(replacementKey, ExternalMigrationFindingLevel.Blocker, "Validation", $"{name} credentials", $"{reason} Select a stored {name} credential to use instead.",
                    entry.ProviderId, input);

                challenge.ChallengeCredentialKey = input;
            }
            else if (parameters.Any(p => p.IsCredential))
            {
                var shared = secretKeys.Any() && _source.Secrets.Where(s => secretKeys.Contains(s.Key)).All(s => s.IsShared);
                var origin = shared
                    ? string.Join(", ", _source.Secrets.Where(s => secretKeys.Contains(s.Key)).Select(s => s.Location).Distinct())
                    : $"renewal {_source.RenewalId ?? _source.Name}";

                challenge.ChallengeCredentialKey = CredentialDraft(entry.ProviderId, $"{name} ({Tool} {origin})",
                    credentialValues
                        .GroupBy(v => parameters.FirstOrDefault(p => string.Equals(p.Key, v.Key, StringComparison.OrdinalIgnoreCase))?.Key ?? v.Key)
                        .ToDictionary(g => g.Key, g => g.First().Value));
            }

            var unreadableInline = unreadable.Except(unreadableCredential).ToList();
            if (unreadableInline.Any())
            {
                Add($"{key}-secret", ExternalMigrationFindingLevel.Blocker, "Validation", $"{name} settings not readable",
                    string.Join(" ", unreadableInline.Select(u => $"{u.Location}: {u.Reason}")));
            }

            Add(key, ExternalMigrationFindingLevel.Mapped, "Validation", "dns-01 validation", $"{name}{scope}.");

            if (entry.Note != null)
            {
                Add($"{key}-provider", ExternalMigrationFindingLevel.Assumption, "Validation", name, entry.Note);
            }

            if (validation.UnmappedOptions.Any())
            {
                Add($"{key}-options", ExternalMigrationFindingLevel.Assumption, "Validation", $"{name} options not migrated",
                    $"{string.Join(", ", validation.UnmappedOptions)} have no equivalent here.");
            }

            if (parameters.Any(p => p.Key == "zoneid"))
            {
                Add($"{key}-zone", ExternalMigrationFindingLevel.Mapped, "Validation", "DNS zone", $"Looked up from {name} at import, using the credential.");
            }

            return true;
        }

        /// <summary>
        /// The provider parameter for a source option, matched by key. Posh-ACME names a secure argument and its plain
        /// text alternative X and XInsecure, of which providers here have one, or name the argument in their config
        /// </summary>
        private static ProviderParameter? FindParameter(List<ProviderParameter> parameters, string sourceKey)
        {
            string[] candidates =
            [
                sourceKey,
                sourceKey + "Insecure",
                sourceKey + "Secure",
                sourceKey.EndsWith("Insecure", StringComparison.Ordinal) ? sourceKey[..^"Insecure".Length] : "",
                sourceKey.EndsWith("Secure", StringComparison.Ordinal) && !sourceKey.EndsWith("Insecure", StringComparison.Ordinal) ? sourceKey[..^"Secure".Length] : ""
            ];

            foreach (var candidate in candidates.Where(c => c.Length > 0))
            {
                var match = parameters.FirstOrDefault(p => string.Equals(p.Key, candidate, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    return match;
                }
            }

            return parameters.FirstOrDefault(p => p.ExtendedConfig?.Replace(" ", "").Contains($"\"AltParamKey\":\"{sourceKey}\"", StringComparison.OrdinalIgnoreCase) == true);
        }

        /// <summary>
        /// A value from a provider's config string, e.g. Script from "Provider=Certify.Providers.DNS.PoshACME;Script=Akamai"
        /// </summary>
        private static string? GetConfigValue(string? config, string name) =>
            config?.Split(';')
                .Select(p => p.Split('=', 2))
                .FirstOrDefault(p => p.Length == 2 && string.Equals(p[0].Trim(), name, StringComparison.OrdinalIgnoreCase))?[1].Trim();

        /// <returns>true if the output stores the certificate in the machine certificate store</returns>
        private bool MapOutput(SourceOutput output, int index)
        {
            var key = $"store-{index}";
            var settings = output.Settings;
            settings.TryGetValue(SourceSettingNames.Path, out var path);
            var fileName = settings.TryGetValue(SourceSettingNames.FileName, out var f) && !string.IsNullOrWhiteSpace(f) ? f : (_item.RequestConfig.PrimaryDomain ?? _source.Name).Replace("*", "_");

            foreach (var note in output.Notes)
            {
                Add($"{key}-note-{Slug(note)}", ExternalMigrationFindingLevel.Assumption, "Store", output.SourceName, note);
            }

            if (settings.TryGetValue(SourceSettingNames.KeepExisting, out var keep) && string.Equals(keep, "true", StringComparison.OrdinalIgnoreCase))
            {
                Add($"{key}-keep", ExternalMigrationFindingLevel.Assumption, "Store", "Previous certificates",
                    $"{Tool} is set to keep previous certificates. This instance follows its own setting for removing replaced certificates.");
            }

            switch (output.Kind)
            {
                case SourceOutputKinds.CertificateStore:
                    {
                        settings.TryGetValue(SourceSettingNames.StoreName, out var storeName);
                        var isPersonal = string.IsNullOrWhiteSpace(storeName) || string.Equals(storeName, "My", StringComparison.OrdinalIgnoreCase);

                        Add(key, isPersonal ? ExternalMigrationFindingLevel.Mapped : ExternalMigrationFindingLevel.Assumption, "Store", "Certificate store",
                            isPersonal
                                ? "Stored in the local machine certificate store."
                                : $"{Tool} stores the certificate in the {storeName} store. This instance stores it in the store set in its own settings (Personal by default), and IIS bindings refer to it there.");

                        foreach (var (listKey, permission) in new[] { (SourceSettingNames.AclFullControl, "fullcontrol"), (SourceSettingNames.AclRead, "read") })
                        {
                            if (!output.ListSettings.TryGetValue(listKey, out var accounts))
                            {
                                continue;
                            }

                            foreach (var account in accounts.Where(a => !string.IsNullOrWhiteSpace(a)))
                            {
                                AddTask(MigrationCatalogue.TaskKeyPermissions, $"Private key {permission} access for {account}",
                                    ("account", account), ("permission", permission));
                            }

                            if (accounts.Any())
                            {
                                Add($"{key}-{permission}", ExternalMigrationFindingLevel.Mapped, "Store", "Private key access", $"{(permission == "read" ? "Read" : "Full control")} for {string.Join(", ", accounts)}.");
                            }
                        }

                        return true;
                    }

                case SourceOutputKinds.PemFiles:
                    {
                        if (string.IsNullOrWhiteSpace(path))
                        {
                            Add(key, ExternalMigrationFindingLevel.Blocker, "Store", "PEM files", $"{Tool} writes PEM files to a default folder which could not be determined.");
                            return false;
                        }

                        var password = PasswordDraft(output, "PEM key password");

                        AddExport("pemcrt", Combine(path, $"{fileName}-crt.pem"), null);
                        AddExport("pemcrtpartialchain", Combine(path, $"{fileName}-chain.pem"), null);
                        AddExport("pemintermediates", Combine(path, $"{fileName}-chain-only.pem"), null);
                        AddExport("pemkey", Combine(path, $"{fileName}-key.pem"), password);

                        Add(key, ExternalMigrationFindingLevel.Mapped, "Store", "PEM files", $"Exported to {Combine(path, fileName)}-crt.pem, -chain.pem, -chain-only.pem and -key.pem{(password != null ? ", the key protected by the same password" : "")}.");
                        return false;
                    }

                case SourceOutputKinds.PfxFile:
                    {
                        if (string.IsNullOrWhiteSpace(path))
                        {
                            Add(key, ExternalMigrationFindingLevel.Blocker, "Store", "PFX file", $"{Tool} writes the PFX file to a default folder which could not be determined.");
                            return false;
                        }

                        var password = PasswordDraft(output, "PFX password");
                        var target = Combine(path, $"{fileName}.pfx");

                        AddExport("pfxfull", target, password);
                        Add(key, ExternalMigrationFindingLevel.Mapped, "Store", "PFX file", $"Exported to {target}{(password != null ? " with the same password" : " without a password")}.");
                        return false;
                    }

                case SourceOutputKinds.CentralSsl:
                    {
                        if (string.IsNullOrWhiteSpace(path))
                        {
                            Add(key, ExternalMigrationFindingLevel.Blocker, "Store", "IIS Central Certificate Store", $"{Tool} writes to a default folder which could not be determined.");
                            return false;
                        }

                        var password = PasswordDraft(output, "Central Certificate Store password");
                        AddTask(MigrationCatalogue.TaskCcs, "Deploy to IIS Central Certificate Store", ("path", path!), (ExportPasswordParameter, password));

                        Add(key, ExternalMigrationFindingLevel.Mapped, "Store", "IIS Central Certificate Store", $"Deployed to {path}.");
                        return false;
                    }

                case SourceOutputKinds.Files:
                    {
                        var files = settings.Where(s => FileExportTypes.ContainsKey(s.Key) && !string.IsNullOrWhiteSpace(s.Value)).ToList();

                        if (!files.Any())
                        {
                            Add(key, ExternalMigrationFindingLevel.Mapped, "Store", output.SourceName, $"{Tool} writes no certificate files of its own here.");
                            return false;
                        }

                        foreach (var (type, file) in files)
                        {
                            AddExport(type, file, null);
                        }

                        Add(key, ExternalMigrationFindingLevel.Mapped, "Store", output.SourceName,
                            $"Exported to the same files: {string.Join(", ", files.Select(f => $"{f.Value} ({FileExportTypes[f.Key]})"))}.");
                        return false;
                    }

                case SourceOutputKinds.KeyVault:
                    MapKeyVault(output, key);
                    return false;

                case SourceOutputKinds.None:
                    Add(key, ExternalMigrationFindingLevel.Mapped, "Store", "No store", "The certificate is not stored anywhere other than this instance.");
                    return false;

                case SourceOutputKinds.UserStore:
                case SourceOutputKinds.P7bFile:
                    Add(key, ExternalMigrationFindingLevel.Assumption, "Store", $"{output.SourceName} not migrated",
                        $"There is no equivalent of {Tool}'s {output.SourceName} store here, so the certificate is no longer written there. Add a deployment task if something relies on it.");
                    return false;

                default:
                    Add(key, ExternalMigrationFindingLevel.Blocker, "Store", "Unknown store", $"The store plugin {output.SourceName} is not recognised.");
                    return false;
            }
        }

        private const string ExportPasswordParameter = "export_pwd_credential";

        /// <summary>
        /// Export types of the certificate export task a <see cref="SourceOutputKinds.Files"/> output can use
        /// </summary>
        private static readonly Dictionary<string, string> FileExportTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            ["pemcrt"] = "certificate",
            ["pemintermediates"] = "intermediate certificates",
            ["pemcrtpartialchain"] = "certificate and intermediates",
            ["pemkey"] = "private key",
            ["pemfull"] = "key, certificate and chain",
            ["pfxfull"] = "PFX"
        };

        private void MapKeyVault(SourceOutput output, string key)
        {
            var settings = output.Settings;

            if (!settings.TryGetValue(SourceSettingNames.VaultName, out var vault) || string.IsNullOrWhiteSpace(vault))
            {
                Add(key, ExternalMigrationFindingLevel.Blocker, "Store", "Azure Key Vault", "The vault name is missing.");
                return;
            }

            settings.TryGetValue(SourceSettingNames.AzureService, out var service);
            service = string.IsNullOrWhiteSpace(service) ? "global" : service;

            var suffix = service switch
            {
                "china" => "vault.azure.cn",
                "usgov" => "vault.usgovcloudapi.net",
                "germany" => "vault.microsoftazure.de",
                _ => "vault.azure.net"
            };

            settings.TryGetValue(SourceSettingNames.CertificateName, out var certName);
            var task = AddTask(MigrationCatalogue.TaskKeyVault, "Deploy to Azure Key Vault",
                ("vault_uri", $"https://{vault}.{suffix}/"), ("cert_name", certName), ("azure_service", service));

            var unreadable = output.SecretSettings.Values.Select(k => _source.Secrets.FirstOrDefault(s => s.Key == k)).Where(s => s?.IsReadable == false).ToList();

            if (output.AmbientAuthentication != null || unreadable.Any())
            {
                var replacementKey = $"{key}-credential";
                var reason = output.AmbientAuthentication != null
                    ? $"{Tool} authenticates to Key Vault {output.AmbientAuthentication}, which cannot migrate."
                    : $"{Tool}'s Key Vault credentials could not be read: {string.Join(" ", unreadable.Select(u => $"{u!.Location}: {u.Reason}"))}";

                var input = GetCredentialInput(replacementKey, MigrationCatalogue.AzureClientSecretCredentialType);
                AddInput(replacementKey, ExternalMigrationFindingLevel.Blocker, "Store", "Azure Key Vault credentials", $"{reason} Select a stored Azure client secret credential to use instead.",
                    MigrationCatalogue.AzureClientSecretCredentialType, input);

                task.ChallengeCredentialKey = input;
            }
            else
            {
                var values = new Dictionary<string, string>
                {
                    ["tenantid"] = ExternalMigrationCredentialDraft.LiteralPrefix + settings.GetValueOrDefault(SourceSettingNames.TenantId, ""),
                    ["clientid"] = ExternalMigrationCredentialDraft.LiteralPrefix + settings.GetValueOrDefault(SourceSettingNames.ClientId, "")
                };

                if (output.SecretSettings.TryGetValue(SourceSettingNames.ClientSecret, out var secret))
                {
                    values["secret"] = secret;
                }

                task.ChallengeCredentialKey = CredentialDraft(MigrationCatalogue.AzureClientSecretCredentialType, $"Azure Key Vault {vault} ({Tool} renewal {_source.RenewalId ?? _source.Name})", values);
            }

            Add(key, ExternalMigrationFindingLevel.Mapped, "Store", "Azure Key Vault", $"Deployed to {vault}{(string.IsNullOrWhiteSpace(certName) ? "" : $" as {certName}")}.");
        }

        /// <returns>true if the installation updates IIS bindings</returns>
        private bool MapInstallation(SourceInstallation installation, int index)
        {
            var key = $"install-{index}";
            var settings = installation.Settings;

            foreach (var note in installation.Notes)
            {
                Add($"{key}-note-{Slug(note)}", ExternalMigrationFindingLevel.Assumption, "Installation", installation.SourceName, note);
            }

            switch (installation.Kind)
            {
                case SourceInstallationKinds.Iis:
                    {
                        var config = _item.RequestConfig;
                        config.PerformAutomatedCertBinding = true;
                        config.DeploymentBindingOption = DeploymentBindingOption.AddOrUpdate;

                        if (settings.TryGetValue(SourceSettingNames.SiteId, out var siteId) && !string.IsNullOrWhiteSpace(siteId))
                        {
                            config.DeploymentSiteOption = DeploymentOption.SingleSite;
                            _item.ServerSiteId = siteId;
                        }
                        else
                        {
                            config.DeploymentSiteOption = string.IsNullOrWhiteSpace(_item.ServerSiteId) ? DeploymentOption.Auto : DeploymentOption.SingleSite;
                        }

                        if (settings.TryGetValue(SourceSettingNames.BindingIp, out var ip) && !string.IsNullOrWhiteSpace(ip))
                        {
                            config.BindingIPAddress = ip;
                        }

                        if (settings.TryGetValue(SourceSettingNames.BindingPort, out var port) && !string.IsNullOrWhiteSpace(port))
                        {
                            config.BindingPort = port;
                        }

                        Add(key, ExternalMigrationFindingLevel.Mapped, "Installation", "IIS bindings",
                            config.DeploymentSiteOption == DeploymentOption.SingleSite ? $"Https bindings of IIS site {_item.ServerSiteId} are updated or added." : "Https bindings matching the certificate's hosts are updated or added.");

                        Add($"{key}-bindings", ExternalMigrationFindingLevel.Assumption, "Installation", "Binding changes",
                            $"Bindings are matched and created by this instance's rules, which can differ from {Tool}'s for wildcard and IP based bindings. Check the deployment preview in the test.");
                        return true;
                    }

                case SourceInstallationKinds.Script:
                    {
                        if (!installation.SecretSettings.TryGetValue(SourceSettingNames.ScriptWrapper, out var wrapper))
                        {
                            Add(key, ExternalMigrationFindingLevel.Blocker, "Installation", "Installation script", $"The script {settings.GetValueOrDefault(SourceSettingNames.Script)} cannot be run from here.");
                            return false;
                        }

                        settings.TryGetValue(SourceSettingNames.Script, out var script);

                        AddTask(MigrationCatalogue.TaskPowerShell, $"Run {System.IO.Path.GetFileName(script)}",
                            ("scriptpath", InlineDraft(wrapper, $"Wrapper for {script}")), ("inputresult", "true"));

                        Add(key, ExternalMigrationFindingLevel.Mapped, "Installation", installation.SourceName == SourceInstallationKinds.Script ? "Installation script" : installation.SourceName,
                            settings.GetValueOrDefault(SourceSettingNames.Description) ?? $"{script} runs after each renewal with the same arguments, through a wrapper script written at import.");
                        return false;
                    }

                case SourceInstallationKinds.None:
                    return false;

                case SourceInstallationKinds.IisFtp:
                    Add(key, ExternalMigrationFindingLevel.Blocker, "Installation", "IIS FTP bindings", "Updating IIS FTP site bindings is not supported here.");
                    return false;

                default:
                    Add(key, ExternalMigrationFindingLevel.Blocker, "Installation", "Unknown installation", $"The installation plugin {installation.SourceName} is not recognised.");
                    return false;
            }
        }

        private void MapSourceState()
        {
            foreach (var u in _source.Unrecognised)
            {
                Add($"unrecognised-{Slug(u.Category + u.Description)}", u.IsBlocker ? ExternalMigrationFindingLevel.Blocker : ExternalMigrationFindingLevel.Assumption, u.Category, "Not recognised", u.Description);
            }

            if (_source.LastRunErrors.Any())
            {
                Add("last-run", ExternalMigrationFindingLevel.Assumption, "Source", $"{Tool}'s last renewal failed",
                    $"{string.Join(" ", _source.LastRunErrors.Take(3))} The same problem may affect the migrated item, so check the tests carefully.");
            }

            _plan.CanAdoptCurrentCertificate = _source.CurrentCertificateReadable;
            _plan.CurrentCertificateExpiry = _source.CurrentCertificateExpiry;
            _plan.CurrentCertificateThumbprint = _source.CurrentCertificateThumbprint;

            if (_source.CurrentCertificateReadable && _source.CurrentCertificateExpiry < DateTimeOffset.UtcNow)
            {
                Add("current-certificate", ExternalMigrationFindingLevel.Mapped, "Certificate", "Current certificate adopted",
                    $"The certificate {Tool} last issued expired on {_source.CurrentCertificateExpiry:yyyy-MM-dd}. It is copied to the item, which orders a new certificate at its first renewal after cut over.");
            }
            else if (_source.CurrentCertificateReadable)
            {
                Add("current-certificate", ExternalMigrationFindingLevel.Mapped, "Certificate", "Current certificate adopted",
                    $"The certificate {Tool} last issued{(_source.CurrentCertificateExpiry != null ? $" (expires {_source.CurrentCertificateExpiry:yyyy-MM-dd})" : "")} is copied to the item, so nothing is ordered until it is due for renewal.");
            }
            else
            {
                Add("current-certificate", ExternalMigrationFindingLevel.Assumption, "Certificate", "Current certificate not adopted",
                    $"{_source.CurrentCertificateNote ?? $"{Tool}'s current certificate and key could not be read."} The item orders a new certificate at its first renewal after cut over.");
            }
        }

        private string? PasswordDraft(SourceOutput output, string label)
        {
            if (!output.SecretSettings.TryGetValue(SourceSettingNames.Password, out var secretKey))
            {
                return null;
            }

            var secret = _source.Secrets.FirstOrDefault(s => s.Key == secretKey);
            if (secret?.IsReadable != true)
            {
                Add($"password-{Slug(secretKey)}", ExternalMigrationFindingLevel.Blocker, "Store", $"{label} not readable",
                    $"{secret?.Location}: {secret?.Reason}");
                return null;
            }

            var title = secret.IsShared ? $"{label} ({Tool} {secret.Location})" : $"{label} ({Tool} renewal {_source.RenewalId ?? _source.Name})";
            return CredentialDraft(MigrationCatalogue.PasswordCredentialType, title, new Dictionary<string, string> { ["password"] = secretKey });
        }

        private string CredentialDraft(string providerType, string title, Dictionary<string, string> values)
        {
            var existing = _plan.Credentials.FirstOrDefault(c => c.ProviderType == providerType && c.Title == title);
            if (existing != null)
            {
                return existing.Key;
            }

            var draft = new ExternalMigrationCredentialDraft
            {
                Key = $"{ExternalMigrationCredentialDraft.KeyPrefix}{_plan.Credentials.Count}",
                Title = title,
                ProviderType = providerType,
                Values = values
            };

            _plan.Credentials.Add(draft);
            return draft.Key;
        }

        /// <summary>
        /// A value read from the source at import and put straight into the item, e.g. a registration or generated path
        /// </summary>
        private string InlineDraft(string secretKey, string title)
        {
            var existing = _plan.Credentials.FirstOrDefault(c => c.IsInlineValue && c.Values.GetValueOrDefault(ExternalMigrationCredentialDraft.InlineValueKey) == secretKey);
            if (existing != null)
            {
                return existing.Key;
            }

            var draft = new ExternalMigrationCredentialDraft
            {
                Key = $"{ExternalMigrationCredentialDraft.KeyPrefix}{_plan.Credentials.Count}",
                Title = title,
                IsInlineValue = true,
                Values = new Dictionary<string, string> { [ExternalMigrationCredentialDraft.InlineValueKey] = secretKey }
            };

            _plan.Credentials.Add(draft);
            return draft.Key;
        }

        /// <summary>
        /// The stored credential supplied for a finding, if it exists and is of the required type
        /// </summary>
        private string? GetCredentialInput(string findingKey, string credentialType)
        {
            if (!_inputs.TryGetValue(findingKey, out var value) || string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            return _context.Credentials.Any(c => c.StorageKey == value && c.ProviderType == credentialType) ? value : null;
        }

        private DeploymentTaskConfig AddTask(string taskTypeId, string name, params (string Key, string? Value)[] parameters)
        {
            var task = new DeploymentTaskConfig
            {
                Id = Guid.NewGuid().ToString(),
                TaskTypeId = taskTypeId,
                TaskName = name,
                TaskTrigger = TaskTriggerType.ON_SUCCESS,
                IsFatalOnError = true,
                Parameters = parameters.Where(p => p.Value != null).Select(p => new ProviderParameterSetting(p.Key, p.Value!)).ToList()
            };

            _item.PostRequestTasks!.Add(task);

            if (!_context.DeploymentProviders.Any(d => d.Id == taskTypeId))
            {
                Add($"task-{Slug(taskTypeId)}", ExternalMigrationFindingLevel.Blocker, "Deployment", "Deployment task not available",
                    $"The deployment task {taskTypeId} is not available on this instance.");
            }

            return task;
        }

        private void AddExport(string type, string path, string? passwordCredential) =>
            AddTask(MigrationCatalogue.TaskCertificateExport, $"Export {type} to {path}", ("path", path), ("type", type), (ExportPasswordParameter, passwordCredential));

        private static string Combine(string? folder, string file) => string.IsNullOrWhiteSpace(folder) ? file : System.IO.Path.Combine(folder, file);

        private void AddInput(string key, ExternalMigrationFindingLevel level, string category, string title, string description, string credentialType, string? appliedInput)
        {
            _plan.Findings.Add(new ExternalMigrationFinding
            {
                Key = key,
                Level = level,
                Category = category,
                Title = title,
                Description = description,
                InputType = ExternalMigrationInputTypes.Credential,
                CredentialType = credentialType,
                AppliedInput = appliedInput
            });
        }

        private void Add(string key, ExternalMigrationFindingLevel level, string category, string title, string description)
        {
            // keys must be unique, as inputs are matched to findings by key
            var unique = key;
            for (var n = 2; _plan.Findings.Any(f => f.Key == unique); n++)
            {
                unique = $"{key}-{n}";
            }

            _plan.Findings.Add(new ExternalMigrationFinding { Key = unique, Level = level, Category = category, Title = title, Description = description });
        }

        private static string Slug(string value)
        {
            var chars = value.ToLowerInvariant().Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
            var slug = new string(chars).Trim('-');
            while (slug.Contains("--"))
            {
                slug = slug.Replace("--", "-");
            }

            return slug.Length > 40 ? slug[..40] : slug;
        }
    }
}
