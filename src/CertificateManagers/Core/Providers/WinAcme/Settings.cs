using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certify.Plugin.CertificateManagers.WinAcme
{
    /// <summary>
    /// Options for one plugin of a renewal. Plugins are identified by GUID and each has its own option names, so
    /// everything other than the plugin id is kept as raw JSON for the plugin specific mapping to read
    /// </summary>
    public class PluginOptions
    {
        /// <summary>
        /// GUID of the plugin these options are for
        /// </summary>
        public string? Plugin { get; set; }

        /// <summary>
        /// All other options, by name
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? Options { get; set; }

        /// <summary>
        /// A string option, or null if it is absent or not a string
        /// </summary>
        public string? GetString(string name) =>
            Options != null && Options.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        /// <summary>
        /// A list of strings option, or null if it is absent or not a list
        /// </summary>
        public List<string>? GetStringList(string name)
        {
            if (Options == null || !Options.TryGetValue(name, out var value) || value.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            var list = new List<string>();

            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    list.Add(item.GetString()!);
                }
                else if (item.ValueKind == JsonValueKind.Number)
                {
                    list.Add(item.GetRawText());
                }
            }

            return list;
        }
    }

    public class TargetPluginOptions : PluginOptions
    {
        public string? CommonName { get; set; }
        public List<string>? AlternativeNames { get; set; }
    }

    public class HistoryItem
    {
        public DateTime? Date { get; set; }
        public bool? Success { get; set; }
        public List<HistoryResult>? OrderResults { get; set; }

        /// <summary>
        /// Before per order results were recorded (win-acme 2.1 and earlier) the thumbprints and expiry were held
        /// on the history item itself
        /// </summary>
        public List<string>? Thumbprints { get; set; }
        public DateTime? ExpireDate { get; set; }
        public List<string>? ErrorMessages { get; set; }

        /// <summary>
        /// The results for each order, with legacy history items converted the same way win-acme does
        /// </summary>
        public List<HistoryResult> GetOrderResults()
        {
            if (OrderResults != null)
            {
                return OrderResults;
            }

            var results = new List<HistoryResult>();

            if (Thumbprints?.Count > 0)
            {
                foreach (var thumbprint in Thumbprints)
                {
                    results.Add(new HistoryResult { Name = results.Count == 0 ? WinAcmeRenewal.MainOrderName : "legacy", Thumbprint = thumbprint, ExpireDate = ExpireDate, Success = Success });
                }
            }
            else
            {
                results.Add(new HistoryResult { Name = WinAcmeRenewal.MainOrderName, ExpireDate = ExpireDate, Success = Success, ErrorMessages = ErrorMessages });
            }

            return results;
        }
    }

    public class HistoryResult
    {
        /// <summary>
        /// Name of the order within the renewal, "main" unless the order plugin splits the renewal
        /// </summary>
        public string? Name { get; set; }
        public DateTime? ExpireDate { get; set; }
        public bool? Success { get; set; }

        /// <summary>
        /// Set when an order from an earlier run was not produced by the latest run
        /// </summary>
        public bool? Missing { get; set; }
        public bool? Revoked { get; set; }
        public string? Thumbprint { get; set; }
        public List<string>? ErrorMessages { get; set; }
    }

    /// <summary>
    /// A win-acme or simple-acme renewal ({id}.renewal.json)
    /// </summary>
    public class WinAcmeRenewal
    {
        public const string MainOrderName = "main";

        public string? Id { get; set; }

        /// <summary>
        /// ACME server URL, recorded by simple-acme. win-acme 2.2 does not record it, and the per server folder the
        /// renewal is in identifies the server instead
        /// </summary>
        public string? EndPoint { get; set; }
        public string? FriendlyName { get; set; }
        public string? LastFriendlyName { get; set; }
        public string? PfxPasswordProtected { get; set; }

        /// <summary>
        /// Name of the ACME account, if not the default account
        /// </summary>
        public string? Account { get; set; }

        /// <summary>
        /// Settings which override the global and per server settings for this renewal
        /// </summary>
        public JsonElement? Settings { get; set; }

        public TargetPluginOptions? TargetPluginOptions { get; set; }
        public PluginOptions? ValidationPluginOptions { get; set; }
        public PluginOptions? CsrPluginOptions { get; set; }
        public PluginOptions? OrderPluginOptions { get; set; }
        public List<PluginOptions>? StorePluginOptions { get; set; }
        public List<PluginOptions>? InstallationPluginOptions { get; set; }
        public List<HistoryItem>? History { get; set; }

        /// <summary>
        /// Any fields not described above, so that newer formats can be reported rather than silently dropped
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? OtherFields { get; set; }
    }
}
