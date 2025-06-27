using System;
using System.Text.Json.Serialization;

namespace Certify.Plugin.CertificateManagers.Providers.PoshAcme
{
    public class ConfigSettings
    {
        [JsonPropertyName("location")]
        public string? Id { get; set; }
        public string? FriendlyName { get; set; }
        public string? MainDomain { get; set; }
        public string[]? SANs { get; set; }

        public string? Status { get; set; }

        public DateTime? RenewAfter { get; set; }
        public DateTime? CertExpires { get; set; }
        public string? PfxPass { get; set; }
    }
}
