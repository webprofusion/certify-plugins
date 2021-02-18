using Newtonsoft.Json;
using System;

namespace Certify.Plugin.CertificateManagers.PoshAcme
{


    public class ConfigSettings
    {
        [JsonProperty("location")]
        public string Id { get; set; }
        public string FriendlyName { get; set; }
        public string MainDomain { get; set; }
        public string[] SANs { get; set; }

        public string Status { get; set; }

        public DateTime? RenewAfter { get; set; }
        public DateTime? CertExpires { get; set; }
        public string PfxPass { get; set; }
    }
}
