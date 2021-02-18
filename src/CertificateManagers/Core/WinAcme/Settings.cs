using System;
using System.Collections.Generic;

namespace Certify.Plugin.CertificateManagers.WinAcme
{
    public class TargetPluginOptions
    {
        public string CommonName { get; set; }
        public List<string> AlternativeNames { get; set; }
    }

    public class HistoryItem
    {
        public DateTime? Date { get; set; }
        public bool Success { get; set; }
        public string Thumbprint { get; set; }
    }

    public class ConfigSettings
    {
        public string Id { get; set; }
        public string LastFriendlyName { get; set; }
        public string PfxPasswordProtected { get; set; }
        public TargetPluginOptions TargetPluginOptions { get; set; }
        public List<HistoryItem> History { get; set; }
    }
}
