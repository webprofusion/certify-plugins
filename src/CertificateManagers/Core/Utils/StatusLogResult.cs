using System;

namespace Certify.Plugin.CertificateManagers.Utils
{
    public class StatusLogResult
    {
        public string? ItemId { get; set; }
        public string? Status { get; set; }
        public string? Message { get; set; }

        public DateTimeOffset? StatusDate { get; set; }
    }
}
