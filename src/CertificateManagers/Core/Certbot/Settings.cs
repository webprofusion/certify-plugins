using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace Certify.Plugin.CertificateManagers.Certbot
{


    public class ConfigSettings
    {
       
        public string Version { get; set; }
        public string ArchiveDir { get; set; }
        public string Cert { get; set; }
        public string PrivKey { get; set; }
        public string Chain { get; set; }
        public string FullChain { get; set; }

        // renewal params

        public string AccountId { get; set; }
        public string Authenticator { get; set; }
        public string Server { get; set; }

        public Dictionary<string,string> WebrootMap { get; set; }
    }
}
