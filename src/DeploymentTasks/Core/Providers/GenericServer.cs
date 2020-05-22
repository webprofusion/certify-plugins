using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models.Config;
using Certify.Models.Providers;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Generic version of certificate export deployment task
    /// </summary>
    public class GenericServer : Apache, IDeploymentTaskProvider
    {
        public static new DeploymentProviderDefinition Definition { get; }
        public new DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static GenericServer()
        {
            // https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile

            // SSLCertificateFile : e.g. server.crt - pem encoded certificate(s). At a minimum, the file must include an end-entity (leaf) certificate. Can include intermediates sorted from leaf to root (apache 2.4.8 and higher)
            // SSLCertificateChainFile: e.g. ca.crt - (not required if intermediates etc included in SSLCertificateFile) crt concatentated PEM format, intermediate to root CA certificate
            // SSLCertificateKeyFile : e.g. server.key - pem encoded private key

            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.GenericServer",
                Title = "Deploy to Generic Server (multi-purpose)",
                Description = "Deploy latest certificate as component files (PEM, CRT, KEY) to Local or Remote Server",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork | DeploymentContextType.SSH,
                ProviderParameters = Apache.Definition.ProviderParameters
            };

        }

        public new async Task<List<ActionResult>> Execute(
            ILog log,
            object subject,
            DeploymentTaskConfig settings,
            Dictionary<string, string> credentials,
            bool isPreviewOnly,
            DeploymentProviderDefinition definition,
            CancellationToken cancellationToken
        )
        {
            return await base.Execute(log, subject, settings, credentials, isPreviewOnly, definition, cancellationToken);
        }

        public async Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition = null)
        {

            return await base.Validate(subject, settings, credentials, definition);
        }

    }
}
