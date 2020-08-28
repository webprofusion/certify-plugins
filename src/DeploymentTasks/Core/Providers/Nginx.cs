using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// nginx specific version of certificate export deployment task
    /// </summary>
    public class Nginx : CertificateExport, IDeploymentTaskProvider
    {
        public static new DeploymentProviderDefinition Definition { get; }
        public new DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static Nginx()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Nginx",
                Title = "Deploy to nginx",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork | DeploymentContextType.SSH,
                Description = "Deploy latest certificate to a local or remote nginx server",
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>
                {
                    new ProviderParameter{ Key="path_cert", Name="Destination for .crt", IsRequired=true, IsCredential=false, Description="e.g. Path, UNC or /somewhere/server.crt" },
                    new ProviderParameter{ Key="path_key", Name="Destination for .key", IsRequired=true, IsCredential=false, Description="e.g. Path, UNC or /somewhere/server.key"  },
                }
            };
        }

        public async new Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {
            var definition = GetDefinition(execParams.Definition);
            var settings = execParams.Settings;

            // for each item, execute a certificate export
            var results = new List<ActionResult>();

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            settings.Parameters.Add(new ProviderParameterSetting("path", null));
            settings.Parameters.Add(new ProviderParameterSetting("type", null));

            var certPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_cert");
            if (certPath != null)
            {
                settings.Parameters.Find(p => p.Key == "path").Value = certPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemcrtpartialchain";
                results.AddRange(await base.Execute(execParams));
            }

            var keyPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_key");
            if (keyPath != null && !results.Any(r => r.IsSuccess == false))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = keyPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemkey";
                results.AddRange(await base.Execute(new DeploymentTaskExecutionParams(execParams, definition)));
            }

            return results;
        }
    }
}
