using Certify.Models;
using Certify.Models.Config;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class Tomcat : CertificateExport, IDeploymentTaskProvider
    {
        public static new DeploymentProviderDefinition Definition { get; }
        public new DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static Tomcat()
        {

            /*
             * https://tomcat.apache.org/tomcat-8.5-doc/ssl-howto.html
             * Most instructions refer to generating a CSR and using a keystore, however tomcat can consume the normal PFX
             * From Tomcat installation directory, edit server.xml
             * Add or Edit connector on port 443 pointing to .pfx

                <Connector port="443" ... scheme="https" secure="true"
                    SSLEnabled="true"
                    sslProtocol="TLS"
                    keystoreFile="your_certificate.pfx"
                    keystorePass="" keystoreType="PKCS12"/>
            */
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Tomcat",
                Title = "Deploy to Tomcat",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork | DeploymentContextType.SSH,
                SupportsRemoteTarget = true,
                Description = "Deploy latest certificate to a local or remote Tomcat server",
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>
                {
                     new ProviderParameter{ Key="path_pfx", Name="Destination Path", IsRequired=true, IsCredential=false , Description="Local/remote path to copy PFX file to e.g /usr/local/ssl/server.pfx"},
                }
            };
        }

        public new async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {
            var definition = GetDefinition(execParams.Definition);
            var settings = execParams.Settings;

            // for each item, execute a certificate export
            var results = new List<ActionResult>();

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            settings.Parameters.Add(new ProviderParameterSetting("path", null));
            settings.Parameters.Add(new ProviderParameterSetting("type", null));

            var certPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_pfx");
            if (!string.IsNullOrWhiteSpace(certPath?.Value))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = certPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pfxfull";

                execParams.Log.Information(definition.Title + ":: exporting PFX format certificates and key");
                results.AddRange(await base.Execute(new DeploymentTaskExecutionParams(execParams, definition)));
            }

            return results;
        }

        public new async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {

            // validate a certificate export
            var results = new List<ActionResult>();
            var settings = execParams.Settings;

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            settings.Parameters.Add(new ProviderParameterSetting("path", null));
            settings.Parameters.Add(new ProviderParameterSetting("type", null));

            var certPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_pfx");
            if (string.IsNullOrEmpty(certPath.Value))
            {
                results.Add(new ActionResult
                {
                    IsSuccess = false,
                    Message = "Required: " + Definition.ProviderParameters.First(f => f.Key == "path_pfx").Name
                });
            }
            else
            {
                settings.Parameters.Find(p => p.Key == "path").Value = certPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pfxfull";
                results.AddRange(await base.Validate(execParams));
            }

            return results;
        }

    }
}
