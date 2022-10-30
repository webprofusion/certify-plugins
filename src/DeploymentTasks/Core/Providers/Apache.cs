
using Certify.Models;
using Certify.Models.Config;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Apache specific version of certificate export deployment task
    /// </summary>
    public class Apache : CertificateExport, IDeploymentTaskProvider
    {
        public static new DeploymentProviderDefinition Definition { get; }
        public new DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static Apache()
        {
            // https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile

            // SSLCertificateFile : e.g. server.crt - pem encoded certificate(s). At a minimum, the file must include an end-entity (leaf) certificate. Can include intermediates sorted from leaf to root (apache 2.4.8 and higher)
            // SSLCertificateChainFile: e.g. ca.crt - (not required if intermediates etc included in SSLCertificateFile) crt concatentated PEM format, intermediate to root CA certificate
            // SSLCertificateKeyFile : e.g. server.key - pem encoded private key

            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Apache",
                Title = "Deploy to Apache",
                Description = "Deploy latest certificate to Local or Remote Apache Server",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork | DeploymentContextType.SSH,
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>
                {
                     new ProviderParameter{ Key="path_cert", Name="Output filepath for cert", IsRequired=true, IsCredential=false, Description="e.g. /somewhere/cert.pem" },
                     new ProviderParameter{ Key="path_key", Name="Output filepath for key", IsRequired=true, IsCredential=false, Description="e.g. /somewhere/privkey.pem"  },
                     new ProviderParameter{ Key="path_fullchain", Name="Output filepath for full chain", IsRequired=false, IsCredential=false, Description="(Optional) e.g. /somewhere/fullchain.pem"  },
                     new ProviderParameter{ Key="path_chain", Name="Output filepath for CA chain", IsRequired=false, IsCredential=false, Description="(Optional) e.g. /somewhere/chain.pem"  },
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

            var certPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_cert");
            if (!string.IsNullOrWhiteSpace(certPath?.Value))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = certPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemcrt";

                execParams.Log.Information(definition.Title + ":: exporting PEM format certificate file");
                results.AddRange(await base.Execute(new DeploymentTaskExecutionParams(execParams, definition)));
            }

            var keyPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_key");
            if (!string.IsNullOrWhiteSpace(keyPath?.Value) && !results.Any(r => r.IsSuccess == false))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = keyPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemkey";

                execParams.Log.Information(definition.Title + ":: exporting PEM format key file");
                results.AddRange(await base.Execute(new DeploymentTaskExecutionParams(execParams, definition)));
            }

            var chainPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_chain");
            if (!string.IsNullOrWhiteSpace(chainPath?.Value) && !results.Any(r => r.IsSuccess == false))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = chainPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemchain";

                execParams.Log.Information(definition.Title + ":: exporting PEM format chain file");
                results.AddRange(await base.Execute(new DeploymentTaskExecutionParams(execParams, definition)));
            }

            var fullchainPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_fullchain");
            if (!string.IsNullOrWhiteSpace(fullchainPath?.Value) && !results.Any(r => r.IsSuccess == false))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = fullchainPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemcrtpartialchain";

                execParams.Log.Information(definition.Title + ":: exporting PEM format full chain file (excluding root)");
                results.AddRange(await base.Execute(new DeploymentTaskExecutionParams(execParams, definition)));
            }

            return results;
        }

        public new async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {

            // for each item, execute a certificate export
            var results = new List<ActionResult>();
            var settings = execParams.Settings;

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            settings.Parameters.Add(new ProviderParameterSetting("path", null));
            settings.Parameters.Add(new ProviderParameterSetting("type", null));

            var certPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_cert");
            if (string.IsNullOrEmpty(certPath.Value) && string.IsNullOrEmpty(settings.Parameters.FirstOrDefault(p => p.Key == "path_fullchain")?.Value))
            {
                results.Add(new ActionResult
                {
                    IsSuccess = false,
                    Message = $"Required: {Definition.ProviderParameters.First(f => f.Key == "path_cert").Name} or {Definition.ProviderParameters.First(f => f.Key == "path_fullchain").Name}"
                });
            }
            else
            {
                settings.Parameters.Find(p => p.Key == "path").Value = certPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemcrt";
                results.AddRange(await base.Validate(execParams));
            }

            var keyPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_key");
            if (string.IsNullOrEmpty(keyPath.Value))
            {
                results.Add(new ActionResult
                {
                    IsSuccess = false,
                    Message = "Required: " + Definition.ProviderParameters.First(f => f.Key == "path_key").Name
                });
            }
            else
            {
                if (keyPath != null && !results.Any(r => r.IsSuccess == false))
                {

                    settings.Parameters.Find(p => p.Key == "path").Value = keyPath.Value;
                    settings.Parameters.Find(p => p.Key == "type").Value = "pemkey";
                    results.AddRange(await base.Validate(execParams));
                }
            }

            var chainPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_chain");
            if (chainPath != null && !results.Any(r => r.IsSuccess == false))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = chainPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemchain";
                results.AddRange(await base.Validate(execParams));

            }


            var fullchainPath = settings.Parameters.FirstOrDefault(p => p.Key == "path_fullchain");
            if (fullchainPath != null && !results.Any(r => r.IsSuccess == false))
            {
                settings.Parameters.Find(p => p.Key == "path").Value = fullchainPath.Value;
                settings.Parameters.Find(p => p.Key == "type").Value = "pemfullnokey";
                results.AddRange(await base.Validate(execParams));

            }

            return results;
        }

    }
}