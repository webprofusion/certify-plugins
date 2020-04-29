using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Config;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;
using SimpleImpersonation;

namespace Certify.Providers.DeploymentTasks
{
    public class CentralizedCertificateStore : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition) => (currentDefinition ?? Definition);

        static CentralizedCertificateStore()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.CCS",
                Title = "Deploy to Centralized Certificate Store (CCS)",
                DefaultTitle = "Deploy to CCS",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork,
                Description = "Deploy latest certificate to Windows Centralized Certificate Store",
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>
                {
                    new ProviderParameter{
                        Key ="path",
                        Name ="Destination Path",
                        IsRequired =true,
                        IsCredential =false,
                        Description="UNC Path or Local Share"
                    },
                }
            };
        }

        public async Task<List<ActionResult>> Execute(
            ILog log,
            object subject,
            DeploymentTaskConfig settings,
            Dictionary<string, string> credentials,
            bool isPreviewOnly,
            DeploymentProviderDefinition definition = null
            )
        {

            definition = GetDefinition(definition);

            var managedCert = ManagedCertificate.GetManagedCertificate(subject);

            UserCredentials windowsCredentials = null;

            if (credentials != null && credentials.Count > 0)
            {
                try
                {
                    var username = credentials["username"];
                    var pwd = credentials["password"];
                    credentials.TryGetValue("domain", out var domain);

                    if (domain != null)
                    {
                        windowsCredentials = new UserCredentials(domain, username, pwd);
                    }
                    else
                    {
                        windowsCredentials = new UserCredentials(username, pwd);
                    }
                }
                catch
                {
                    return new List<ActionResult>{
                        new ActionResult { IsSuccess = false, Message = "CCS Export task with Windows Credentials requires username and password." }
                    };
                }
            }

            var windowsFileClient = new WindowsNetworkFileClient(windowsCredentials);

            var domains = managedCert.GetCertificateDomains();

            var fileList = new Dictionary<string, string>();

            var destinationPath = settings.Parameters?.FirstOrDefault(d => d.Key == "path")?.Value;

            foreach (var domain in domains)
            {

                // normalise wildcard domains to _.domain.com for file store
                var targetDomain = domain.Replace('*', '_');

                // attempt save to store, which may be a network UNC path or otherwise authenticated resource

                if (!string.IsNullOrWhiteSpace(destinationPath))
                {
                    var filename = Path.Combine(destinationPath.Trim(), domain + ".pfx");

                    fileList.Add(managedCert.CertificatePath, filename);

                    log.Information($"{Definition.Title}: Storing PFX as {filename}");
                }
            }

            if (fileList.Count == 0)
            {
                return new List<ActionResult>{
                    new ActionResult { IsSuccess = true, Message = $"{Definition.Title}: Nothing to copy." }
                   };
            }
            else
            {
                if (!isPreviewOnly)
                {
                    windowsFileClient.CopyLocalToRemote(log, fileList);
                }

            }

            return new List<ActionResult>{
                await Task.FromResult(new ActionResult { IsSuccess = true, Message = "File copying completed" })
            };
        }

        public Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition)
        {
            throw new System.NotImplementedException();
        }
    }
}

