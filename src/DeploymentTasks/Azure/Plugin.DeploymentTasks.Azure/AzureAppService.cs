using Azure.Identity;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using Microsoft.Azure.Management.AppService.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace Plugin.DeploymentTasks.Azure
{

    public class AzureAppService : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private IdnMapping _idnMapping = new IdnMapping();

        static AzureAppService()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.AzureAppService",
                Title = "Deploy to Azure App Service",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = "ExternalAuth.Azure.ClientSecret",
                Description = "Apply a certificate to an Azure App Service",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="service_name", Name="App Service Name", IsRequired=true, IsCredential=false,  Description="e.g. my-example-app", Type= OptionType.String },
                    new ProviderParameter{ Key="subscriptionid",Name="Subscription Id", IsRequired=true , IsPassword=false, IsCredential=false, Type=OptionType.String}
                }
            };
        }

        /// <summary>
        /// Deploy current cert to Azure Key Vault
        /// </summary>
        /// <param name="log"></param>
        /// <param name="managedCert"></param>
        /// <param name="settings"></param>
        /// <param name="credentials"></param>
        /// <param name="isPreviewOnly"></param>
        /// <returns></returns>
        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var definition = GetDefinition(execParams.Definition);

            var results = await Validate(execParams);

            if (results.Any())
            {
                return results;
            }

            var managedCert = ManagedCertificate.GetManagedCertificate(execParams.Subject);

            if (string.IsNullOrEmpty(managedCert.CertificatePath))
            {
                results.Add(new ActionResult("No certificate to deploy.", false));
                return results;
            }

            var serviceName = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "service_name")?.Value;
            var subscriptionId = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "subscriptionid")?.Value;
            var tenantId = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "tenantid")?.Value ?? (execParams.Credentials.ContainsKey("tenantid") ? execParams.Credentials["tenantid"] : null); //tenantid from parameter or credential

            var azureEnvironmentName = "AzureGlobalCloud";
            var knownEnv = AzureEnvironment.KnownEnvironments;

            var svcPrincipalLogin = new ServicePrincipalLoginInformation { ClientId = execParams.Credentials["clientid"], ClientSecret = execParams.Credentials["secret"] };
            var azureCreds = new AzureCredentials(svcPrincipalLogin, tenantId, AzureEnvironment.FromName(azureEnvironmentName));

            var restClient = RestClient
                .Configure()
                .WithEnvironment(AzureEnvironment.FromName(azureEnvironmentName))
                .WithCredentials(azureCreds)
                .Build();

            var azure = new AppServiceManager(restClient, subscriptionId, tenantId);

            var webapps = await azure.WebApps.ListAsync();
            var functions = await azure.FunctionApps.ListAsync();

            // target could be web app/web app slot, function app/ function app slot
            var targetApp = webapps.FirstOrDefault(a => a.Name.ToLower() == serviceName.ToLower());

            if (targetApp == null)
            {
                execParams.Log.Error($"Azure App Service deployment - App not found: {serviceName}");
                results.Add(new ActionResult("Azure App Service deployment - App not found: {serviceName}", false));
                return results;
            }

            var certPwd = "";

            // get PFX password if in use
            if (!string.IsNullOrWhiteSpace(managedCert.CertificatePasswordCredentialId))
            {
                var cred = await execParams.CredentialsManager.GetUnlockedCredentialsDictionary(managedCert.CertificatePasswordCredentialId);
                if (cred != null)
                {
                    certPwd = cred["password"];
                }
            }

            try
            {
                // upload cert and apply it to the SNI binding.
                var app = await azure.WebApps.GetByIdAsync(targetApp.Id);

                var primaryDomain = managedCert.RequestConfig.PrimaryDomain;

                var pfxBytes = System.IO.File.ReadAllBytes(managedCert.CertificatePath);

                // upload cert if not present
                var existingCerts = await azure.AppServiceCertificates.ListByResourceGroupAsync(app.ResourceGroupName);

                IAppServiceCertificate certificate;
                if (!existingCerts.Any(c => c.Thumbprint == managedCert.CertificateThumbprintHash))
                {
                    // https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-certificate#private-certificate-requirements
                    certificate = await azure.AppServiceCertificates
                                          .Define($"{primaryDomain}_{DateTime.UtcNow.ToString("yyyyMMdd")}")
                                          .WithRegion(app.Region)
                                          .WithExistingResourceGroup(app.ResourceGroupName)
                                          .WithPfxByteArray(pfxBytes)
                                          .WithPfxPassword(certPwd)
                                          .CreateAsync();
                }
                else
                {
                    certificate = existingCerts.First(c => c.Thumbprint == managedCert.CertificateThumbprintHash);
                }
                // apply cert to binding

                await app.Update()
                             .DefineSslBinding()
                                 .ForHostname(managedCert.RequestConfig.PrimaryDomain)
                                 .WithExistingCertificate(certificate.Thumbprint)
                                 .WithSniBasedSsl()
                                 .Attach()
                             .ApplyAsync();

                execParams.Log.Information($"Deployed certificate to Azure App Service");

                results.Add(new ActionResult("Certificate Deployed to Azure App Service", true));
            }
            catch (AuthenticationFailedException exp)
            {
                execParams.Log.Error($"Azure Authentication error: {exp.InnerException?.Message ?? exp.Message}");
                results.Add(new ActionResult("Azure App Service Deployment Failed", false));
            }
            catch (Exception exp)
            {
                execParams.Log.Error($"Failed to deploy certificate to Azure App Service :{exp}");
                results.Add(new ActionResult("Azure App Service Deployment Failed", false));
            }

            return results;
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult> { };

            var uri = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "service_name")?.Value;
            if (string.IsNullOrEmpty(uri))
            {
                results.Add(new ActionResult("Service name is required", false));
            }

            return await Task.FromResult(results);
        }
    }
}
