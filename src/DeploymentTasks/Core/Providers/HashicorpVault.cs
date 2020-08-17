using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using static Certify.Providers.DeploymentTasks.CertificateExport;

namespace Certify.Providers.DeploymentTasks
{
    public class HashicorpVault : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static HashicorpVault()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.HashicorpVault",
                Title = "Deploy to Hashicorp Vault",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.Any,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_API_TOKEN,
                Description = "Store your certificate and private key in an instance of Hashicorp Vault.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="vault_uri", Name="Vault URI", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. http://127.0.0.1:8200" },
                    new ProviderParameter{ Key="vault_secret_path", Name="Path to Secret", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. /v1/secret/data/examplecert" },

                }
            };
        }

        public async Task<List<ActionResult>> Execute(
          ILog log,
          object subject,
          DeploymentTaskConfig settings,
          Dictionary<string, string> credentials,
          bool isPreviewOnly,
          DeploymentProviderDefinition definition,
          CancellationToken cancellationToken
          )
        {

            definition = GetDefinition(definition);

            var results = await Validate(subject, settings, credentials, definition);
            if (results.Any())
            {
                return results;
            }

            var managedCert = ManagedCertificate.GetManagedCertificate(subject);

            if (string.IsNullOrEmpty(managedCert.CertificatePath))
            {
                results.Add(new ActionResult("No certificate to deploy.", false));
                return results;

            }
            string vaultUri = settings.Parameters.FirstOrDefault(c => c.Key == "vault_uri")?.Value;
            string vaultPath = settings.Parameters.FirstOrDefault(c => c.Key == "vault_secret_path")?.Value;

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("X-Vault-Token", credentials["api_token"]);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var vaultUrl = $"{vaultUri}{vaultPath}";

            byte[] pfxData =  File.ReadAllBytes(managedCert.CertificatePath);

            var pfxPwd = "";

            var secret = new
            {
                data = new { 
                    key = GetEncodedCertComponent("pemkey", pfxData, pfxPwd), 
                    cert = GetEncodedCertComponent("pemcrt", pfxData, pfxPwd),
                    intermediates = GetEncodedCertComponent("pemchain", pfxData, pfxPwd),
                    pfx = GetEncodedCertComponent("pfxfull", pfxData, pfxPwd)
                }
            };

            /*
                {
                  "data": { },
                  "options": { },
                  "version": 0
                }";
            */

            var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(secret), System.Text.UnicodeEncoding.UTF8, "application/json");

            log.Information($"Deploying to Vault: {vaultUrl}");

            var response = await httpClient.PostAsync(vaultUrl, content);

            if (response.IsSuccessStatusCode)
            {
                return results;
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                return new List<ActionResult> { new ActionResult("Vault storage failed: " + error, false) };
            }
        }

        public string GetEncodedCertComponent(string exportType, byte[] pfxData, string certPwd)
        {
            var export = new CertificateExport();

            string exportString = null;
            if (exportType == "pfxfull")
            {
                exportString = Convert.ToBase64String(pfxData);
            }
            else if (exportType == "pemkey")
            {
                exportString = export.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.PrivateKey);
            }
            else if (exportType == "pemchain")
            {
                exportString = export.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.IntermediateCertificates | ExportFlags.RootCertificate);
            }
            else if (exportType == "pemcrt")
            {
                exportString = export.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.EndEntityCertificate);
            }
            else if (exportType == "pemcrtpartialchain")
            {
                exportString = export.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.EndEntityCertificate | ExportFlags.IntermediateCertificates);
            }
            else if (exportType == "pemfull")
            {
                exportString = export.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.PrivateKey | ExportFlags.EndEntityCertificate | ExportFlags.IntermediateCertificates | ExportFlags.RootCertificate);
            }

            return exportString;
        }

        public async Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition)
        {
            var results = new List<ActionResult> { };

            return await Task.FromResult(results);
        }
    }
}
