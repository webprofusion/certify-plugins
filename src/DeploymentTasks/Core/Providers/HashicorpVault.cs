using Certify.Models;
using Certify.Models.Config;
using Certify.Shared.Core.Utils.PKI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

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
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
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
            string vaultUri = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "vault_uri")?.Value;
            string vaultPath = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "vault_secret_path")?.Value;

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("X-Vault-Token", execParams.Credentials["api_token"]);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var vaultUrl = $"{vaultUri}{vaultPath}";

            byte[] pfxData = File.ReadAllBytes(managedCert.CertificatePath);

            var pfxPwd = "";

            var secret = new
            {
                data = new
                {
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

            execParams.Log.Information($"Deploying to Vault: {vaultUrl}");

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
            string exportString = null;
            if (exportType == "pfxfull")
            {
                exportString = Convert.ToBase64String(pfxData);
            }
            else if (exportType == "pemkey")
            {
                exportString = CertUtils.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.PrivateKey);
            }
            else if (exportType == "pemchain")
            {
                exportString = CertUtils.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.IntermediateCertificates | ExportFlags.RootCertificate);
            }
            else if (exportType == "pemcrt")
            {
                exportString = CertUtils.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.EndEntityCertificate);
            }
            else if (exportType == "pemcrtpartialchain")
            {
                exportString = CertUtils.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.EndEntityCertificate | ExportFlags.IntermediateCertificates);
            }
            else if (exportType == "pemfull")
            {
                exportString = CertUtils.GetCertComponentsAsPEMString(pfxData, certPwd, ExportFlags.PrivateKey | ExportFlags.EndEntityCertificate | ExportFlags.IntermediateCertificates | ExportFlags.RootCertificate);
            }

            return exportString;
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult> { };

            return await Task.FromResult(results);
        }
    }
}
