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
    public class Doppler : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static Doppler()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Doppler",
                Title = "Deploy to Doppler",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_API_TOKEN,
                Description = "Store your certificate and private key as a secret in Doppler.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="project", Name="Project Name", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. PROJECT_NAME" },
                    new ProviderParameter{ Key="config", Name="Config Name", IsRequired=false, IsCredential=false, Type= OptionType.String, Description="e.g. dev, prd etc" },
                    new ProviderParameter{ Key="secretname_cert", Name="Name for Certificate", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. EXAMPLE_COM_CERT" },
                    new ProviderParameter{ Key="secretname_key", Name="Name for Private Key", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="e.g. EXAMPLE_COM_KEY" },
                    new ProviderParameter{ Key="secretname_fullchain", Name="Name for Fullchain", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="(optional)" },
                    new ProviderParameter{ Key="secretname_pfx", Name="Name for PFX", IsRequired=true, IsCredential=false, Type= OptionType.String, Description="(optional)" }

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
            var doppler_project = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "project")?.Value;
            var doppler_config = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "config")?.Value;
            var secretname_cert = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_cert")?.Value;
            var secretname_key = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_key")?.Value;
            var secretname_fullchain = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_fullchain")?.Value;
            var secretname_pfx = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_pfx")?.Value;

            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("authorization",$"Bearer {execParams.Credentials["api_token"]}");

            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var pfxData = File.ReadAllBytes(managedCert.CertificatePath);

            var pfxPwd = "";

            // get PFX password if in use
            if (!string.IsNullOrWhiteSpace(managedCert.CertificatePasswordCredentialId))
            {
                var pwdCred = await execParams.CredentialsManager.GetUnlockedCredentialsDictionary(managedCert.CertificatePasswordCredentialId);
                if (pwdCred != null)
                {
                    pfxPwd = pwdCred["password"];
                }
            }

            var secret = new
            {
                key = GetEncodedCertComponent("pemkey", pfxData, pfxPwd),
                cert = GetEncodedCertComponent("pemcrt", pfxData, pfxPwd),
                fullchain = GetEncodedCertComponent("pemcrtpartialchain", pfxData, pfxPwd),
                pfx = GetEncodedCertComponent("pfxfull", pfxData, pfxPwd)
            };

            var secrets = new Dictionary<string, string>();

            if (!string.IsNullOrEmpty(secretname_cert))
            {
                secrets.Add(secretname_cert, secret.cert);
            };

            if (!string.IsNullOrEmpty(secretname_key))
            {
                secrets.Add(secretname_key, secret.key);
            };

            if (!string.IsNullOrEmpty(secretname_fullchain))
            {
                secrets.Add(secretname_fullchain, secret.fullchain);
            };

            if (!string.IsNullOrEmpty(secretname_pfx))
            {
                secrets.Add(secretname_pfx, secret.pfx);
            };

            var payload = new
            {
                project = doppler_project,
                config = doppler_config,
                secrets = secrets,
            };
            execParams.Log.Information($"Deploying to Doppler: {doppler_project}::{doppler_config}");

            var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(payload), System.Text.UnicodeEncoding.UTF8, "application/json");

            var response = await httpClient.PostAsync("https://api.doppler.com/v3/configs/config/secrets", content);

            if (response.IsSuccessStatusCode)
            {
                return results;
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                return new List<ActionResult> { new ActionResult("Doppler update failed: " + error, false) };
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

            var doppler_project = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "project")?.Value;
            var doppler_config = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "config")?.Value;
            var secretname_cert = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_cert")?.Value;
            var secretname_key = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_key")?.Value;
            var secretname_fullchain = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_fullchain")?.Value;
            var secretname_pfx = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "secretname_pfx")?.Value;

            if (string.IsNullOrEmpty(doppler_project) || string.IsNullOrEmpty(doppler_config))
            {
                results.Add(new ActionResult("Doppler project and config names required.", false));
            }

            return await Task.FromResult(results);
        }
    }
}
