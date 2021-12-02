using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Microsoft.TeamFoundation.DistributedTask.WebApi;
using Microsoft.VisualStudio.Services.Common;
using Microsoft.VisualStudio.Services.WebApi;

using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;

namespace Plugin.DeploymentTasks.AzureDevOps
{

    /// <summary>
    /// Deployment task to update a thumbprint in an AzureDevOps variable group
    /// Contributed by Timo Jansen - madesmart.nl - 01/Dec/2021
    /// </summary>
    public class AzureDevOps : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private IdnMapping _idnMapping = new IdnMapping();

        static AzureDevOps()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.AzureDevOps",
                Title = "Add/Update Thumbprint in Azure DevOps",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.ExternalCredential,
                ExternalCredentialType = StandardAuthTypes.STANDARD_AUTH_API_TOKEN,
                Description = "Store a certificate thumbprint in Microsoft Azure DevOps variable",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="devops_uri", Name="Azure DevOps Uri", IsRequired=true, IsCredential=false,  Description="e.g. https://dev.azure.com/<tenant>", Type= OptionType.String },
                    new ProviderParameter{ Key="project_name", Name="Azure DevOps Project", IsRequired=true, IsCredential=false,  Description="e.g. Applications", Type= OptionType.String },
                    new ProviderParameter{ Key="group_name", Name="Variable-Group Name", IsRequired=true, IsCredential=false,  Description="e.g. Certificates", Type= OptionType.String },
                    new ProviderParameter{ Key="cert_name", Name="Certificate Name", IsRequired=false, IsCredential=false,  Description="(optional, alphanumeric characters 0-9a-Z, . or _)", Type= OptionType.String }
                }
            };
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult> { };

            var uri = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "devops_uri")?.Value;
            if (string.IsNullOrEmpty(uri))
            {
                results.Add(new ActionResult("Devops URI is required e.g. https://dev.azure.com/<tenant>", false));
            }

            var project = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "project_name")?.Value;
            if (string.IsNullOrEmpty(project))
            {
                results.Add(new ActionResult("Devops Project Name is required", false));
            }

            var group = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "group_name")?.Value;
            if (string.IsNullOrEmpty(group))
            {
                results.Add(new ActionResult("Group name is required", false));
            }

            var cert_name = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "cert_name")?.Value;
            if (!string.IsNullOrEmpty(cert_name))
            {
                if (!Regex.IsMatch(cert_name, "^[0-9a-zA-Z._]+$"))
                {
                    results.Add(new ActionResult("Certificate name can only be alphanumeric.", false));
                }
            }
            return await Task.FromResult(results);
        }


        /// <summary>
        /// Deploy current cert thumbprint to Azure DevOps
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

            var token = execParams.Credentials["api_token"];
            var url = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "devops_uri")?.Value;
            var project = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "project_name")?.Value;
            var groupName = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "group_name")?.Value;
            var customName = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "cert_name")?.Value ?? managedCert.Name;

            var certName = GetStringAsVariableName(customName ?? managedCert.Name);

            try
            {
                var creds = new VssBasicCredential(string.Empty, token);
                VssConnection vssConnection = new VssConnection(new Uri(url), creds);

                var client = vssConnection.GetClient<TaskAgentHttpClient>();
                var group = client.GetVariableGroupsAsync(project, groupName).Result.FirstOrDefault();
                if (group == null)
                    throw new InvalidOperationException($"Variable group with name {groupName} was not found in project {project}. Please make sure the variable group exists");

                var vgp = new VariableGroupParameters()
                {
                    Name = group.Name,
                    Description = group.Description,
                    Type = group.Type,
                    ProviderData = group.ProviderData,
                    Variables = group.Variables
                };

                vgp.Variables[certName] = managedCert.CertificateThumbprintHash;
                var res = client.UpdateVariableGroupAsync(project, group.Id, vgp).Result;

                if (res == null)
                    throw new InvalidOperationException("Error updating variable group");

            }
            catch (Exception ex)
            {
                execParams.Log.Error($"Failed to update certificate thumbprint for [{certName}] to Azure DevOps :{ex}");
                results.Add(new ActionResult($"DevOps Deployment Failed: {ex}", false));
            }

            return results;
        }

        /// <summary>
        /// https://docs.microsoft.com/en-us/azure/devops/pipelines/process/variables?view=azure-devops&tabs=yaml%2Cbatch#variable-naming-restrictions
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        private string GetStringAsVariableName(string name)
        {
            if (name == null) return null;

            var ascii = _idnMapping.GetAscii(name);

            // ^[0-9a-zA-Z._]+$ : alphanumeric or '.' or '_'
            ascii = ascii.Replace('-', '_');
            ascii = ascii.Replace(" ", "");

            return ascii;
        }
    }
}
