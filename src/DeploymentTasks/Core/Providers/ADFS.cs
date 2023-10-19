﻿using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Plugin.DeploymentTasks.Shared;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class Adfs : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition) => (currentDefinition ?? Definition);

        private const string SCRIPT_NAME = "ADFS.ps1";

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {
            var validation = await Validate(execParams);

            if (validation.Any())
            {
                return validation;
            }

            var script = Helpers.ReadStringResource(SCRIPT_NAME);

            var definition = execParams.Definition;

            definition = GetDefinition(definition);

            var certRequest = execParams.Subject as CertificateRequestResult;

            execParams.Log?.Information("Executing command via PowerShell");

            var performRestart = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "performServiceRestart")?.Value ?? "false";
            var alternateTlsBinding = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "alternateTlsBinding")?.Value ?? "false";
            var logonType = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "logontype")?.Value ?? null;

            var parameters = new Dictionary<string, object>
            {
                { "performServiceRestart", performRestart },
                { "alternateTlsBinding", alternateTlsBinding }
            };

            var scriptResult = await PowerShellManager.RunScript(execParams.Context.PowershellExecutionPolicy, certRequest, parameters: parameters, scriptContent: script, credentials: execParams.Credentials, logonType: logonType);

            return new List<ActionResult> { scriptResult };
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            // validate

            return await Task.FromResult(results);
        }

        static Adfs()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.ADFS",
                Title = "Deploy to ADFS",
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork,
                IsExperimental = true,
                Description = "Apply certificate to local Active Directory Federation Services (ADFS) service",
                ProviderParameters = new List<ProviderParameter>
                {
                     new ProviderParameter { Key = "restartServices", Name = "Include Service Restart",  Type= OptionType.Boolean, IsCredential = false,Value="true" },
                     new ProviderParameter { Key = "alternateTlsBinding", Name = "Use Alternate TLS client binding",  Type= OptionType.Boolean, IsCredential = false,Value="false" },
                     new ProviderParameter { Key = "logontype", Name = "Impersonation LogonType", IsRequired= false, IsCredential= false, Type= OptionType.Select, Value="interactive", OptionsList=Helpers.LogonTypeOptions },
                     // Note on LogonTypes: The following have been tested to work with Deploy to ADFS to impersonate users: Service, Interactive, Batch
                }
            };
        }
    }
}
