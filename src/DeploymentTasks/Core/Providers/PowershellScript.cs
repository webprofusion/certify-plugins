using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class PowershellScript : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition) => (currentDefinition ?? Definition);

        static PowershellScript()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Powershell",
                Title = "Run Powershell Script",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.Any,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork,
                Description = "Run a Powershell script",
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>
                {
                    new ProviderParameter{ Key="scriptpath", Name="Program/Script", IsRequired=true, IsCredential=false, Description="Command to run, may require a full path"  },
                    new ProviderParameter{ Key="inputresult", Name="Pass Result as First Arg", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="true"  },
                    new ProviderParameter{ Key="logontype", Name="Impersonation LogonType", IsRequired=false, IsCredential=false, Type= OptionType.Select, Value="network", OptionsList="network=Network;newcredentials=New Credentials;service=Service;interactive=Interactive;batch=Batch"  },
                    new ProviderParameter{ Key="args", Name="Arguments (optional)", IsRequired=false, IsCredential=false, Description="optional arguments in the form arg1=value;arg2=value"  },
                }
            };
        }

        /// <summary>
        /// Execute a local powershell script
        /// </summary>
        /// <param name="log"></param>
        /// <param name="managedCert"></param>
        /// <param name="settings"></param>
        /// <param name="credentials"></param>
        /// <param name="isPreviewOnly"></param>
        /// <returns></returns>
        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            var certRequest = execParams.Subject as CertificateRequestResult;

            var command = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "scriptpath")?.Value;
            var args = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "args")?.Value;

            var inputResultAsArgument = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "inputresult")?.Value;

            var parameters = new Dictionary<string, object>();
            if (inputResultAsArgument?.Trim().ToLower() == "true")
            {
                parameters.Add("result", certRequest);
            };

            if (!string.IsNullOrEmpty(args))
            {
                foreach (var o in args.Split(';'))
                {
                    if (!string.IsNullOrEmpty(o))
                    {
                        var keyValuePair = o.Split('=');

                        if (keyValuePair.Length == 1)
                        {
                            // item has a key only
                            parameters.Add(keyValuePair[0].Trim(), "");
                        }
                        else
                        {
                            // item has a key and value
                            parameters.Add(keyValuePair[0].Trim(), keyValuePair[1].Trim());
                        }
                    }
                }
            }

            execParams.Log?.Information("Executing command via PowerShell");

            string logonType = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "logontype")?.Value ?? null;

            // if running as local/default service user no credentials are provided for user impersonation
            var credentials = execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL ? null : execParams.Credentials;

            var result = await PowerShellManager.RunScript(execParams.Context.PowershellExecutionPolicy, null, command, parameters, null, credentials: credentials, logonType: logonType);

            results.Add(result);

            return results;
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            var path = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "scriptpath")?.Value;

            if (string.IsNullOrEmpty(path))
            {
                results.Add(new ActionResult("A path to a script is required.", false));
            }
            else
            {
                if (!System.IO.File.Exists(path))
                {
                    results.Add(new ActionResult("There is no script file present at the given path: " + path, false));
                }
            }

            return await Task.FromResult(results);
        }
    }
}
