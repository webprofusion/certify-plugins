using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Config;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Management;
using SimpleImpersonation;
using Plugin.DeploymentTasks.Shared;

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
                    new ProviderParameter{ Key="inputresult", Name="Pass Result as First Argument", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="true"  },
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
        public async Task<List<ActionResult>> Execute(
          ILog log,
          object subject,
          DeploymentTaskConfig settings,
          Dictionary<string, string> credentials,
          bool isPreviewOnly,
          DeploymentProviderDefinition definition = null
          )
        {
            var results = new List<ActionResult>();

            definition = GetDefinition(definition);

            var certRequest = subject as CertificateRequestResult;

            var command = settings.Parameters.FirstOrDefault(c => c.Key == "scriptpath")?.Value;
            var args = settings.Parameters.FirstOrDefault(c => c.Key == "args")?.Value;

            var inputResultAsArgument = settings.Parameters.FirstOrDefault(c => c.Key == "inputresult")?.Value;

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


            log?.Information("Executing command via PowerShell");

            var result = await PowerShellManager.RunScript(null, command, parameters, null, credentials: credentials);

            results.Add(result);

            return results;
        }

        public async Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition)
        {
            var results = new List<ActionResult>();

            var path = settings.Parameters.FirstOrDefault(c => c.Key == "scriptpath")?.Value;

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

            return results;
        }
    }
}
