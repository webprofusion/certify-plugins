﻿using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Plugin.DeploymentTasks.Shared;
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
                SupportsRemoteTarget = false,
                Description = "Run a Powershell script",
                ProviderParameters = new System.Collections.Generic.List<ProviderParameter>
                {
                    new ProviderParameter{ Key="scriptpath", Name="Program/Script", IsRequired=true, IsCredential=false, Description="Command to run, may require a full path"  },
                    new ProviderParameter{ Key="inputresult", Name="Pass Result as First Arg", IsRequired=false, IsCredential=false, Type= OptionType.Boolean, Value="true"  },
                    new ProviderParameter{ Key="logontype", Name="Impersonation LogonType", IsRequired=false, IsCredential=false, Type= OptionType.Select, Value="network", OptionsList=Helpers.LogonTypeOptions  },
                    new ProviderParameter{ Key="args", Name="Arguments (optional)", IsRequired=false, IsCredential=false, Description="optional arguments in the form arg1=value;arg2=value"  },
                    new ProviderParameter{ Key="timeout", Name="Script Timeout Mins.", IsRequired=false, IsCredential=false, Description="optional number of minutes to wait for the script before timeout."  },
                    new ProviderParameter{ Key="newprocess", Name="Launch New Process", IsRequired=false, Type= OptionType.Boolean, IsCredential = false, Value="false" }
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

            var timeoutMinutes = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "timeout")?.Value;

            int.TryParse(timeoutMinutes, out var timeout);

            if (timeout < 1 || timeout > 120)
            {
                timeout = 5;
            }

            var launchNewProcess = false;
            if (bool.TryParse(execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "newprocess")?.Value, out var parsedBool))
            {
                launchNewProcess = parsedBool;
            }

            var parameters = new Dictionary<string, object>();
            if (inputResultAsArgument?.Trim().ToLower() == "true")
            {
                parameters.Add("result", certRequest);
            };

            if (!string.IsNullOrEmpty(args))
            {
                args = SubstituteEscapedCharacters(args);

                foreach (var o in args.Split(';'))
                {
                    if (!string.IsNullOrEmpty(o))
                    {
                        var keyValuePair = o.Split('=');

                        if (keyValuePair.Length == 1)
                        {
                            // item has a key only
                            var key = RestoreEscapedCharacters(keyValuePair[0]).Trim();
                            parameters.Add(key, "");
                        }
                        else
                        {
                            // item has a key and value
                            var key = RestoreEscapedCharacters(keyValuePair[0]).Trim();
                            var val = RestoreEscapedCharacters(keyValuePair[1]).Trim();
                            parameters.Add(key, val);
                        }
                    }
                }
            }

            execParams.Log?.Information("Executing command via PowerShell");

            var logonType = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "logontype")?.Value ?? null;

            // if running as local/default service user no credentials are provided for user impersonation
            var credentials = execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL ? null : execParams.Credentials;

            var result = await PowerShellManager.RunScript(execParams.Context.PowershellExecutionPolicy, null, command, parameters, null, credentials: credentials, logonType: logonType, timeoutMinutes: timeout, launchNewProcess: launchNewProcess);

            results.Add(result);

            return results;
        }

        /// <summary>
        /// Before parsing arguments, allow for escaped characters
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        private string SubstituteEscapedCharacters(string args)
        {
            // substitute escaped semicolons
            args = args.Replace(@"\;", "🏠");

            // substitute escaped =
            args = args.Replace(@"\=", "▶️");

            // substitute escaped \
            args = args.Replace(@"\\", "⏫");

            return args;
        }

        /// <summary>
        /// After parsing arguments, restore escaped characters
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        private string RestoreEscapedCharacters(string value)
        {
            if (value == null) return value;

            // restore escaped semicolons
            value = value.Replace("🏠", ";");

            // restore escaped =
            value = value.Replace("▶️", "=");

            // restore escaped \
            value = value.Replace("⏫", @"\");

            return value;
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            var path = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "scriptpath")?.Value;

            if (string.IsNullOrEmpty(path))
            {
                results.Add(new ActionResult("A path to a script file is required.", false));
            }

            var args = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "args")?.Value;
            if (args != null)
            {
                if (args.Trim().StartsWith("-"))
                {
                    results.Add(new ActionResult("Arguments must be provided in the format arg1=value;arg2=value;arg3=value", false));
                }
            }

            var timeoutMinutes = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "timeout")?.Value;
            if (!string.IsNullOrEmpty(timeoutMinutes))
            {
                if (!int.TryParse(timeoutMinutes, out var timeout))
                {
                    results.Add(new ActionResult("Timeout (Minutes) value is invalid", false));
                }

                if (timeout < 1 || timeout > 120)
                {
                    results.Add(new ActionResult("Timeout (Minutes) value is out of range (1-120).", false));
                }
            }
            return await Task.FromResult(results);
        }
    }
}
