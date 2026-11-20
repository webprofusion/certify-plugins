using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Plugin.DeploymentTasks.Shared;

namespace Certify.Providers.DeploymentTasks
{
    public class UpdatePortBinding : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private const string SCRIPT_NAME = "UpdatePortBinding.ps1";

        /// <summary>
        /// App Id used when none is given, which helps identify bindings made by this task (must match UpdatePortBinding.ps1)
        /// </summary>
        public const string DEFAULT_APP_ID = "c0a1e5ce-c001-c0de-ba5e-000000000042";

        static UpdatePortBinding()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.UpdatePortBinding",
                Title = "Update Port Binding",
                DefaultTitle = "Update Port Binding",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService,
                Description = "Uses netsh to update a IP:port certificate binding",
                ProviderParameters = new List<ProviderParameter>
                {
                      new ProviderParameter{ Key="ip", Name="IP", IsRequired=true, IsCredential=false, Value="0.0.0.0", Description="e.g. 0.0.0.0 would bind for all IPs"},
                      new ProviderParameter{ Key="port", Name="Port", IsRequired=true, IsCredential=false},
                      new ProviderParameter{ Key="appid", Name="App Id (Guid)", IsRequired=false, IsCredential=false, Description="(optional)"},
                }
            };
        }

        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var validation = await Validate(execParams);

            if (validation.Any())
            {
                return validation;
            }

            var script = Helpers.ReadStringResource(SCRIPT_NAME);

            var certRequest = execParams.Subject as CertificateRequestResult;

            execParams.Log?.Information("Executing command via PowerShell");

            var ip = IPAddress.Parse(execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "ip")?.Value.Trim());
            var port = int.Parse(execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "port")?.Value.Trim());
            var appid = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "appid")?.Value?.Trim();

            var parameters = new Dictionary<string, object>
            {
                { "ipport", GetIpPort(ip, port) },
                { "appid", string.IsNullOrWhiteSpace(appid) ? null : Guid.Parse(appid).ToString() }
            };

            var scriptResult = await PowerShellManager.RunScript(new PowerShellScriptSettings
            {
                PowerShellExecutionPolicy = execParams.Context.PowershellExecutionPolicy,
                Result = certRequest,
                Parameters = parameters,
                ScriptContent = script,
                Credentials = execParams.Credentials,
                ExecutionMode = PowerShellExecutionMode.Automatic
            });

            return new List<ActionResult> { scriptResult };
        }

        /// <summary>
        /// The netsh ipport value, e.g. 0.0.0.0:443 or [::]:443
        /// </summary>
        public static string GetIpPort(IPAddress ip, int port) => ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{ip}]:{port}" : $"{ip}:{port}";

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            var ip = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "ip")?.Value?.Trim();

            if (string.IsNullOrEmpty(ip))
            {
                results.Add(new ActionResult("An IP is required. Use 0.0.0.0 to catch all.", false));
            }
            else if (!IPAddress.TryParse(ip, out _))
            {
                results.Add(new ActionResult($"Invalid IP address [{ip}]. Use an IP address such as 0.0.0.0 (all IPv4 addresses) or ::.", false));
            }

            var port = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "port")?.Value?.Trim();

            if (string.IsNullOrEmpty(port))
            {
                results.Add(new ActionResult("A port number is required.", false));
            }
            else if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var portNumber) || portNumber < 1 || portNumber > 65535)
            {
                results.Add(new ActionResult($"Invalid port number [{port}]. The port must be a number from 1 to 65535.", false));
            }

            var guid = execParams.Settings.Parameters.FirstOrDefault(p => p.Key == "appid")?.Value?.Trim();

            if (!string.IsNullOrWhiteSpace(guid) && (!Guid.TryParseExact(guid, "D", out _)))
            {
                results.Add(new ActionResult($"Invalid App Id (GUID). Don't include braces, or leave blank to use the default App Id {DEFAULT_APP_ID}.", false));
            }

            return await Task.FromResult(results);
        }
    }
}
