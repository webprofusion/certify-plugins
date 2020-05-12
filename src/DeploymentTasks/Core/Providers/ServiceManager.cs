using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models.Config;
using Certify.Models.Providers;

namespace Certify.Providers.DeploymentTasks.Core
{
    public class ServiceManager : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null)
        {
            var definition = (currentDefinition ?? Definition);

            // this provider has dynamic properties to list the available services


            // TODO: current user may not have access
            try
            {
                // populate options list with list of current services
                var services = ServiceController.GetServices().OrderBy(s=>s.DisplayName);
                
                var p = definition.ProviderParameters.First(k => k.Key == "servicename");

                p.OptionsList = string.Join(";", services.Select(s => s.ServiceName + "=" + s.DisplayName));


            }
            catch { }

            return definition;
        }


        private static int MAX_DURATION = 10 * 60;

        static ServiceManager()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.ServiceManager",
                Title = "Stop, Start or Restart a Service",
                IsExperimental = true,
                HasDynamicParameters = true,
                UsageType = DeploymentProviderUsage.Any,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.WindowsNetwork,
                Description = "Used to restart a service affected by certificate updates.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="servicename", Name="Service", IsRequired=true, IsCredential=false, Type= OptionType.Select, OptionsList="W3SVC=World Wide Web Publishing Service;"},
                    new ProviderParameter{ Key="action", Name="Action", IsRequired=true, IsCredential=false, Value = "restart", Type= OptionType.Select, OptionsList="restart=Restart Service;stop=Stop Service;start=Start Service;"},
                    new ProviderParameter{ Key="maxwait", Name="Max. Wait Time (secs)", IsRequired=true, IsCredential=false, Value = "20", Type= OptionType.String }
                }
            };
        }

        public async Task<List<ActionResult>> Execute(
          ILog log,
          object subject,
          DeploymentTaskConfig settings,
          Dictionary<string, string> credentials,
          bool isPreviewOnly,
          DeploymentProviderDefinition definition
          )
        {

            definition = GetDefinition(definition);

            var validation = await Validate(subject, settings, credentials, definition);
            if (validation.Any())
            {
                return validation;
            }

            if (!int.TryParse(settings.Parameters.FirstOrDefault(c => c.Key == "maxwait")?.Value, out var durationSeconds))
            {
                durationSeconds = 20;
            }

            var servicename = settings.Parameters.FirstOrDefault(c => c.Key == "servicename")?.Value;
            var action = settings.Parameters.FirstOrDefault(c => c.Key == "action")?.Value;

            ServiceController service = new ServiceController(servicename);

            var ticks = System.TimeSpan.FromSeconds(durationSeconds);

            if (action == "restart")
            {
                log?.Information($"Stopping service [{servicename}] ");

                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, ticks);

                log?.Information($"Starting service [{servicename}] ");

                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, ticks);
            }
            else if (action == "stop")
            {
                log?.Information($"Stopping service [{servicename}] ");

                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, ticks);
            }
            else if (action == "start")
            {
                log?.Information($"Starting service [{servicename}] ");

                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, ticks);
            }

            return new List<ActionResult>();

        }

        public async Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition)
        {
            var results = new List<ActionResult> { };

            var action = settings.Parameters.FirstOrDefault(c => c.Key == "action")?.Value;

            if (string.IsNullOrEmpty(action))
            {
                results.Add(new ActionResult("An action is required.", false));
                return results;
            }

            var servicename = settings.Parameters.FirstOrDefault(c => c.Key == "servicename")?.Value;

            if (string.IsNullOrEmpty(servicename))
            {
                results.Add(new ActionResult("A service name is required.", false));
                return results;
            }

            var duration = settings.Parameters.FirstOrDefault(c => c.Key == "maxwait")?.Value;

            if (string.IsNullOrEmpty(duration))
            {
                results.Add(new ActionResult("Invalid wait duration specified. An integer value is required.", false));
                return results;
            }

            if (!int.TryParse(settings.Parameters.FirstOrDefault(c => c.Key == "maxwait")?.Value, out var durationSeconds))
            {
                results.Add(new ActionResult("Invalid wait duration specified. An integer value is required.", false));
            }
            else
            {
                if (durationSeconds < 0 || durationSeconds > MAX_DURATION)
                {
                    results.Add(new ActionResult($"Duration specified is outside the supported range. Max wait duration is {MAX_DURATION}", false));
                }
            }

            return results;
        }
    }
}
