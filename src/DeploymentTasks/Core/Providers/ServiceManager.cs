using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models.Config;
using Certify.Models.Providers;

namespace Certify.Providers.DeploymentTasks
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
                var services = ServiceController.GetServices().OrderBy(s => s.DisplayName);

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
          DeploymentProviderDefinition definition,
          CancellationToken cancellationToken
          )
        {

            definition = GetDefinition(definition);

            List<ActionResult> results = await Validate(subject, settings, credentials, definition);
            if (results.Any())
            {
                return results;
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
                if (service.Status != ServiceControllerStatus.Stopped)
                {
                    if (!isPreviewOnly)
                    {
                        service = await StopServiceWithRetry(log, servicename, service, ticks);
                    }
                }
                else
                {
                    log?.Information($"Service already stopped [{servicename}] ");
                }

                if (!isPreviewOnly)
                {
                    service = await StartServiceWithRetry(log, servicename, service, ticks);
                }

                results.Add(new ActionResult("Service Restarted", true));

            }
            else if (action == "stop")
            {
                if (service.Status != ServiceControllerStatus.Stopped)
                {
                    if (!isPreviewOnly)
                    {
                        service = await StopServiceWithRetry(log, servicename, service, ticks);
                    }

                    results.Add(new ActionResult("Service Stopped", true));
                }
                else
                {
                    log?.Information($"Service already stopped [{servicename}] ");

                    results.Add(new ActionResult("Service already stopped", true));
                }
            }
            else if (action == "start")
            {
                if (!isPreviewOnly)
                {
                    service = await StartServiceWithRetry(log, servicename, service, ticks);
                }

                results.Add(new ActionResult("Service Started", true));
            }

            return results;

        }

        private static async Task<ServiceController> StopServiceWithRetry(ILog log, string servicename, ServiceController service, TimeSpan ticks)
        {
            log?.Information($"Stopping service [{servicename}] ");

            try
            {
                service.Stop();
            }
            catch (InvalidOperationException)
            {
                log?.Information($"First attempt to stop service encountered an Invalid Operation. Retrying stop for [{servicename}] ");

                await Task.Delay(1000);

                service = new ServiceController(servicename);

                if (service.Status != ServiceControllerStatus.Stopped)
                {
                    service.Stop();
                }

            }

            service.WaitForStatus(ServiceControllerStatus.Stopped, ticks);
            return service;
        }

        private static async Task<ServiceController> StartServiceWithRetry(ILog log, string servicename, ServiceController service, TimeSpan ticks)
        {
            log?.Information($"Starting service [{servicename}] ");

            try
            {
                service.Start();
            }
            catch (InvalidOperationException)
            {
                log?.Information($"First attempt to start service encountered an Invalid Operation. Retrying start for [{servicename}] ");

                await Task.Delay(1000);

                service = new ServiceController(servicename);

                if (service.Status != ServiceControllerStatus.Running)
                {
                    service.Start();
                }
            }

            service.WaitForStatus(ServiceControllerStatus.Running, ticks);
            return service;
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

            return await Task.FromResult(results);
        }
    }
}
