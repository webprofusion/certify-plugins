using Certify.Models.Config;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class WaitTask : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        private static int MAX_DURATION = 10 * 60;

        static WaitTask()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.Wait",
                Title = "Wait For N Seconds..",
                IsExperimental = false,
                UsageType = DeploymentProviderUsage.Any,
                SupportedContexts = DeploymentContextType.LocalAsService,
                Description = "Used to pause task execution.",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="duration", Name="Wait Time (seconds)", IsRequired=true, IsCredential=false, Value = "20", Type= OptionType.String }
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

            var definition = GetDefinition(execParams.Definition);

            var validation = await Validate(execParams);
            if (validation.Any())
            {
                return validation;
            }

            if (int.TryParse(execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "duration")?.Value, out var durationSeconds))
            {
                execParams.Log?.Information($"Waiting for {durationSeconds} seconds..");
                await Task.Delay(durationSeconds * 1000, execParams.CancellationToken);
            }

            return new List<ActionResult>();

        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult> { };

            var duration = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "duration")?.Value;

            if (string.IsNullOrEmpty(duration))
            {
                results.Add(new ActionResult("Invalid duration specified. An integer value is required.", false));
                return results;
            }

            if (!int.TryParse(execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "duration")?.Value, out var durationSeconds))
            {
                results.Add(new ActionResult("Invalid duration specified. An integer value is required.", false));
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
