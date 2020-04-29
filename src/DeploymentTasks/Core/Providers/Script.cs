using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Config;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;
using System.Text;
using System;
using System.Diagnostics;
using SimpleImpersonation;
using Plugin.DeploymentTasks.Shared;

namespace Certify.Providers.DeploymentTasks
{
    public class Script : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition) => (currentDefinition ?? Definition);

        static Script()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.ShellExecute",
                Title = "Run...",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.SSH,
                Description = "Run a program, batch file or custom script",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="path", Name="Program/Script", IsRequired=true, IsCredential=false, Description="Command to run, may require a full path"  },
                    new ProviderParameter{ Key="args", Name="Arguments (optional)", IsRequired=false, IsCredential=false  },
                }
            };
        }

        /// <summary>
        /// Execute a script or program either locally or remotely, windows or ssh
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

            definition = GetDefinition(definition);

            var results = await Validate(subject, settings, credentials, definition);
            if (results.Any())
            {
                return results;
            }

            var command = settings.Parameters.FirstOrDefault(c => c.Key == "path")?.Value;
            var args = settings.Parameters.FirstOrDefault(c => c.Key == "args")?.Value;


            //TODO: non-ssh local script
            if (settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_SSH)
            {
                return await RunSSHScript(log, command, args, settings, credentials);
            }

            if (settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL)
            {
                var result = await RunLocalScript(log, command, args, settings, credentials);
                results.Add(result);
            }

            if (settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL || settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER || settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_WINDOWS)
            {
                UserCredentials windowsCredentials = null;
                if (credentials != null && credentials.Count > 0)
                {
                    try
                    {
                        windowsCredentials = Helpers.GetWindowsCredentials(credentials);
                    }
                    catch
                    {
                        var err = "Task with Windows Credentials requires username and password.";
                        log.Error(err);

                        return new List<ActionResult>{
                            new ActionResult { IsSuccess = false, Message = err }
                        };
                    }
                }

                var _defaultLogonType = LogonType.Network;

                await Impersonation.RunAsUser(windowsCredentials, _defaultLogonType, async () =>
                {
                    var result = await RunLocalScript(log, command, args, settings, credentials);
                    results.Add(result);

                });

            }
            return results;
        }

        private static async Task<List<ActionResult>> RunSSHScript(ILog log, string command, string args, DeploymentTaskConfig settings, Dictionary<string, string> credentials)
        {
            var sshConfig = SshClient.GetConnectionConfig(settings, credentials);

            var ssh = new SshClient(sshConfig);

            var commandList = new List<string>
            {
                $"{command} {args}"
            };

            log?.Information("Executing command via SSH");

            var scriptResults = await Task.FromResult(ssh.ExecuteCommands(commandList));

            if (scriptResults.Any(r => r.IsError))
            {
                var firstError = scriptResults.First(c => c.IsError == true);
                return new List<ActionResult> {
                    new ActionResult { IsSuccess = false, Message = $"One or more commands failed: {firstError.Command} :: {firstError.Result}" }
                };
            }
            else
            {
                return new List<ActionResult> {
                    new ActionResult { IsSuccess = true, Message = "Nothing to do" }
                };
            }
        }

        public async Task<List<ActionResult>> Validate(object subject, DeploymentTaskConfig settings, Dictionary<string, string> credentials, DeploymentProviderDefinition definition)
        {
            var results = new List<ActionResult>();

            // validate
            var path = settings.Parameters.FirstOrDefault(c => c.Key == "path")?.Value;

            if (string.IsNullOrEmpty(path))
            {
                results.Add(new ActionResult("A path to a script is required.", false));
            }
            else
            {
                if ((settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL || settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER) && !System.IO.File.Exists(path))
                {
                    results.Add(new ActionResult("There is no local script file present at the given path: " + path, false));
                }
            }

            return results;
        }

        private static async Task<ActionResult> RunLocalScript(ILog log, string command, string args, DeploymentTaskConfig settings, Dictionary<string, string> credentials)
        {
            var _log = new StringBuilder();

            // https://stackoverflow.com/questions/5519328/executing-batch-file-in-c-sharp

            var maxWaitTime = 120;

            var scriptProcessInfo = new ProcessStartInfo(Environment.ExpandEnvironmentVariables(command))
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            if (!string.IsNullOrWhiteSpace(args))
            {
                scriptProcessInfo.Arguments = args;
            }
            else
            {
                _log.AppendLine($"{Definition.Title}: Running script [{command} {args}]");
            }

            try
            {
                var process = new Process { StartInfo = scriptProcessInfo };

                var logMessages = new StringBuilder();

                // capture output streams and add to log
                process.OutputDataReceived += (obj, a) =>
                {
                    if (a.Data != null)
                    {
                        logMessages.AppendLine(a.Data);
                    }
                };

                process.ErrorDataReceived += (obj, a) =>
                {
                    if (!string.IsNullOrWhiteSpace(a.Data))
                    {
                        logMessages.AppendLine($"Error: {a.Data}");
                    }
                };

                try
                {
                    process.Start();

                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    process.WaitForExit((maxWaitTime) * 1000);
                }
                catch (Exception exp)
                {
                    _log.AppendLine("Error Running Script: " + exp.ToString());
                }

                // append output to main log
                _log.Append(logMessages.ToString());

                if (!process.HasExited)
                {
                    //process still running, kill task
                    process.CloseMainWindow();

                    _log.AppendLine("Warning: Script ran but took too long to exit and was closed.");
                }
                else if (process.ExitCode != 0)
                {
                    _log.AppendLine("Warning: Script exited with the following ExitCode: " + process.ExitCode);
                }
                return await Task.FromResult(new ActionResult { IsSuccess = true, Message = _log.ToString() });
            }
            catch (Exception exp)
            {
                _log.AppendLine("Error: " + exp.ToString());
                return await Task.FromResult(new ActionResult { IsSuccess = false, Message = _log.ToString() });
            }
        }
    }


}
