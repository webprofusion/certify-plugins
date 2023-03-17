﻿using Certify.Config;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers.Deployment.Core.Shared;
using Plugin.DeploymentTasks.Shared;
using SimpleImpersonation;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Certify.Providers.DeploymentTasks
{
    public class Script : IDeploymentTaskProvider
    {
        public static DeploymentProviderDefinition Definition { get; }
        public DeploymentProviderDefinition GetDefinition(DeploymentProviderDefinition currentDefinition = null) => (currentDefinition ?? Definition);

        static Script()
        {
            Definition = new DeploymentProviderDefinition
            {
                Id = "Certify.Providers.DeploymentTasks.ShellExecute",
                Title = "Run...",
                IsExperimental = true,
                UsageType = DeploymentProviderUsage.PostRequest,
                SupportedContexts = DeploymentContextType.LocalAsService | DeploymentContextType.LocalAsUser | DeploymentContextType.SSH,
                SupportsRemoteTarget = true,
                Description = "Run a program, batch file or custom script",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="path", Name="Program/Script", IsRequired=true, IsCredential=false, Description="Command to run, may require a full path"  },
                    new ProviderParameter{ Key="args", Name="Arguments (optional)", IsRequired=false, IsCredential=false  },
                    new ProviderParameter{ Key="timeout", Name="Script Timeout Mins.", IsRequired=false, IsCredential=false, Description="optional number of minutes to wait for the script before timeout."  },
                    new ProviderParameter{ Key="newprocess", Name="Launch New Process", IsRequired=false, Type= OptionType.Boolean, IsCredential = false, Value="false" }
                }
            };
        }

        /// <summary>
        /// Execute a script or program either locally or remotely, windows or ssh
        /// </summary>

        /// <returns></returns>
        public async Task<List<ActionResult>> Execute(DeploymentTaskExecutionParams execParams)
        {

            var definition = GetDefinition(execParams.Definition);

            var results = await Validate(execParams);
            if (results.Any())
            {
                return results;
            }

            var command = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "path")?.Value;
            var args = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "args")?.Value;

            var timeoutMinutes = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "timeout")?.Value;

            int.TryParse(timeoutMinutes, out var timeout);

            if (timeout < 1 || timeout > 120)
            {
                timeout = 2;
            }

            var launchNewProcess = false;
            if (bool.TryParse(execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "newprocess")?.Value, out var parsedBool))
            {
                launchNewProcess = parsedBool;
            }

            if (execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_SSH)
            {
                return await RunSSHScript(execParams.Log, command, args, execParams.Settings, execParams.Credentials);
            }
            else if (execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL)
            {
                var result = RunLocalScript(execParams.Log, command, args, execParams.Settings, execParams.Credentials, timeout);
                results.Add(result);
            }
            else if (execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER || execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_WINDOWS)
            {
                UserCredentials windowsCredentials = null;
                if (execParams.Credentials != null && execParams.Credentials.Count > 0)
                {
                    try
                    {
                        windowsCredentials = Helpers.GetWindowsCredentials(execParams.Credentials);
                    }
                    catch
                    {
                        var err = "Task with Windows Credentials requires username and password.";
                        execParams.Log.Error(err);

                        return new List<ActionResult>{
                            new ActionResult { IsSuccess = false, Message = err }
                        };
                    }
                }

                if (launchNewProcess)
                {
                    // start process as new user
                    var result = RunLocalScript(execParams.Log, command, args, execParams.Settings, execParams.Credentials, timeout, true);
                    results.Add(result);
                }
                else
                {
                    // default is to wrap in an impersonation context
                    var _defaultLogonType = LogonType.Interactive;

                    using (var userHandle = windowsCredentials.LogonUser(_defaultLogonType))
                    {
                        WindowsIdentity.RunImpersonated(userHandle, () =>
                        {
                            var result = RunLocalScript(execParams.Log, command, args, execParams.Settings, execParams.Credentials, timeout, false);
                            results.Add(result);
                        });
                    }

                }
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

            log?.Information($"Executing command via SSH [{sshConfig.Host}:{sshConfig.Port}]");

            var scriptResults = await Task.FromResult(ssh.ExecuteCommands(commandList, log));

            if (scriptResults.Any(r => r.IsError))
            {
                var firstError = scriptResults.First(c => c.IsError);
                return new List<ActionResult> {
                    new ActionResult { IsSuccess = false, Message = $"One or more commands failed: {firstError.Command} :: {firstError.Result}" }
                };
            }
            else
            {
                return new List<ActionResult> {
                    new ActionResult { IsSuccess = true, Message = "Command Completed" }
                };
            }
        }

        public async Task<List<ActionResult>> Validate(DeploymentTaskExecutionParams execParams)
        {
            var results = new List<ActionResult>();

            // validate
            var path = execParams.Settings.Parameters.FirstOrDefault(c => c.Key == "path")?.Value;

            if (string.IsNullOrEmpty(path))
            {
                results.Add(new ActionResult("A path to a script is required.", false));
            }
            else
            {
                if ((execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL || execParams.Settings.ChallengeProvider == StandardAuthTypes.STANDARD_AUTH_LOCAL_AS_USER) && !System.IO.File.Exists(path))
                {
                    results.Add(new ActionResult("There is no local script file present at the given path: " + path, false));
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

        private static ActionResult RunLocalScript(ILog log, string command, string args, DeploymentTaskConfig settings, Dictionary<string, string> credentials, int timeoutMins, bool launchNewProcess = false)
        {
            var _log = new StringBuilder();

            // https://stackoverflow.com/questions/5519328/executing-batch-file-in-c-sharp

            var scriptProcessInfo = new ProcessStartInfo(Environment.ExpandEnvironmentVariables(command))
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            if (launchNewProcess)
            {
                // launch process with user credentials set
                if (credentials != null && credentials.ContainsKey("username") && credentials.ContainsKey("password"))
                {
                    var username = credentials["username"];
                    var pwd = credentials["password"];

                    credentials.TryGetValue("domain", out var domain);

                    if (domain == null && !username.Contains(".\\") && !username.Contains("@"))
                    {
                        domain = ".";
                    }

                    scriptProcessInfo.UserName = username;
                    scriptProcessInfo.Domain = domain;

                    var sPwd = new SecureString();
                    foreach (var c in pwd)
                    {
                        sPwd.AppendChar(c);
                    }
                    sPwd.MakeReadOnly();

                    scriptProcessInfo.Password = sPwd;

                    _log.AppendLine($"Launching Process as User: {domain}\\{username}");
                }
            }

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

                    process.WaitForExit((timeoutMins * 60) * 1000);
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
                    return new ActionResult { IsSuccess = false, Message = _log.ToString() };
                }
                else if (process.ExitCode != 0)
                {
                    _log.AppendLine("Warning: Script exited with the following ExitCode: " + process.ExitCode);
                    return new ActionResult { IsSuccess = false, Message = _log.ToString() };
                }

                return new ActionResult { IsSuccess = true, Message = _log.ToString() };

            }
            catch (Exception exp)
            {
                _log.AppendLine("Error: " + exp.ToString());
                return new ActionResult { IsSuccess = false, Message = _log.ToString() };
            }
        }
    }


}
