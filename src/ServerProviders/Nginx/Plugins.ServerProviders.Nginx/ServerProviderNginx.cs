using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Plugins.Server.Nginx;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Certify.Management.Servers
{
    public class ServerProviderNginx : ITargetWebServer
    {
        private ILog _log;
        private NginxManager _nginxManager;

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "Plugin.ServerProviders.Nginx",
                    Title = "NGINX",
                    Description = "Queries local nginx config for site info",
                    HelpUrl = "https://nginx.com"
                };
            }
        }

        public ServerProviderNginx()
        {

        }

        public ServerProviderNginx(string configRoot, ILog log = null)
        {
            Init(log, configRoot);
        }

        public void Init(ILog log, string configRoot)
        {
            _log = log;

            _nginxManager = new NginxManager(configRoot);
        }

        private NginxBindingDeploymentTarget _bindingDeploymentTarget = null;
        public IBindingDeploymentTarget GetDeploymentTarget()
        {
            if (_bindingDeploymentTarget == null)
            {
                _bindingDeploymentTarget = new NginxBindingDeploymentTarget(this);
            }
            return _bindingDeploymentTarget;
        }

        public void Dispose()
        {
        }

        public async Task<List<SiteInfo>> GetPrimarySites(bool ignoreStoppedSites)
        {
            return await _nginxManager.GetPrimarySites();
        }

        private string GetShellCommandOutput(string command)
        {
            // TODO: move this to a utility with common code from the Script.cs core deployment task
            var output = "";
            var errorOutput = "";

            var shell = "cmd.exe";

            // if running on *nix, identify if shell available : TODO: expand search method
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                shell = System.IO.File.Exists("/usr/bin/bash") ? "/usr/bin/bash" : "/bin/sh";
                command = $"-c {command.Replace("\"", "\\\"")}";
            }
            else
            {
                // TODO: It would be best if we could configure the location of nginx for Windows, similar to NginxManager does for the config path
                command = $"/C \"{command.Replace("\"", "\\\"").Replace("nginx", "C:\\nginx\\nginx.exe")}\""; ;
            }


            var startInfo = new ProcessStartInfo()
            {
                FileName = shell,
                Arguments = command,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var process = new Process() { StartInfo = startInfo };

            process.OutputDataReceived += (obj, a) =>
            {
                if (!String.IsNullOrWhiteSpace(a.Data))
                {
                    _log?.Information(a.Data);
                    output += a.Data;
                }
            };

            process.ErrorDataReceived += (obj, a) =>
            {
                if (!String.IsNullOrWhiteSpace(a.Data))
                {
                    _log?.Error($"Error: {a.Data}");
                    errorOutput += a.Data;
                }
            };

            try
            {
                process.Start();

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                // It is noted in the .NET API documentation that when using asynchronous output streams for Process,
                // it is best to call WaitForExit(), as specifying a timeout by using the WaitForExit(Int32) overload
                // does not ensure the output buffer has been flushed. 
                // See https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.errordatareceived?view=net-7.0#remarks
                process.WaitForExit();
            }
            catch (Exception exp)
            {
                _log?.Error("Error Running Script: " + exp.ToString());
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return output;
            }
            else
            {
                // Note: For some reason, nginx for Windows outputs the results of 'nginx -v' to the error stream rather than the output stream
                return errorOutput;
            }
        }

        public async Task<Version> GetServerVersion()
        {
            // get nginx version e.g. "nginx version: nginx/1.18.0 (Ubuntu)"
            var versionOutputString = await Task.Run<string>(() =>
            {
                return GetShellCommandOutput("nginx -v");
            });

            return GetServerVersion(versionOutputString);
        }

        public Version GetServerVersion(string versionOutputString)
        {
            var versionInfo = versionOutputString.Split("/".ToCharArray());

            if (versionInfo.Length >= 2 && Version.TryParse(versionInfo[1].Split(' ')[0], out var versionResult))
            {
                return versionResult;
            }
            else
            {
                // could not parse
                return new Version(0, 0, 0);
            }
        }

        public Task<List<BindingInfo>> GetSiteBindingList(bool ignoreStoppedSites, string siteId = null)
        {
            return _nginxManager.GetBindings();
        }

        public async Task<SiteInfo> GetSiteById(string siteId)
        {
            var sites = await _nginxManager.GetPrimarySites();
            return sites.FirstOrDefault(s => s.Id == siteId);
        }

        public Task<bool> IsAvailable()
        {
            return Task.FromResult(true);
        }

        public Task<bool> IsSiteRunning(string id)
        {
            return Task.FromResult(true);
        }

        public Task RemoveHttpsBinding(string siteId, string sni) => throw new NotImplementedException();

        public Task<List<ActionStep>> RunConfigurationDiagnostics(string siteId)
        {

            return Task.FromResult(new List<ActionStep>());
        }

        public async Task<SiteInfo> CreateSite(List<string> hostnames, string phyPath, string protocol = "http", string ipAddress = "*", int? port = 80)
        {
            return _nginxManager.CreateSiteConfig(hostnames, phyPath, protocol, ipAddress, port);
        }

        public async Task<bool> DeleteSite(string primaryHostname)
        {
            return _nginxManager.DeleteSiteConfig(primaryHostname);
        }

        public Task<bool> SiteExists(string primaryHostname)
        {
            return _nginxManager.SiteExists(primaryHostname);
        }

        internal Task<ActionStep> AddOrUpdateSiteBinding(BindingInfo targetBinding, bool addNew)
        {
            // perform add/update of ssl binding config for the target site
            return Task.FromResult(new ActionStep { Title = "No Deployment for nginx" });
        }

        public ServerTypeInfo GetServerTypeInfo()
        {
            return new ServerTypeInfo { ServerType = StandardServerTypes.Nginx, Title = "NGINX" };
        }
    }

    public class NginxBindingTargetItem : IBindingDeploymentTargetItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }

    public class NginxBindingDeploymentTarget : IBindingDeploymentTarget
    {
        private readonly ServerProviderNginx _manager;

        public NginxBindingDeploymentTarget(ServerProviderNginx manager)
        {
            _manager = manager;
        }

        public async Task<ActionStep> AddBinding(BindingInfo targetBinding) => await _manager.AddOrUpdateSiteBinding(targetBinding, true);

        public async Task<ActionStep> UpdateBinding(BindingInfo targetBinding) => await _manager.AddOrUpdateSiteBinding(targetBinding, false);

        public async Task<List<IBindingDeploymentTargetItem>> GetAllTargetItems()
        {
            var sites = await _manager.GetPrimarySites(true);

            return sites.Select(s =>
                (IBindingDeploymentTargetItem)new NginxBindingTargetItem
                {
                    Id = s.Id,
                    Name = s.Name
                }).ToList();
        }

        public async Task<List<BindingInfo>> GetBindings(string targetItemId) => await _manager.GetSiteBindingList(true, targetItemId);

        public async Task<IBindingDeploymentTargetItem> GetTargetItem(string id)
        {
            var site = await _manager.GetSiteById(id);
            if (site != null)
            {
                return new NginxBindingTargetItem { Id = site.Id, Name = site.Name };
            }
            else
            {
                return null;
            }
        }

        public string GetTargetName() => "NGINX";
    }
}
