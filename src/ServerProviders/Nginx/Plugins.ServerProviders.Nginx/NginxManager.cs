using Certify.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Certify.Plugins.Server.Nginx
{
    public class ConfigBlock
    {
        public string FilePath { get; set; }
        public int StartLine { get; set; }
        public int EndLine { get; set; }
        public string BlockKey { get; set; }
        public List<KeyValuePair<string, string>> Properties { get; set; } = new List<KeyValuePair<string, string>>();
        public Dictionary<String, ConfigBlock> ChildBlocks { get; set; } = new Dictionary<string, ConfigBlock>();
    }

    public class NginxManager
    {
        private string _configPath { get; set; }
        private string _siteConfigSubfolder { get; set; } = "sites-available";
        private string _primaryConfigFile { get; set; } = "nginx.conf";
        private readonly bool _isWindows;
        public NginxManager(string configPath)
        {
            _configPath = configPath;
            _isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            AutodiscoverConfig();
        }

        /// <summary>
        /// Attempt to auto discover the nginx config path, if not already set
        /// </summary>
        public void AutodiscoverConfig()
        {
            if (string.IsNullOrEmpty(_configPath))
            {
                if (_isWindows)
                {
                    if (Directory.Exists("C:\\nginx\\conf"))
                    {
                        _configPath = "C:\\nginx\\conf";
                    }
                }
                else
                {
                    if (Directory.Exists("/etc/nginx"))
                    {
                        _configPath = "/etc/nginx";
                    }
                }
            }
        }

        /// <summary>
        /// Perform non-validating recursive config parsing for the given text stream.
        /// </summary>
        /// <param name="sr"></param>
        /// <returns></returns>
        public async Task<ConfigBlock> ParseBlock(StreamReader sr, int lineIndex)
        {
            var block = new ConfigBlock { StartLine = lineIndex };

            string l;

            while ((l = await sr.ReadLineAsync()) != null)
            {
                lineIndex++;

                //tokenize all lines to build config block

                var line = l.ToString();

                // discard comments from line e.g. http { # this is the http block
                if (line.IndexOf("#") > -1) line = line.Remove(line.IndexOf("#"));

                line = line.Trim(" \t\r".ToCharArray());

                // if opening bracket, parse and add new child block
                if (line.EndsWith("{"))
                {
                    var childBlock = await ParseBlock(sr, lineIndex);
                    if (childBlock != null)
                    {
                        var blockKey = line.Replace("{", "").Trim(" \t\r".ToCharArray());

                        childBlock.BlockKey = blockKey;

                        block.ChildBlocks.Add(blockKey, childBlock);
                    }
                }
                else if (line.EndsWith("}"))
                {
                    // reached end of block
                    break;
                }
                else if (!string.IsNullOrWhiteSpace(line))
                {
                    // property and optional values e.g. server_name example.com www.example.com;
                    // properties with same key can appear multiple times in same block

                    var lineitems = line.Split(' ')
                        .Select(s => s.Replace(";", ""))
                        .ToArray();

                    if (lineitems.Length > 0)
                    {
                        var key = lineitems[0];
                        var values = "";

                        if (lineitems.Length > 1)
                        {
                            values = string.Join(" ", lineitems.Skip(1).ToArray());
                        }

                        block.Properties.Add(new KeyValuePair<string, string>(key, values));

                        // if line item is an include, attempt to follow and parse
                        if (key == "include")
                        {
                            var includePath = values;
                            var pattern = "*";

                            if (includePath.EndsWith("*.conf"))
                            {
                                pattern = " *.conf";
                                includePath = includePath.Replace("*.conf", "");
                            }

                            if (includePath.EndsWith("*"))
                            {
                                pattern = "*";
                                includePath = includePath.Replace("*", "");
                            }

                            if (!Path.IsPathRooted(includePath))
                            {
                                includePath = Path.Combine(_configPath, includePath);
                            }

                            try
                            {

                                var files = Directory.GetFiles(includePath, pattern);
                                if (files.Any())
                                {
                                    foreach (var file in files)
                                    {
                                        // note: malicious user could encouraged app to follow a path nginx is not normally allowed to read here, could check that path is a subfolder of our main config?
                                        var includeBlock = await ParseConfig(file, "include");

                                        block.ChildBlocks.Add(file, includeBlock);

                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                //log failure to read include
                                System.Diagnostics.Debug.WriteLine(ex);
                            }
                        }
                    }

                }
            }

            block.EndLine = lineIndex;

            return block;
        }


        /// <summary>
        /// Perform non-validating parsing for a given nginx .conf file
        /// </summary>
        /// <param name="configPath"></param>
        /// <returns></returns>
        public async Task<ConfigBlock> ParseConfig(string configPath, string blockKey = "main")
        {
            using (var sr = File.OpenText(configPath))
            {
                var lineIndex = 0;
                var block = await ParseBlock(sr, lineIndex);

                block.BlockKey = blockKey;
                block.FilePath = configPath;
                return block;
            }
        }

        private List<ConfigBlock> FindServerBlocks(ConfigBlock config)
        {
            var serverBlocks = new List<ConfigBlock>();
            foreach (var block in config.ChildBlocks)
            {
                if (block.Key == "server")
                {
                    serverBlocks.Add(block.Value);

                }
                var childServerBlocks = FindServerBlocks(block.Value);
                if (childServerBlocks.Any())
                {
                    serverBlocks.AddRange(childServerBlocks);
                }
            }
            return serverBlocks;
        }

        public async Task<List<BindingInfo>> GetBindings()
        {
            // enumerate, read and parse config
            var bindings = new List<BindingInfo>();

            if (string.IsNullOrEmpty(_configPath))
            {
                return bindings;
            }

            // find config files, read nginx main config, then included config files
            var primaryConfigPath = _isWindows ? Path.Combine(_configPath, _primaryConfigFile) : Path.Combine(_configPath, _primaryConfigFile).Replace("\\", "/");
            if (File.Exists(primaryConfigPath))
            {

                var config = await ParseConfig(primaryConfigPath);

                System.Diagnostics.Debug.WriteLine(JsonConvert.SerializeObject(config, Formatting.Indented));

                var serverBlocks = FindServerBlocks(config);

                // get all server blocks, then extract binding info
                foreach (var locationBlock in serverBlocks)
                {
                    var props = locationBlock.Properties;

                    var rootPath = props.FirstOrDefault(p => p.Key == "root").Value;

                    var server_name = locationBlock.Properties.FirstOrDefault(p => p.Key == "server_name");

                    bool isHttps = props.Any(p => p.Key == "ssl_certificate") && props.Any(p => p.Key == "ssl_certificate_key");

                    // attempt to parse IP listening ip:ports
                    var ipV4Listen = props.FirstOrDefault(p => p.Key == "listen" && !p.Value.Trim().StartsWith("["));
                    var ipV6Listen = props.FirstOrDefault(p => p.Key == "listen" && p.Value.Trim().StartsWith("["));

                    var ipV4Port = ipV4Listen.Value != null ? ipV4Listen.Value.Trim().Split(' ').FirstOrDefault().Split(':').FirstOrDefault() : null; // TODO: check if this should default to 80
                    var ipV6Port = ipV6Listen.Value != null ? ipV6Listen.Value.Trim().Split(' ').FirstOrDefault()?.LastIndexOf("]:") : null;

                    var cert_store = props.Find(p => p.Key == "ssl_certificate").Value;

                    if (server_name.Value != null)
                    {
                        var siteId = GetSiteIdFromServerNames(server_name.Value);
                        var servernames = GetServerNames(server_name.Value);

                        foreach (var identifier in servernames)
                        {
                            bindings.Add(new BindingInfo
                            {
                                Host = identifier,
                                IsEnabled = true,
                                PhysicalPath = rootPath,
                                IsHTTPS = isHttps,
                                IsSNIEnabled = true,
                                ServerType = StandardServerTypes.Nginx.ToString().ToLower(),
                                CertificateStore = cert_store,
                                HasCertificate = !string.IsNullOrEmpty(cert_store),
                                SiteId = siteId,
                                SiteName = siteId,
                                Protocol = isHttps ? "https" : "http"
                            });
                        }
                    }

                }
            }
            return bindings;
        }

        private IEnumerable<string> GetServerNames(string servernames)
        {
            // TODO: filter special values like _ and regex

            var names = servernames.Split(' ').Where(d => !string.IsNullOrWhiteSpace(d));
            return names;
        }

        private string GetSiteIdFromServerNames(string servernames)
        {
            var siteId = "(default)";

            if (!string.IsNullOrEmpty(servernames))
            {
                var names = GetServerNames(servernames);

                if (names.Any())
                {
                    siteId = names.First().ToLower().Trim();
                }
            }

            return siteId;
        }

        public async Task<List<SiteInfo>> GetPrimarySites()
        {
            // enumerate, read and parse config
            var siteInfoList = new List<SiteInfo>();

            if (string.IsNullOrEmpty(_configPath))
            {
                return new List<SiteInfo>();
            }

            // find config files, read nginx main config, then included config files
            var primaryConfigPath = _isWindows ? Path.Combine(_configPath, _primaryConfigFile) : Path.Combine(_configPath, _primaryConfigFile).Replace("\\", "/");
            if (File.Exists(primaryConfigPath))
            {

                var config = await ParseConfig(primaryConfigPath);

                System.Diagnostics.Debug.WriteLine(JsonConvert.SerializeObject(config, Formatting.Indented));

                var serverBlocks = FindServerBlocks(config);

                // get all server blocks, then extract binding info
                foreach (var locationBlock in serverBlocks)
                {
                    var props = locationBlock.Properties;

                    var rootPath = props.FirstOrDefault(p => p.Key == "root").Value;

                    var server_name = locationBlock.Properties.FirstOrDefault(p => p.Key == "server_name");

                    bool isHttps = props.Any(p => p.Key == "ssl_certificate") && props.Any(p => p.Key == "ssl_certificate_key");

                    var siteInfo = new SiteInfo
                    {
                        ServerType = StandardServerTypes.Nginx,
                        HasCertificate = isHttps,
                        Path = rootPath,
                        Id = GetSiteIdFromServerNames(server_name.Value)
                    };

                    siteInfo.Name = siteInfo.Id;

                    siteInfoList.Add(siteInfo);
                }
            }
            return siteInfoList;
        }

        public SiteInfo CreateSiteConfig(List<string> hostnames, string phyPath, string protocol = "http", string ipAddress = "*", int? port = 80)
        {
            if (string.IsNullOrEmpty(_configPath))
            {
                return null;
            }

            var config = @"
                 server {
                    listen [PORT];
                    listen[::]:[PORT];

                    server_name [DOMAINS];

                    root [PATH];
                    index index.html;

                    location / {
                        try_files $uri $uri / = 404;
                    }
                }
            ";

            config = config.Replace("[DOMAINS]", string.Join(" ", hostnames));
            config = _isWindows ? config.Replace("[PATH]", phyPath) : config.Replace("[PATH]", phyPath.Replace("\\", "/"));
            config = config.Replace("[PORT]", port.ToString());

            var outputPath = System.IO.Path.Combine(_configPath, _siteConfigSubfolder, hostnames[0]);
            System.IO.File.WriteAllText(outputPath, config);

            var siteInfo = new SiteInfo { Id = hostnames[0], Name = hostnames[0], Path = phyPath, ServerType = StandardServerTypes.Nginx, IsEnabled = true, HasCertificate = false };

            return siteInfo;
        }


        internal bool DeleteSiteConfig(string primaryHostname)
        {
            if (string.IsNullOrEmpty(_configPath))
            {
                return false;
            }

            var configPath = System.IO.Path.Combine(_configPath, _siteConfigSubfolder, primaryHostname);
            if (System.IO.File.Exists(configPath))
            {
                try
                {
                    System.IO.File.Delete(configPath);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            else
            {
                return true;
            }
        }

        public void AddOrUpdateHttpsBinding(string path, string startIndex, List<BindingInfo> bindings)
        {
            // identify server block, find if we are already managing it, identify existing http or https bindings, prepare and write new config

            // insert /update ssl cert config

            // "ssl_certificate     sslcert/website.com/www.crt;";
            //"ssl_certificate_key sslcert/website.com/www.key; ";

        }

        public async Task<bool> RemoveHttpsBinding(string path, string startIndex, List<BindingInfo> bindings)
        {
            return false;
        }

        public async Task<bool> CheckPermissions()
        {
            // check main config can be written to.
            return false;
        }

        public async Task<bool> PerformConfigReload()
        {
            return false;
        }

        internal async Task<bool> SiteExists(string primaryHostname)
        {
            if (string.IsNullOrEmpty(_configPath))
            {
                return false;
            }

            var configPath = System.IO.Path.Combine(_configPath, _siteConfigSubfolder, primaryHostname);
            if (System.IO.File.Exists(configPath))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
