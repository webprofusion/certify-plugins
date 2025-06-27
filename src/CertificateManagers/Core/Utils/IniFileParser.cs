using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Utils
{
    public static class IniFileParser
    {
        /// <summary>
        /// Parses the INI file content and returns a dictionary representing the parsed data.
        /// </summary>
        /// <param name="ini">The INI file content to parse.</param>
        /// <param name="logger">The logger to log any errors encountered during parsing.</param>
        /// <returns>A dictionary representing the parsed INI file content. Default section is "_global" and accessed as result["_global"]["key"]</returns>
        public static Dictionary<string, Dictionary<string, string>> Parse(string ini, ILogger logger)
        {
            var content = new Dictionary<string, Dictionary<string, string>>();

            if (!string.IsNullOrEmpty(ini))
            {
                var section = "_global";
                var lines = ini.Split('\n');
                foreach (var l in lines)
                {
                    try
                    {
                        if (l.StartsWith("["))
                        {
                            section = l.Replace("[", "").Replace("]", "").Trim();
                        }
                        else
                        {
                            if (!string.IsNullOrEmpty(l) && l.Contains("="))
                            {
                                var kv = l.Split('=');
                                content.TryGetValue(section, out var values);
                                if (values == null) values = new Dictionary<string, string>();
                                values.Add(kv[0].Trim(), kv[1].Trim());
                                content[section] = values;
                            }
                        }
                    }
                    catch (Exception exp)
                    {
                        logger.LogError("Error parsing config: " + exp);
                    }
                }
            }

            return content;
        }
    }
}
