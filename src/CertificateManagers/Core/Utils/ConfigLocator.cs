using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Certify.Plugin.CertificateManagers.Utils
{
    /// <summary>
    /// Finds config folders that other tools keep in a user's own profile. Those tools are often run by a person
    /// rather than by the account our service runs as, so their config is not in our own profile
    /// </summary>
    public static class ConfigLocator
    {
        /// <summary>
        /// Expand a leading ~ to the home folder of the account this process runs as
        /// </summary>
        public static string ExpandHome(string path)
        {
            if (path == "~" || path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal))
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path.Length > 2 ? path[2..] : string.Empty);
            }

            return path;
        }

        /// <summary>
        /// The home folders of the users on this machine, which on Linux includes root
        /// </summary>
        public static IEnumerable<string> GetUserHomeFolders()
        {
            var roots = new List<string>();

            if (OperatingSystem.IsWindows())
            {
                var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);

                if (!string.IsNullOrEmpty(systemRoot))
                {
                    roots.Add(Path.Combine(systemRoot, "Users"));
                }
            }
            else
            {
                roots.Add("/home");
            }

            var homes = new List<string>();

            foreach (var root in roots)
            {
                try
                {
                    if (Directory.Exists(root))
                    {
                        homes.AddRange(Directory.GetDirectories(root));
                    }
                }
                catch (Exception)
                {
                    // a folder we cannot list just means its users' config cannot be found this way
                }
            }

            if (!OperatingSystem.IsWindows())
            {
                homes.Add("/root");
            }

            return homes;
        }

        /// <summary>
        /// Find a config folder at the same place below each user's home folder. Only a single match is used: with
        /// several there is no way to know which one the user wants monitored, so they are logged and the user is
        /// asked to configure the path instead
        /// </summary>
        /// <param name="relativePaths">Paths below a home folder to try, in order of preference</param>
        public static string? FindSingleInUserHomes(ILogger? logger, string toolTitle, params string[] relativePaths)
        {
            var found = new List<string>();

            foreach (var home in GetUserHomeFolders())
            {
                foreach (var relativePath in relativePaths)
                {
                    var candidate = Path.Combine(home, relativePath);

                    try
                    {
                        if (Directory.Exists(candidate))
                        {
                            found.Add(candidate);
                            break;
                        }
                    }
                    catch (Exception)
                    {
                        // an inaccessible profile is skipped
                    }
                }
            }

            if (found.Count == 1)
            {
                return found[0];
            }

            if (found.Count > 1)
            {
                logger?.LogWarning("{tool} config was found for more than one user ({paths}). Configure the path to monitor in the certificate manager settings.", toolTitle, string.Join(", ", found));
            }

            return null;
        }

        /// <summary>
        /// The first of the given folders which exists
        /// </summary>
        public static string? FirstExisting(IEnumerable<string?> candidates) =>
            candidates.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c) && Directory.Exists(c));
    }
}
