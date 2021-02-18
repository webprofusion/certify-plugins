using SimpleImpersonation;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace Plugin.DeploymentTasks.Shared
{
    public class Helpers
    {
        /// <summary>
        /// Fetch embedded resource text file
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public static string ReadStringResource(string name)
        {
            var assembly = Assembly.GetExecutingAssembly();

            var resourcePath = assembly.GetManifestResourceNames()
                    .Single(str => str.EndsWith(name));

            using (var stream = assembly.GetManifestResourceStream(resourcePath))
            using (var reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        public static UserCredentials GetWindowsCredentials(Dictionary<string, string> credentials)
        {
            UserCredentials windowsCredentials;

            var username = credentials["username"];
            var pwd = credentials["password"];

            credentials.TryGetValue("domain", out var domain);

            if (domain == null && !username.Contains(".\\") && !username.Contains("@"))
            {
                domain = ".";
            }

            if (domain != null)
            {
                windowsCredentials = new UserCredentials(domain, username, pwd);
            }
            else
            {
                windowsCredentials = new UserCredentials(username, pwd);
            }

            return windowsCredentials;
        }
    }
}
