using System.Collections.Generic;
using Certify.Models;
using Certify.Models.Config;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// Index of the stored credential types defined by the core deployment tasks. The plugin lists them alongside the standard credential types.
    /// </summary>
    public static class CredentialTypes
    {
        /// <summary>
        /// Kemp LoadMaster API sign in: api_key, or username and password
        /// </summary>
        public const string KempLoadMaster = "ExternalAuth.Kemp.LoadMaster";

        /// <summary>
        /// All credential types in the index. New definitions each call, so callers cannot change the originals
        /// </summary>
        public static List<ChallengeProviderDefinition> GetAll() => new List<ChallengeProviderDefinition>
        {
            new ChallengeProviderDefinition
            {
                Id = KempLoadMaster,
                Title = "Kemp LoadMaster API",
                Description = "LoadMaster API key, or username and password",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="api_key", Name="API Key", IsRequired=false, IsPassword=true, IsCredential=true, Description="API key of the LoadMaster user. Leave blank to sign in with a username and password instead." },
                    new ProviderParameter{ Key="username", Name="Username", IsRequired=false, IsCredential=true, Description="Not needed when using an API key" },
                    new ProviderParameter{ Key="password", Name="Password", IsRequired=false, IsPassword=true, IsCredential=true, Description="Not needed when using an API key" }
                },
                ChallengeType = "",
                HandlerType = ChallengeHandlerType.INTERNAL
            }
        };
    }
}
