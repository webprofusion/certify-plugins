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
        /// AWS access key, optionally used to assume an IAM role: accesskey, secretaccesskey, useassumerole, rolearn, rolesessionname, externalid
        /// </summary>
        public const string AwsAccessKey = "ExternalAuth.AWS.AccessKey";

        /// <summary>
        /// Kubernetes API server and service account token: server, token, ca_data, allow_invalid_tls
        /// </summary>
        public const string KubernetesToken = "ExternalAuth.Kubernetes.Token";

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
            },
            new ChallengeProviderDefinition
            {
                Id = AwsAccessKey,
                Title = "AWS Access Key",
                Description = "AWS IAM access key, optionally used to assume an IAM role",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="accesskey", Name="Access Key ID", IsRequired=true, IsCredential=true },
                    new ProviderParameter{ Key="secretaccesskey", Name="Secret Access Key", IsRequired=true, IsPassword=true, IsCredential=true },
                    new ProviderParameter{ Key="useassumerole", Name="Assume IAM role", IsRequired=false, IsCredential=true, Value="false", Type=OptionType.Boolean, Description="Use the access key to assume an IAM role, for example in another AWS account, and act as that role." },
                    new ProviderParameter{ Key="rolearn", Name="Role ARN", IsRequired=false, IsCredential=true, Description="Role to assume, e.g. arn:aws:iam::123456789012:role/CertifyCertificateManager. Required when Assume IAM role is enabled." },
                    new ProviderParameter{ Key="rolesessionname", Name="Session name", IsRequired=false, IsCredential=true, Value="CertifyTheWeb", Description="Optional session name for the assumed role." },
                    new ProviderParameter{ Key="externalid", Name="External ID", IsRequired=false, IsPassword=true, IsCredential=true, Description="Optional. Needed if the role's trust policy requires an external ID." }
                },
                ChallengeType = "",
                HandlerType = ChallengeHandlerType.INTERNAL
            },
            new ChallengeProviderDefinition
            {
                Id = KubernetesToken,
                Title = "Kubernetes API Token",
                Description = "Kubernetes API server address and a service account token",
                ProviderParameters = new List<ProviderParameter>
                {
                    new ProviderParameter{ Key="server", Name="API Server", IsRequired=true, IsCredential=true, Description="Address of the Kubernetes API server, as in the 'server' of a kubeconfig file, e.g. https://k8s.example.com:6443" },
                    new ProviderParameter{ Key="token", Name="Token", IsRequired=true, IsPassword=true, IsCredential=true, Description="Bearer token of the service account to use, e.g. from 'kubectl create token' or a service account token secret." },
                    new ProviderParameter{ Key="ca_data", Name="Cluster CA Certificate", IsRequired=false, IsCredential=true, Type=OptionType.MultiLineText, Description="(optional) CA certificate of the API server, as the 'certificate-authority-data' of a kubeconfig file or in PEM format. If set, only this CA is trusted. Leave blank if the API server certificate is publicly trusted." },
                    new ProviderParameter{ Key="allow_invalid_tls", Name="Allow Invalid TLS Certificate", IsRequired=false, IsCredential=true, Type=OptionType.Boolean, Value="false", Description="Don't check the API server's TLS certificate. Not recommended: set the Cluster CA Certificate instead." }
                },
                ChallengeType = "",
                HandlerType = ChallengeHandlerType.INTERNAL
            }
        };
    }
}
