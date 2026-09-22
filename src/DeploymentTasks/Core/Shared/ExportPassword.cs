using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;

namespace Certify.Providers.Deployment.Core.Shared
{
    /// <summary>
    /// Optional new password for tasks which export the certificate private key, sourced from a stored password credential
    /// </summary>
    public static class ExportPassword
    {
        public const string ParameterKey = "export_pwd_credential";

        /// <summary>
        /// Task parameter to select the optional new password, optionally only applying for given values of another parameter (see ProviderParameter.DependsOnKey)
        /// </summary>
        public static ProviderParameter GetParameter(string dependsOnKey = null, string[] dependsOnValues = null) => new ProviderParameter
        {
            Key = ParameterKey,
            Name = "Optional New Password",
            IsRequired = false,
            IsCredential = false,
            Type = OptionType.StoredCredential,
            ExtendedConfig = StandardAuthTypes.STANDARD_AUTH_PASSWORD,
            DependsOnKey = dependsOnKey,
            DependsOnValues = dependsOnValues,
            Description = "Optional new password credential to apply to protect the exported private key"
        };

        /// <summary>
        /// Get the new password selected for the task. Result is null if the task does not set one
        /// </summary>
        public static async Task<ActionResult<string>> GetNewPassword(DeploymentTaskExecutionParams execParams)
        {
            var credentialId = execParams.Settings?.Parameters?.FirstOrDefault(c => c.Key == ParameterKey)?.Value?.Trim();

            if (string.IsNullOrWhiteSpace(credentialId))
            {
                return new ActionResult<string> { IsSuccess = true };
            }

            var cred = await execParams.CredentialsManager.GetUnlockedCredentialsDictionary(credentialId);
            if (cred != null && cred.TryGetValue("password", out var pwd) && !string.IsNullOrEmpty(pwd))
            {
                return new ActionResult<string> { IsSuccess = true, Result = pwd };
            }

            return new ActionResult<string>($"Export - the new password credential could not be unlocked or was not accessible {credentialId}.", false);
        }

        /// <summary>
        /// Get the password of the managed certificate's own PFX. Result is blank if the certificate has no password credential
        /// </summary>
        public static async Task<ActionResult<string>> GetCertificatePassword(DeploymentTaskExecutionParams execParams, ManagedCertificate managedCert)
        {
            if (string.IsNullOrWhiteSpace(managedCert.CertificatePasswordCredentialId))
            {
                return new ActionResult<string> { IsSuccess = true, Result = "" };
            }

            var cred = await execParams.CredentialsManager.GetUnlockedCredentialsDictionary(managedCert.CertificatePasswordCredentialId);
            if (cred != null)
            {
                return new ActionResult<string> { IsSuccess = true, Result = cred["password"] };
            }

            return new ActionResult<string>($"Export - the credentials for this task could not be unlocked or were not accessible {managedCert.CertificatePasswordCredentialId}.", false);
        }
    }
}
