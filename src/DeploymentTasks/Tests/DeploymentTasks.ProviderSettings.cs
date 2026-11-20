using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Certify.Config;
using Certify.Models;
using Certify.Models.Config;
using Certify.Providers.DeploymentTasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Certify.Tests.DeploymentTaskTests
{
    /// <summary>
    /// Task settings handling which needs no external system: argument parsing, validation and definitions
    /// </summary>
    [TestClass]
    public class DeploymentTaskProviderSettings
    {
        private static DeploymentTaskExecutionParams GetExecParams(IDeploymentTaskProvider provider, bool isPreviewOnly, params (string key, string value)[] parameters)
        {
            var config = new DeploymentTaskConfig
            {
                ChallengeProvider = StandardAuthTypes.STANDARD_AUTH_LOCAL,
                Parameters = parameters.Select(p => new ProviderParameterSetting(p.key, p.value)).ToList()
            };

            return new DeploymentTaskExecutionParams(null, null, new ManagedCertificate(), config, null, isPreviewOnly, provider.GetDefinition(null), new DeploymentContext(), CancellationToken.None);
        }

        [TestMethod, TestCategory("Misc")]
        public void TestPowershellArgumentParsing()
        {
            var args = PowershellScript.ParseArguments(@"path=c:\temp\folder\\;other=test;token=abc=123;escaped=a\;b\=c;flag");

            CollectionAssert.AreEqual(new[] { "path", "other", "token", "escaped", "flag" }, args.Select(a => a.Key).ToArray());
            Assert.AreEqual(@"c:\temp\folder\", args[0].Value);
            Assert.AreEqual("test", args[1].Value);
            Assert.AreEqual("abc=123", args[2].Value);
            Assert.AreEqual("a;b=c", args[3].Value);
            Assert.AreEqual("", args[4].Value);

            Assert.AreEqual(0, PowershellScript.ParseArguments(null).Count);
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestUpdatePortBindingValidation()
        {
            var provider = new UpdatePortBinding();

            Assert.AreEqual(0, (await provider.Validate(GetExecParams(provider, false, ("ip", "0.0.0.0"), ("port", "443")))).Count);
            Assert.AreEqual(0, (await provider.Validate(GetExecParams(provider, false, ("ip", "::"), ("port", "8443"), ("appid", "c0a1e5ce-c001-c0de-ba5e-000000000042")))).Count);

            Assert.AreEqual(1, (await provider.Validate(GetExecParams(provider, false, ("ip", "0.0.0.0; Remove-Item c:\\"), ("port", "443")))).Count);
            Assert.AreEqual(1, (await provider.Validate(GetExecParams(provider, false, ("ip", "0.0.0.0"), ("port", "443 & calc")))).Count);
            Assert.AreEqual(1, (await provider.Validate(GetExecParams(provider, false, ("ip", "0.0.0.0"), ("port", "70000")))).Count);
            Assert.AreEqual(1, (await provider.Validate(GetExecParams(provider, false, ("ip", "0.0.0.0"), ("port", "443"), ("appid", "{c0a1e5ce-c001-c0de-ba5e-000000000042}")))).Count);

            Assert.AreEqual("0.0.0.0:443", UpdatePortBinding.GetIpPort(IPAddress.Parse("0.0.0.0"), 443));
            Assert.AreEqual("[::]:443", UpdatePortBinding.GetIpPort(IPAddress.Parse("::"), 443));

            Assert.IsFalse(UpdatePortBinding.Definition.ProviderParameters.First(p => p.Key == "appid").IsRequired);
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestDopplerValidation()
        {
            var provider = new Doppler();
            var definition = Doppler.Definition.ProviderParameters;

            Assert.IsTrue(definition.First(p => p.Key == "config").IsRequired);
            Assert.IsFalse(definition.First(p => p.Key == "secretname_fullchain").IsRequired);
            Assert.IsFalse(definition.First(p => p.Key == "secretname_pfx").IsRequired);

            Assert.AreEqual(0, (await provider.Validate(GetExecParams(provider, false, ("project", "p"), ("config", "dev"), ("secretname_cert", "CERT"), ("secretname_key", "KEY")))).Count);
            Assert.AreEqual(1, (await provider.Validate(GetExecParams(provider, false, ("project", "p"), ("secretname_cert", "CERT"), ("secretname_key", "KEY")))).Count);
            Assert.AreEqual(1, (await provider.Validate(GetExecParams(provider, false, ("project", "p"), ("config", "dev"), ("secretname_cert", "CERT")))).Count);
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestHashicorpVaultValidation()
        {
            var provider = new HashicorpVault();

            Assert.AreEqual(0, (await provider.Validate(GetExecParams(provider, false, ("vault_uri", "https://vault.example.com:8200"), ("vault_secret_path", "/v1/secret/data/example"), ("vault_namespace", "admin")))).Count);
            Assert.AreEqual(2, (await provider.Validate(GetExecParams(provider, false, ("vault_uri", "vault.example.com")))).Count);
        }

        [TestMethod, TestCategory("Misc")]
        public async Task TestServiceManagerPreviewAndContexts()
        {
            var provider = new ServiceManager();

            var preview = await provider.Validate(GetExecParams(provider, true, ("servicename", "W3SVC"), ("action", "restart"), ("maxwait", "20")));
            Assert.AreEqual(1, preview.Count);
            Assert.IsTrue(preview[0].IsSuccess);
            StringAssert.Contains(preview[0].Message, "would be restarted");

            Assert.AreEqual(0, (await provider.Validate(GetExecParams(provider, false, ("servicename", "W3SVC"), ("action", "restart"), ("maxwait", "20")))).Count);

            Assert.AreEqual(DeploymentContextType.LocalAsService, ServiceManager.Definition.SupportedContexts);
        }

        [TestMethod, TestCategory("Misc")]
        public void TestScriptContexts()
        {
            Assert.IsFalse(Script.Definition.SupportedContexts.HasFlag(DeploymentContextType.WindowsNetwork));
            Assert.IsTrue(Script.Definition.SupportedContexts.HasFlag(DeploymentContextType.SSH));
        }
    }
}
