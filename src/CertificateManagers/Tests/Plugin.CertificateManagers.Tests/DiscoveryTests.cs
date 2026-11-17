using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Plugin.CertificateManagers.Providers.AcmeSh;
using Certify.Plugin.CertificateManagers.Providers.Certbot;
using Certify.Plugin.CertificateManagers.Providers.PoshAcme;
using Certify.Plugin.CertificateManagers.Providers.SimpleAcme;
using Certify.Plugin.CertificateManagers.Providers.WinAcme;
using Certify.Plugin.CertificateManagers.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Plugin.CertificateManagers
{
    /// <summary>
    /// What monitoring reports about each item: its domains, orders, certificate authority and renewal state
    /// </summary>
    [TestClass]
    public class DiscoveryTests
    {
        private static string AssetPath(params string[] parts) =>
            Path.Combine(new[] { Directory.GetCurrentDirectory(), "Assets" }.Concat(parts).ToArray());

        private static string[] DomainsOf(ManagedCertificate item) =>
            item.DomainOptions.Select(d => d.Domain!).ToArray();

        private static async Task<List<ManagedCertificate>> GetItems(Certify.Providers.CertificateManagers.ICertificateManager manager, string configPath)
        {
            manager.Init(NullLogger.Instance, new CertificateManagerPreference { ConfigPath = configPath, LogPath = configPath });
            return await manager.GetManagedCertificates();
        }

        private static string CreateTempFolder()
        {
            var path = Path.Combine(Path.GetTempPath(), $"certmanager-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(path);
            return path;
        }

        [TestMethod]
        [DataRow("acme-v02.api.letsencrypt.org", "letsencrypt.org", false, DisplayName = "win-acme server folder")]
        [DataRow("acme-staging-v02.api.letsencrypt.org", "letsencrypt.org", true, DisplayName = "win-acme staging server folder")]
        [DataRow("https://acme-v02.api.letsencrypt.org/", "letsencrypt.org", false, DisplayName = "Base URL")]
        [DataRow("https://acme-staging-v02.api.letsencrypt.org/directory", "letsencrypt.org", true, DisplayName = "Directory URL")]
        [DataRow("https://acme.zerossl.com/v2/DV90", "zerossl.com", false, DisplayName = "Directory URL with a path")]
        [DataRow("acme.zerossl.comv2DV90", "zerossl.com", false, DisplayName = "Folder name with the path separators removed")]
        [DataRow("https://acme.sectigo.com/v2/OV", "sectigo-OV", false, DisplayName = "One of several CAs on a host")]
        public void CertificateAuthorityIsFoundFromEndpoint(string endpoint, string expectedId, bool expectedStaging)
        {
            var ca = CertificateAuthorityLookup.FromEndpoint(endpoint);

            Assert.IsNotNull(ca);
            Assert.AreEqual(expectedId, ca.Value.CertificateAuthorityId);
            Assert.AreEqual(expectedStaging, ca.Value.IsStaging);
        }

        [TestMethod]
        [DataRow("acme.sectigo.com", DisplayName = "Host shared by several CAs")]
        [DataRow("https://acme.example.com/directory", DisplayName = "Unknown CA")]
        [DataRow("", DisplayName = "Blank")]
        public void CertificateAuthorityIsNotGuessed(string endpoint)
        {
            Assert.IsNull(CertificateAuthorityLookup.FromEndpoint(endpoint));
        }

        [TestMethod]
        public void HomeFolderIsExpanded()
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            Assert.AreEqual(Path.Combine(home, ".acme.sh"), ConfigLocator.ExpandHome("~/.acme.sh"));
            Assert.AreEqual("/etc/acme.sh", ConfigLocator.ExpandHome("/etc/acme.sh"));
        }

        [TestMethod]
        public async Task WinAcmeIisTargetTakesDomainsFromCachedRequest()
        {
            var items = await GetItems(new WinAcme(), AssetPath("win-acme"));
            var item = items.Single();

            Assert.AreEqual("ext-win-acme-ryaYpYnybEqLtmhGawIRMQ", item.Id, "An unsplit renewal keeps its existing id");
            CollectionAssert.AreEqual(new[] { "test.projectbids.co.uk", "www.test.projectbids.co.uk" }, DomainsOf(item),
                "An IIS target records only its common name, so the other domains come from the cached certificate request");
            Assert.AreEqual("letsencrypt.org", item.CertificateAuthorityId);
            Assert.IsFalse(item.UseStagingMode);
            Assert.AreEqual(RequestState.Error, item.LastRenewalStatus);
            Assert.AreEqual("First error message.\nSecond error message.", item.RenewalFailureMessage);
            Assert.AreEqual(1, item.RenewalFailureCount);
            Assert.AreEqual("67619FFF90E36CA4BC3C48B28FD79EA34F5E34F9", item.CertificateThumbprintHash, "The certificate is the one from the last successful run");
        }

        [TestMethod]
        public async Task SimpleAcmeManualTargetUsesItsOwnDomains()
        {
            var item = (await GetItems(new SimpleAcme(), AssetPath("simple-acme"))).Single();

            Assert.AreEqual("ext-simple-acme-fpSPud2_AEKj0U5hjTWrXQ", item.Id);
            CollectionAssert.AreEqual(new[] { "simple-01.projectbids.co.uk" }, DomainsOf(item));
            Assert.AreEqual("letsencrypt.org", item.CertificateAuthorityId);
            Assert.AreEqual(RequestState.Success, item.LastRenewalStatus);
        }

        private static void WriteCsr(string path, params string[] domains)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={domains[0]}", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();

            foreach (var domain in domains)
            {
                san.AddDnsName(domain);
            }

            request.CertificateExtensions.Add(san.Build());
            File.WriteAllText(path, request.CreateSigningRequestPem());
        }

        [TestMethod]
        public async Task WinAcmeSplitRenewalIsReportedPerOrder()
        {
            var root = CreateTempFolder();

            try
            {
                var serverFolder = Path.Combine(root, "acme-staging-v02.api.letsencrypt.org");
                Directory.CreateDirectory(Path.Combine(serverFolder, "Certificates"));

                // the Host order plugin gives one order per host. c.example.com was dropped by the second run, and
                // the third run failed before splitting the renewal, so it has only a main result
                File.WriteAllText(Path.Combine(serverFolder, "split.renewal.json"), """
                {
                  "Id": "split",
                  "LastFriendlyName": "[IIS] example site",
                  "TargetPluginOptions": { "CommonName": "a.example.com", "IncludeSiteIds": [ 3 ], "Plugin": "54deb3ee-b5df-4381-8485-fe386054055b" },
                  "OrderPluginOptions": { "Plugin": "874a86e4-29c7-4294-9ab6-6908866847a0" },
                  "History": [
                    { "Date": "2025-06-01T00:00:00Z", "Success": true, "OrderResults": [
                      { "Name": "a.example.com", "Success": true, "ExpireDate": "2025-08-30T00:00:00Z", "Thumbprint": "AAAA" },
                      { "Name": "b.example.com", "Success": true, "ExpireDate": "2025-08-30T00:00:00Z", "Thumbprint": "BBBB" },
                      { "Name": "c.example.com", "Success": true, "ExpireDate": "2025-08-30T00:00:00Z", "Thumbprint": "CCCC" } ] },
                    { "Date": "2025-07-01T00:00:00Z", "Success": true, "OrderResults": [
                      { "Name": "a.example.com", "Success": true, "ExpireDate": "2025-09-29T00:00:00Z", "Thumbprint": "AAA2" },
                      { "Name": "b.example.com", "Success": true, "ExpireDate": "2025-09-29T00:00:00Z", "Thumbprint": "BBB2" },
                      { "Name": "c.example.com", "Missing": true } ] },
                    { "Date": "2025-08-01T00:00:00Z", "Success": false, "OrderResults": [
                      { "Success": false, "ErrorMessages": [ "Site 3 not found" ] } ] }
                  ]
                }
                """);

                WriteCsr(Path.Combine(serverFolder, "Certificates", "split-a.example.com-0123abcd-csr.pem"), "a.example.com", "www.a.example.com");

                var items = (await GetItems(new WinAcme(), root)).OrderBy(i => i.Name).ToList();

                CollectionAssert.AreEqual(new[] { "[IIS] example site [a.example.com]", "[IIS] example site [b.example.com]" }, items.Select(i => i.Name).ToArray(),
                    "Each current order is its own item, and the dropped order and the failed run's main result are not");
                Assert.AreEqual(2, items.Select(i => i.Id).Distinct().Count(), "Each order has its own id");
                Assert.IsTrue(items.All(i => i.Id!.StartsWith("ext-win-acme-split-")));

                CollectionAssert.AreEqual(new[] { "a.example.com", "www.a.example.com" }, DomainsOf(items[0]), "The order's own cached request gives its domains");
                Assert.AreEqual(0, items[1].DomainOptions.Count, "With no request cached, the renewal's common name is not assumed for another order");

                foreach (var item in items)
                {
                    Assert.AreEqual(RequestState.Error, item.LastRenewalStatus, "A run failing before the split applies to every order");
                    Assert.AreEqual("Site 3 not found", item.RenewalFailureMessage);
                    Assert.AreEqual(new DateTimeOffset(2025, 9, 29, 0, 0, 0, TimeSpan.Zero), item.DateExpiry);
                    Assert.AreEqual("letsencrypt.org", item.CertificateAuthorityId);
                    Assert.IsTrue(item.UseStagingMode);
                }

                Assert.AreEqual("AAA2", items[0].CertificateThumbprintHash);
                Assert.AreEqual("BBB2", items[1].CertificateThumbprintHash);
            }
            finally
            {
                Directory.Delete(root, true);
            }
        }

        [TestMethod]
        public async Task WinAcmeLegacyHistoryIsRead()
        {
            var root = CreateTempFolder();

            try
            {
                var serverFolder = Path.Combine(root, "acme-v02.api.letsencrypt.org");
                Directory.CreateDirectory(serverFolder);

                // win-acme 2.1 and earlier recorded thumbprints and expiry on the run rather than per order
                File.WriteAllText(Path.Combine(serverFolder, "legacy.renewal.json"), """
                {
                  "Id": "legacy",
                  "LastFriendlyName": "[Manual] old.example.com",
                  "TargetPluginOptions": { "CommonName": "old.example.com", "AlternativeNames": [ "old.example.com" ], "Plugin": "e239db3b-b42f-48aa-b64f-46d4f3e9941b" },
                  "History": [ { "Date": "2021-01-01T00:00:00Z", "Success": true, "ExpireDate": "2021-03-31T00:00:00Z", "Thumbprints": [ "OLD1" ] } ]
                }
                """);

                var item = (await GetItems(new WinAcme(), root)).Single();

                Assert.AreEqual("ext-win-acme-legacy", item.Id);
                Assert.AreEqual("OLD1", item.CertificateThumbprintHash);
                Assert.AreEqual(new DateTimeOffset(2021, 3, 31, 0, 0, 0, TimeSpan.Zero), item.DateExpiry);
                Assert.AreEqual(RequestState.Success, item.LastRenewalStatus);
            }
            finally
            {
                Directory.Delete(root, true);
            }
        }

        [TestMethod]
        public async Task CertbotReportsAutoRenewTurnedOff()
        {
            var root = CreateTempFolder();

            try
            {
                var source = AssetPath("certbot", "test-config");

                foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
                {
                    var destination = Path.Combine(root, Path.GetRelativePath(source, file));
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    File.Copy(file, destination);
                }

                var renewalFile = Path.Combine(root, "renewal", "wsl2.projectbids.co.uk.conf");
                File.WriteAllText(renewalFile, File.ReadAllText(renewalFile).Replace("[renewalparams]", "[renewalparams]\nautorenew = False"));

                var manager = new Certbot();
                manager.Init(NullLogger.Instance, new CertificateManagerPreference { ConfigPath = root, LogPath = Path.Combine(root, "no-logs") });
                var items = await manager.GetManagedCertificates();

                var disabled = items.Single(i => i.Name == "wsl2.projectbids.co.uk");
                Assert.IsFalse(disabled.IncludeInAutoRenew);
                Assert.IsTrue(disabled.Comments?.Contains("autorenew = False") == true, "The reason renewal will not happen is shown against the item");

                Assert.IsTrue(items.Where(i => i != disabled).All(i => i.IncludeInAutoRenew), "Other lineages renew as normal");

                Assert.IsTrue(items.All(i => i.CertificateAuthorityId == "letsencrypt.org" && i.UseStagingMode), "The test lineages use the Let's Encrypt staging server");
                Assert.IsFalse(items.SelectMany(i => i.DomainOptions).Any(d => d.Domain!.StartsWith("CN=")), "Domains do not carry the subject attribute name");
            }
            finally
            {
                Directory.Delete(root, true);
            }
        }

        [TestMethod]
        public async Task AcmeShReportsCertificateAuthority()
        {
            var items = await GetItems(new AcmeSh(), AssetPath("acme.sh"));

            Assert.AreEqual("zerossl.com", items.Single(i => i.Name == "test.projectbids.co.uk").CertificateAuthorityId);
            Assert.AreEqual("letsencrypt.org", items.Single(i => i.Name == "wsl5.projectbids.co.uk").CertificateAuthorityId);
        }

        [TestMethod]
        public async Task PoshAcmeReportsCertificateAuthorityAndDomains()
        {
            var items = await GetItems(new PoshAcme(), AssetPath("posh-acme"));
            var item = items.Single(i => i.CertificatePath?.EndsWith("cert.cer") == true);

            Assert.AreEqual("letsencrypt.org", item.CertificateAuthorityId, "The server folder's dir.json gives the CA, as the folder is named LE_PROD");
            Assert.IsFalse(item.UseStagingMode);
            Assert.AreEqual("posh-acme.projectbids.co.uk", item.RequestConfig.PrimaryDomain, "The primary domain is the certificate's common name, not its subject");
        }
    }
}
