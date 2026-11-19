using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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
    /// Runs the AWS Certificate Manager task against a local stand-in for the ACM API (JSON 1.1 protocol), reached through the task's ACM Endpoint
    /// setting. The AWS SDK signs each request as it would for AWS; the stand-in only checks the access key ID and region in the signature.
    /// </summary>
    [TestClass]
    public class DeploymentTasksAwsCertificateManager : IntegrationTestBase
    {
        private const string Region = "eu-west-1";
        private const string AccessKey = "AKIDCERTIFYTEST";

        private FakeAcm _acm;
        private string _pfxPath;
        private ManagedCertificate _managedCert;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _acm = new FakeAcm();
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
            _managedCert = GetMockManagedCertificate("AcmTest", "1", "www.example.com", PrimaryIISRoot);
            _managedCert.CertificatePath = _pfxPath;
        }

        [TestCleanup]
        public void Cleanup()
        {
            _acm?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task FirstDeploymentImportsTaggedCertificate()
        {
            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            var imported = _acm.Certificates.Values.Single();
            StringAssert.Contains(results.Last().Message, $"imported the certificate as {imported.Arn}");
            StringAssert.StartsWith(imported.Arn, $"arn:aws:acm:{Region}:123456789012:certificate/");
            Assert.AreEqual(_managedCert.Id, imported.Tags[AwsCertificateManager.ManagedCertificateTag]);
            Assert.AreEqual(LeafSerial(), imported.Serial);

            var import = _acm.Body(_acm.Requests.Single(r => _acm.Operation(r) == "ImportCertificate"));
            Assert.IsNull(import["CertificateArn"]);
            StringAssert.StartsWith(Blob(import, "PrivateKey"), "-----BEGIN PRIVATE KEY-----", "RSA keys are sent as PKCS#8, as ACM documents");
            Assert.AreEqual(1, Regex.Matches(Blob(import, "Certificate"), "BEGIN CERTIFICATE").Count, "only the end entity certificate in Certificate");
            Assert.AreEqual(1, Regex.Matches(Blob(import, "CertificateChain"), "BEGIN CERTIFICATE").Count, "intermediate in the chain, root excluded");

            Assert.IsTrue(_acm.Requests.All(r => r.Header("Authorization").Contains($"Credential={AccessKey}/") && r.Header("Authorization").Contains($"/{Region}/acm/aws4_request")));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task RenewalReimportsTaggedCertificate()
        {
            var previous = _acm.Add(OtherCert(), tags: new() { [AwsCertificateManager.ManagedCertificateTag] = _managedCert.Id }, inUseBy: 2);
            var untagged = _acm.Add(OtherCert());
            var otherItem = _acm.Add(OtherCert(), tags: new() { [AwsCertificateManager.ManagedCertificateTag] = "another-managed-certificate" });
            var awsIssued = _acm.Add(OtherCert(), type: "AMAZON_ISSUED");

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Last().Message, $"re-imported certificate {previous.Arn}, so the 2 AWS resources using it pick up the renewed certificate");
            Assert.AreEqual(LeafSerial(), _acm.Certificates[previous.Arn].Serial);
            Assert.AreEqual(4, _acm.Certificates.Count, "no new certificate");
            Assert.AreNotEqual(LeafSerial(), _acm.Certificates[untagged.Arn].Serial);
            Assert.AreNotEqual(LeafSerial(), _acm.Certificates[otherItem.Arn].Serial);

            var import = _acm.Body(_acm.Requests.Single(r => _acm.Operation(r) == "ImportCertificate"));
            Assert.AreEqual(previous.Arn, (string)import["CertificateArn"]);
            Assert.IsNull(import["Tags"], "tags can't be applied when re-importing");

            Assert.IsFalse(_acm.Requests.Any(r => _acm.Operation(r) == "ListTagsForCertificate" && (string)_acm.Body(r)["CertificateArn"] == awsIssued.Arn), "only imported certificates are checked");
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task FindsTaggedCertificateOfAnyKeyTypeAcrossPages()
        {
            _acm.PageSize = 1;
            _acm.Add(OtherCert());
            _acm.Add(OtherCert(), keyAlgorithm: "EC_prime256v1");
            var previous = _acm.Add(OtherCert(), tags: new() { [AwsCertificateManager.ManagedCertificateTag] = _managedCert.Id });

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, $"re-imported certificate {previous.Arn}");
            Assert.AreEqual(3, _acm.Requests.Count(r => _acm.Operation(r) == "ListCertificates"));
            Assert.AreEqual(7, _acm.Body(_acm.Requests.First(r => _acm.Operation(r) == "ListCertificates"))["Includes"]["keyTypes"].AsArray().Count, "all key types are listed, not only RSA 2048");
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task CertificatesForOtherDomainsAreNotChecked()
        {
            _acm.Add(OtherCert("www.other.example"), tags: new() { [AwsCertificateManager.ManagedCertificateTag] = _managedCert.Id });

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, "imported the certificate as");
            Assert.AreEqual(0, _acm.Requests.Count(r => _acm.Operation(r) == "ListTagsForCertificate"));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task ReimportsCertificateArnInItsRegion()
        {
            var target = _acm.Add(OtherCert(), region: "us-east-1");

            var results = await Execute(region: null, arn: target.Arn);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, $"re-imported certificate {target.Arn}");
            Assert.AreEqual(LeafSerial(), _acm.Certificates[target.Arn].Serial);
            Assert.IsTrue(_acm.Requests.All(r => r.Header("Authorization").Contains("/us-east-1/acm/aws4_request")), "region comes from the ARN");
            Assert.IsFalse(_acm.Requests.Any(r => _acm.Operation(r) == "ListCertificates"), "no search when the ARN is set");
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task UnknownCertificateArnIsReported()
        {
            var results = await Execute(arn: $"arn:aws:acm:{Region}:123456789012:certificate/00000000-0000-0000-0000-000000000000");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "there is no certificate arn:aws:acm");
            Assert.IsFalse(_acm.Requests.Any(r => _acm.Operation(r) == "ImportCertificate"));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task AwsIssuedCertificateArnIsRefused()
        {
            var target = _acm.Add(OtherCert(), type: "AMAZON_ISSUED");

            var results = await Execute(arn: target.Arn);

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "was issued by AWS, not imported");
            Assert.IsFalse(_acm.Requests.Any(r => _acm.Operation(r) == "ImportCertificate"));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task KeyTypeChangeIsRefused()
        {
            _acm.Add(OtherCert(), tags: new() { [AwsCertificateManager.ManagedCertificateTag] = _managedCert.Id }, keyAlgorithm: "EC_prime256v1");

            var results = await Execute();

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "has an EC P-256 key, but the new certificate has an RSA 2048 key");
            StringAssert.Contains(failure, "can't change the key type");
            Assert.IsFalse(_acm.Requests.Any(r => _acm.Operation(r) == "ImportCertificate"));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task UpToDateCertificateIsNotReimported()
        {
            var current = _acm.Add(LeafPem(), tags: new() { [AwsCertificateManager.ManagedCertificateTag] = _managedCert.Id });

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"certificate {current.Arn} is already up to date");
            Assert.IsFalse(_acm.Requests.Any(r => _acm.Operation(r) == "ImportCertificate"));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task PreviewMakesNoChanges()
        {
            var previous = _acm.Add(OtherCert(), tags: new() { [AwsCertificateManager.ManagedCertificateTag] = _managedCert.Id }, inUseBy: 1);

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"Connected to AWS Certificate Manager in {Region}. Would re-import certificate {previous.Arn} (www.example.com), keeping its ARN, so the AWS resource using it picks up the renewed certificate.");
            Assert.IsFalse(_acm.Requests.Any(r => _acm.Operation(r) == "ImportCertificate"));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            _managedCert.CertificatePath = "";

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, "No certificate has been issued yet. Deploying would import the certificate as a new ACM certificate");
            Assert.IsTrue(_acm.Requests.Any(r => _acm.Operation(r) == "ListCertificates"));
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task ReportsInvalidAccessKey()
        {
            var results = await Execute(accessKey: "AKIDWRONG");

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "access denied");
            StringAssert.Contains(failure, "Check the Access Key ID and Secret Access Key");
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task ReportsMissingPermission()
        {
            _acm.DenyImport = true;

            var results = await Execute();

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "is not authorized to perform: acm:ImportCertificate");
            StringAssert.Contains(failure, "needs the acm:ListCertificates");
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task ReportsImportRejection()
        {
            _acm.RejectImport = "The certificate field contains more than one certificate.";

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "AWS Certificate Manager: ValidationException: The certificate field contains more than one certificate.");
        }

        [TestMethod, TestCategory("AwsCertificateManager")]
        public async Task ValidatesSettings()
        {
            Assert.IsTrue((await Execute(region: null)).Any(r => r.Message.Contains("AWS Region is required, unless you set the Certificate ARN")));
            Assert.IsTrue((await Execute(region: "Ireland")).Any(r => r.Message.Contains("AWS Region must be a region code")));
            Assert.IsTrue((await Execute(arn: "arn:aws:acm:us-east-1:123456789012:certificate/abc")).Any(r => r.Message.Contains("doesn't match the region of the Certificate ARN (us-east-1)")));
            Assert.IsTrue((await Execute(arn: "not-an-arn")).Any(r => r.Message.Contains("Certificate ARN must be an ACM certificate ARN")));
            Assert.IsTrue((await Execute(endpoint: "acm.example")).Any(r => r.Message.Contains("ACM Endpoint must be blank or a full URL")));
            Assert.IsTrue((await Execute(assumeRoleWithoutArn: true)).Any(r => r.Message.Contains("Assume IAM role enabled, but no Role ARN")));
            Assert.IsTrue((await Execute(accessKey: null)).Any(r => r.Message.Contains("An AWS Access Key credential is required")));

            Assert.AreEqual(0, _acm.Requests.Count, "invalid settings never reach ACM");
        }

        private string LeafPem()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).ExportCertificatePem();
        }

        private string LeafSerial() => X509Certificate2.CreateFromPem(LeafPem()).SerialNumber;

        private static string OtherCert(string domain = "www.example.com")
        {
            using var key = RSA.Create(2048);
            using var cert = new CertificateRequest($"CN={domain}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-90), DateTimeOffset.UtcNow.AddDays(1));
            return cert.ExportCertificatePem();
        }

        private static string Blob(JsonNode body, string name) => Encoding.ASCII.GetString(Convert.FromBase64String((string)body[name]));

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(bool isPreviewOnly = false, string region = Region, string arn = null, string endpoint = null, string accessKey = AccessKey, bool assumeRoleWithoutArn = false)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = AwsCertificateManager.Definition.Id,
                TaskName = "ACM test",
                ChallengeProvider = CredentialTypes.AwsAccessKey,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("region", region),
                    new ProviderParameterSetting("certificate_arn", arn),
                    new ProviderParameterSetting("acm_endpoint", endpoint ?? _acm.Address)
                }
            };

            var credentials = accessKey == null ? null : new Dictionary<string, string> { { "accesskey", accessKey }, { "secretaccesskey", "secret" } };
            if (assumeRoleWithoutArn)
            {
                credentials["useassumerole"] = "true";
            }

            var execParams = new DeploymentTaskExecutionParams(_log, null, _managedCert, config, credentials, isPreviewOnly, AwsCertificateManager.Definition, new DeploymentContext(), CancellationToken.None);
            return await new AwsCertificateManager().Execute(execParams);
        }

        public sealed class AcmCertificate
        {
            public string Arn { get; init; }
            public string Type { get; init; }
            public string KeyAlgorithm { get; set; }
            public string Serial { get; set; }
            public string DomainName { get; set; }
            public Dictionary<string, string> Tags { get; init; } = new();
            public int InUseBy { get; init; }
            public DateTimeOffset ImportedAt { get; set; }
        }

        /// <summary>
        /// Stand-in for the ACM JSON 1.1 API: ListCertificates (paged, RSA 2048 only unless key types are given), ListTagsForCertificate,
        /// DescribeCertificate and ImportCertificate, with ACM's rules for re-importing (same key type, no tags)
        /// </summary>
        private sealed class FakeAcm : IDisposable
        {
            private readonly FakeHttpServer _server;

            public Dictionary<string, AcmCertificate> Certificates { get; } = new();
            public List<FakeHttpRequest> Requests => _server.Requests.Where(r => r.Header("Authorization") != null).ToList();
            public string Address => _server.Address;
            public int PageSize { get; set; } = 1000;
            public bool DenyImport { get; set; }
            public string RejectImport { get; set; }

            public FakeAcm()
            {
                _server = new FakeHttpServer(Handle);
            }

            public string Operation(FakeHttpRequest request) => request.Header("X-Amz-Target")?.Replace("CertificateManager.", "");

            public JsonNode Body(FakeHttpRequest request) => JsonNode.Parse(string.IsNullOrEmpty(request.Body) ? "{}" : request.Body);

            public AcmCertificate Add(string certPem, Dictionary<string, string> tags = null, int inUseBy = 0, string type = "IMPORTED", string keyAlgorithm = "RSA_2048", string region = Region)
            {
                using var cert = X509Certificate2.CreateFromPem(certPem);
                var item = new AcmCertificate
                {
                    Arn = $"arn:aws:acm:{region}:123456789012:certificate/{Guid.NewGuid()}",
                    Type = type,
                    KeyAlgorithm = keyAlgorithm,
                    Serial = cert.SerialNumber,
                    DomainName = cert.GetNameInfo(X509NameType.SimpleName, false),
                    Tags = tags ?? new(),
                    InUseBy = inUseBy,
                    ImportedAt = DateTimeOffset.UtcNow.AddDays(-60)
                };

                Certificates[item.Arn] = item;
                return item;
            }

            private FakeHttpResponse Handle(FakeHttpRequest request)
            {
                lock (Certificates)
                {
                    var auth = request.Header("Authorization") ?? "";
                    if (!auth.Contains($"Credential={AccessKey}/"))
                    {
                        return Error("UnrecognizedClientException", "The security token included in the request is invalid.");
                    }

                    var body = Body(request);

                    switch (Operation(request))
                    {
                        case "ListCertificates":
                            var keyTypes = body["Includes"]?["keyTypes"]?.AsArray().Select(k => (string)k).ToList() ?? new List<string> { "RSA_2048" };
                            var all = Certificates.Values.Where(c => keyTypes.Contains(c.KeyAlgorithm)).ToList();
                            var start = int.TryParse((string)body["NextToken"], out var s) ? s : 0;
                            var page = all.Skip(start).Take(PageSize).ToList();
                            var list = new JsonObject
                            {
                                ["CertificateSummaryList"] = new JsonArray(page.Select(c => (JsonNode)new JsonObject
                                {
                                    ["CertificateArn"] = c.Arn,
                                    ["DomainName"] = c.DomainName,
                                    ["SubjectAlternativeNameSummaries"] = new JsonArray(c.DomainName),
                                    ["Type"] = c.Type,
                                    ["KeyAlgorithm"] = c.KeyAlgorithm,
                                    ["ImportedAt"] = c.ImportedAt.ToUnixTimeSeconds()
                                }).ToArray())
                            };
                            if (start + PageSize < all.Count)
                            {
                                list["NextToken"] = (start + PageSize).ToString();
                            }

                            return Ok(list);

                        case "ListTagsForCertificate":
                            if (!Certificates.TryGetValue((string)body["CertificateArn"], out var tagged))
                            {
                                return Error("ResourceNotFoundException", "Could not find certificate.");
                            }

                            return Ok(new JsonObject { ["Tags"] = new JsonArray(tagged.Tags.Select(t => (JsonNode)new JsonObject { ["Key"] = t.Key, ["Value"] = t.Value }).ToArray()) });

                        case "DescribeCertificate":
                            if (!Certificates.TryGetValue((string)body["CertificateArn"], out var described))
                            {
                                return Error("ResourceNotFoundException", $"Could not find certificate {body["CertificateArn"]}.");
                            }

                            return Ok(new JsonObject
                            {
                                ["Certificate"] = new JsonObject
                                {
                                    ["CertificateArn"] = described.Arn,
                                    ["DomainName"] = described.DomainName,
                                    ["Type"] = described.Type,
                                    ["KeyAlgorithm"] = described.KeyAlgorithm,
                                    ["Serial"] = string.Join(":", Convert.FromHexString(described.Serial).Select(b => b.ToString("x2"))),
                                    ["InUseBy"] = new JsonArray(Enumerable.Range(1, described.InUseBy).Select(i => (JsonNode)$"arn:aws:elasticloadbalancing:{Region}:123456789012:loadbalancer/app/lb{i}/1").ToArray())
                                }
                            });

                        case "ImportCertificate":
                            return Import(body);

                        default:
                            return Error("UnknownOperationException", "Unknown operation");
                    }
                }
            }

            private FakeHttpResponse Import(JsonNode body)
            {
                if (DenyImport)
                {
                    return Error("AccessDeniedException", "User: arn:aws:iam::123456789012:user/certify is not authorized to perform: acm:ImportCertificate");
                }

                if (RejectImport != null)
                {
                    return Error("ValidationException", RejectImport);
                }

                var certPem = Blob(body, "Certificate");
                var keyPem = Blob(body, "PrivateKey");

                // the key must match the certificate
                using var cert = X509Certificate2.CreateFromPem(certPem, keyPem);
                var keyAlgorithm = cert.GetRSAPublicKey() is RSA rsa ? $"RSA_{rsa.KeySize}" : "EC_prime256v1";

                var arn = (string)body["CertificateArn"];
                if (arn != null)
                {
                    if (!Certificates.TryGetValue(arn, out var existing))
                    {
                        return Error("ResourceNotFoundException", $"Could not find certificate {arn}.");
                    }

                    if (body["Tags"] != null)
                    {
                        return Error("ValidationException", "Tags cannot be applied when reimporting a certificate.");
                    }

                    if (existing.KeyAlgorithm != keyAlgorithm)
                    {
                        return Error("ValidationException", "The certificate key algorithm cannot be changed.");
                    }

                    existing.Serial = cert.SerialNumber;
                    existing.DomainName = cert.GetNameInfo(X509NameType.SimpleName, false);
                    existing.ImportedAt = DateTimeOffset.UtcNow;
                    return Ok(new JsonObject { ["CertificateArn"] = arn });
                }

                var item = new AcmCertificate
                {
                    Arn = $"arn:aws:acm:{Region}:123456789012:certificate/{Guid.NewGuid()}",
                    Type = "IMPORTED",
                    KeyAlgorithm = keyAlgorithm,
                    Serial = cert.SerialNumber,
                    DomainName = cert.GetNameInfo(X509NameType.SimpleName, false),
                    Tags = body["Tags"]?.AsArray().ToDictionary(t => (string)t["Key"], t => (string)t["Value"]) ?? new(),
                    ImportedAt = DateTimeOffset.UtcNow
                };

                Certificates[item.Arn] = item;
                return Ok(new JsonObject { ["CertificateArn"] = item.Arn });
            }

            private static FakeHttpResponse Ok(JsonNode body) => new FakeHttpResponse(200, "application/x-amz-json-1.1", body.ToJsonString());

            private static FakeHttpResponse Error(string type, string message)
                => new FakeHttpResponse(400, "application/x-amz-json-1.1", new JsonObject { ["__type"] = type, ["message"] = message }.ToJsonString());

            public void Dispose() => _server.Dispose();
        }
    }
}
