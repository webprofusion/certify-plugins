using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
    /// Runs the AWS Secrets Manager task against a local stand-in for the Secrets Manager API (JSON 1.1 protocol), reached through the task's
    /// endpoint setting. The AWS SDK signs each request as it would for AWS; the stand-in only checks the access key ID and region in the signature.
    /// </summary>
    [TestClass]
    public class DeploymentTasksAwsSecretsManager : IntegrationTestBase
    {
        private const string Region = "eu-west-1";
        private const string AccessKey = "AKIDCERTIFYTEST";
        private const string SecretName = "prod/www.example.com/tls";

        private FakeSecretsManager _sm;
        private string _pfxPath;
        private ManagedCertificate _managedCert;

        [TestInitialize]
        public override void Setup()
        {
            base.Setup();

            _sm = new FakeSecretsManager();
            (_pfxPath, _) = TestCertificates.CreatePfxWithChain(1);
            _managedCert = GetMockManagedCertificate("SecretsManagerTest", "1", "www.example.com", PrimaryIISRoot);
            _managedCert.CertificatePath = _pfxPath;
        }

        [TestCleanup]
        public void Cleanup()
        {
            _sm?.Dispose();
            if (_pfxPath != null && File.Exists(_pfxPath))
            {
                File.Delete(_pfxPath);
            }
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task FirstDeploymentCreatesTaggedSecret()
        {
            var results = await Execute(kmsKeyId: "alias/certificates");

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            var secret = _sm.Secrets.Values.Single();
            StringAssert.Contains(results.Last().Message, $"created secret {secret.Arn} holding the certificate");
            Assert.AreEqual(SecretName, secret.Name);
            Assert.AreEqual(_managedCert.Id, secret.Tags[AwsSecretsManager.ManagedCertificateTag]);
            Assert.AreEqual("alias/certificates", secret.KmsKeyId);

            var value = JsonNode.Parse(secret.CurrentValue);
            Assert.AreEqual(LeafSerial(), X509Certificate2.CreateFromPem((string)value["certificate"]).SerialNumber);
            StringAssert.StartsWith((string)value["private_key"], "-----BEGIN PRIVATE KEY-----", "key is PKCS#8");
            using (X509Certificate2.CreateFromPem((string)value["certificate"], (string)value["private_key"]))
            {
                // the key matches the certificate
            }

            Assert.AreEqual(1, Regex.Matches((string)value["certificate"], "BEGIN CERTIFICATE").Count, "only the end entity certificate in certificate");
            Assert.AreEqual(1, Regex.Matches((string)value["chain"], "BEGIN CERTIFICATE").Count, "intermediate in the chain, root excluded");
            Assert.AreEqual((string)value["certificate"] + (string)value["chain"], (string)value["fullchain"]);
            Assert.IsNull(value["pfx"], "no PFX unless asked for");

            Assert.IsTrue(_sm.Requests.All(r => r.Header("Authorization").Contains($"Credential={AccessKey}/") && r.Header("Authorization").Contains($"/{Region}/secretsmanager/aws4_request")));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task RenewalAddsCurrentVersionToExistingSecret()
        {
            var existing = _sm.Add(SecretName, "{\"certificate\":\"previous\"}");
            var previousVersion = existing.CurrentVersionId;

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess && !r.IsWarning), Messages(results));
            StringAssert.Contains(results.Last().Message, $"added the certificate to secret {existing.Arn} as version {existing.CurrentVersionId}, now its current value");
            Assert.AreEqual(1, _sm.Secrets.Count, "no new secret");
            Assert.AreEqual(LeafSerial(), X509Certificate2.CreateFromPem((string)JsonNode.Parse(existing.CurrentValue)["certificate"]).SerialNumber);
            CollectionAssert.Contains(existing.Stages[previousVersion], "AWSPREVIOUS");
            Assert.IsFalse(existing.Tags.ContainsKey(AwsSecretsManager.ManagedCertificateTag), "an existing secret's tags are left as they are");
            Assert.IsFalse(_sm.Requests.Any(r => _sm.Operation(r) == "CreateSecret"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task UpToDateSecretIsNotWritten()
        {
            await Execute();
            var secret = _sm.Secrets.Values.Single();
            var versions = secret.Versions.Count;

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"secret {secret.Arn} is already up to date");
            Assert.AreEqual(versions, secret.Versions.Count);
            Assert.AreEqual(1, _sm.Requests.Count(r => _sm.Operation(r) is "CreateSecret" or "PutSecretValue"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task SameCertificateIsMadeCurrentAgainAfterSecretWasChanged()
        {
            await Execute();
            var secret = _sm.Secrets.Values.Single();
            var deployedVersion = secret.CurrentVersionId;
            _sm.Put(secret, "{\"certificate\":\"changed by someone else\"}", Guid.NewGuid().ToString());

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"already had this certificate as version {deployedVersion}, which is now its current value again");
            Assert.AreEqual(deployedVersion, secret.CurrentVersionId);
            Assert.AreEqual(1, _sm.Requests.Count(r => _sm.Operation(r) == "UpdateSecretVersionStage"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task IncludesPfxWhenAskedFor()
        {
            var results = await Execute(includePfx: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            var value = JsonNode.Parse(_sm.Secrets.Values.Single().CurrentValue);
            CollectionAssert.AreEqual(File.ReadAllBytes(_pfxPath), Convert.FromBase64String((string)value["pfx"]));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task SecretGivenByArnIsWrittenInItsRegion()
        {
            var existing = _sm.Add("other/name", "{}", region: "us-east-1");

            var results = await Execute(region: null, secretId: existing.Arn);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Last().Message, $"added the certificate to secret {existing.Arn}");
            Assert.IsTrue(_sm.Requests.All(r => r.Header("Authorization").Contains("/us-east-1/secretsmanager/aws4_request")), "region comes from the ARN");
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task UnknownSecretArnIsReported()
        {
            var results = await Execute(secretId: $"arn:aws:secretsmanager:{Region}:123456789012:secret:missing-AbCdEf");

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "there is no secret arn:aws:secretsmanager");
            Assert.IsFalse(_sm.Requests.Any(r => _sm.Operation(r) is "CreateSecret" or "PutSecretValue"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task SecretOfAnotherManagedCertificateIsRefused()
        {
            _sm.Add(SecretName, "{}", tags: new() { [AwsSecretsManager.ManagedCertificateTag] = "another-managed-certificate" });

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "holds the certificate of a different managed certificate");
            Assert.IsFalse(_sm.Requests.Any(r => _sm.Operation(r) == "PutSecretValue"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task SecretScheduledForDeletionIsRefused()
        {
            _sm.Add(SecretName, "{}").DeletedDate = DateTimeOffset.UtcNow;

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "is scheduled for deletion");
            Assert.IsFalse(_sm.Requests.Any(r => _sm.Operation(r) == "PutSecretValue"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task ReplicaSecretIsRefused()
        {
            _sm.Add(SecretName, "{}").PrimaryRegion = "us-east-1";

            var results = await Execute();

            StringAssert.Contains(results.Single(r => !r.IsSuccess).Message, "is a replica of a secret in us-east-1");
            Assert.IsFalse(_sm.Requests.Any(r => _sm.Operation(r) == "PutSecretValue"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task RotationIsWarnedAbout()
        {
            _sm.Add(SecretName, "{}").RotationEnabled = true;

            var results = await Execute();

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single(r => r.IsWarning).Message, "rotation is turned on");
            Assert.AreEqual(1, _sm.Requests.Count(r => _sm.Operation(r) == "PutSecretValue"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task PreviewMakesNoChanges()
        {
            var existing = _sm.Add(SecretName, "{}");

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"Connected to AWS Secrets Manager in {Region}. Would add the certificate as a new version of secret {SecretName}, making it the current value.");
            Assert.AreEqual(1, existing.Versions.Count);
            Assert.IsTrue(_sm.Requests.All(r => _sm.Operation(r) == "DescribeSecret"));
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task PreviewBeforeCertificateIssuedChecksConnection()
        {
            _managedCert.CertificatePath = "";

            var results = await Execute(isPreviewOnly: true);

            Assert.IsTrue(results.All(r => r.IsSuccess), Messages(results));
            StringAssert.Contains(results.Single().Message, $"No certificate has been issued yet. Deploying would create secret {SecretName} holding the certificate.");
            Assert.AreEqual(0, _sm.Secrets.Count);
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task ReportsInvalidAccessKey()
        {
            var results = await Execute(accessKey: "AKIDWRONG");

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "access denied");
            StringAssert.Contains(failure, "Check the Access Key ID and Secret Access Key");
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task ReportsMissingPermission()
        {
            _sm.DenyCreate = true;

            var results = await Execute();

            var failure = results.Single(r => !r.IsSuccess).Message;
            StringAssert.Contains(failure, "is not authorized to perform: secretsmanager:CreateSecret");
            StringAssert.Contains(failure, "needs the secretsmanager:DescribeSecret, secretsmanager:CreateSecret, secretsmanager:PutSecretValue, secretsmanager:TagResource and secretsmanager:UpdateSecretVersionStage permissions");
        }

        [TestMethod, TestCategory("AwsSecretsManager")]
        public async Task ValidatesSettings()
        {
            Assert.IsTrue((await Execute(secretId: null)).Any(r => r.Message.Contains("Secret Name or ARN is required")));
            Assert.IsTrue((await Execute(secretId: "has spaces")).Any(r => r.Message.Contains("Secret Name can only contain")));
            Assert.IsTrue((await Execute(region: null)).Any(r => r.Message.Contains("AWS Region is required, unless the secret is given by ARN")));
            Assert.IsTrue((await Execute(region: "Ireland")).Any(r => r.Message.Contains("AWS Region must be a region code")));
            Assert.IsTrue((await Execute(secretId: "arn:aws:secretsmanager:us-east-1:123456789012:secret:x-AbCdEf")).Any(r => r.Message.Contains("doesn't match the region of the secret ARN (us-east-1)")));
            Assert.IsTrue((await Execute(secretId: "arn:aws:acm:eu-west-1:123456789012:certificate/abc")).Any(r => r.Message.Contains("Secret ARN must be a Secrets Manager secret ARN")));
            Assert.IsTrue((await Execute(endpoint: "secretsmanager.example")).Any(r => r.Message.Contains("Secrets Manager Endpoint must be blank or a full URL")));
            Assert.IsTrue((await Execute(assumeRoleWithoutArn: true)).Any(r => r.Message.Contains("Assume IAM role enabled, but no Role ARN")));
            Assert.IsTrue((await Execute(accessKey: null)).Any(r => r.Message.Contains("An AWS Access Key credential is required")));

            Assert.AreEqual(0, _sm.Requests.Count, "invalid settings never reach Secrets Manager");
        }

        private string LeafSerial()
        {
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(_pfxPath, "");
            return collection.Single(c => c.HasPrivateKey).SerialNumber;
        }

        private static string Messages(List<ActionResult> results) => string.Join("; ", results.Select(r => r.Message));

        private async Task<List<ActionResult>> Execute(bool isPreviewOnly = false, string region = Region, string secretId = SecretName, string kmsKeyId = null, bool includePfx = false,
            string endpoint = null, string accessKey = AccessKey, bool assumeRoleWithoutArn = false)
        {
            var config = new DeploymentTaskConfig
            {
                TaskTypeId = AwsSecretsManager.Definition.Id,
                TaskName = "Secrets Manager test",
                ChallengeProvider = CredentialTypes.AwsAccessKey,
                Parameters = new List<ProviderParameterSetting>
                {
                    new ProviderParameterSetting("region", region),
                    new ProviderParameterSetting("secret_id", secretId),
                    new ProviderParameterSetting("kms_key_id", kmsKeyId),
                    new ProviderParameterSetting("include_pfx", includePfx.ToString().ToLowerInvariant()),
                    new ProviderParameterSetting("secretsmanager_endpoint", endpoint ?? _sm.Address)
                }
            };

            var credentials = accessKey == null ? null : new Dictionary<string, string> { { "accesskey", accessKey }, { "secretaccesskey", "secret" } };
            if (assumeRoleWithoutArn)
            {
                credentials["useassumerole"] = "true";
            }

            var execParams = new DeploymentTaskExecutionParams(_log, null, _managedCert, config, credentials, isPreviewOnly, AwsSecretsManager.Definition, new DeploymentContext(), CancellationToken.None);
            return await new AwsSecretsManager().Execute(execParams);
        }

        public sealed class SmSecret
        {
            public string Arn { get; init; }
            public string Name { get; init; }
            public string KmsKeyId { get; init; }
            public Dictionary<string, string> Tags { get; init; } = new();
            public Dictionary<string, string> Versions { get; } = new();
            public Dictionary<string, List<string>> Stages { get; } = new();
            public bool RotationEnabled { get; set; }
            public DateTimeOffset? DeletedDate { get; set; }
            public string PrimaryRegion { get; set; }

            public string CurrentVersionId => Stages.Single(s => s.Value.Contains("AWSCURRENT")).Key;
            public string CurrentValue => Versions[CurrentVersionId];
        }

        /// <summary>
        /// Stand-in for the Secrets Manager JSON 1.1 API: DescribeSecret, CreateSecret, PutSecretValue and UpdateSecretVersionStage, with its
        /// rules for version IDs (a repeated ID with the same value is ignored, with a different value is refused) and stage labels
        /// </summary>
        private sealed class FakeSecretsManager : IDisposable
        {
            private readonly FakeHttpServer _server;

            public Dictionary<string, SmSecret> Secrets { get; } = new();
            public List<FakeHttpRequest> Requests => _server.Requests.Where(r => r.Header("Authorization") != null).ToList();
            public string Address => _server.Address;
            public bool DenyCreate { get; set; }

            public FakeSecretsManager()
            {
                _server = new FakeHttpServer(Handle);
            }

            public string Operation(FakeHttpRequest request) => request.Header("X-Amz-Target")?.Split('.').Last();

            public JsonNode Body(FakeHttpRequest request) => JsonNode.Parse(string.IsNullOrEmpty(request.Body) ? "{}" : request.Body);

            public SmSecret Add(string name, string value, Dictionary<string, string> tags = null, string region = Region, string kmsKeyId = null)
            {
                var secret = new SmSecret
                {
                    Arn = $"arn:aws:secretsmanager:{region}:123456789012:secret:{name}-{Guid.NewGuid().ToString("N")[..6]}",
                    Name = name,
                    KmsKeyId = kmsKeyId,
                    Tags = tags ?? new()
                };

                Put(secret, value, Guid.NewGuid().ToString());
                Secrets[secret.Arn] = secret;
                return secret;
            }

            /// <summary>
            /// Add a version as the current value, moving AWSPREVIOUS to the version that was current
            /// </summary>
            public void Put(SmSecret secret, string value, string versionId)
            {
                var previous = secret.Stages.FirstOrDefault(s => s.Value.Contains("AWSCURRENT")).Key;

                foreach (var stages in secret.Stages.Values)
                {
                    stages.Remove("AWSPREVIOUS");
                }

                if (previous != null)
                {
                    secret.Stages[previous].Remove("AWSCURRENT");
                    secret.Stages[previous].Add("AWSPREVIOUS");
                }

                secret.Versions[versionId] = value;
                secret.Stages[versionId] = new List<string> { "AWSCURRENT" };
            }

            private SmSecret Find(string secretId)
                => Secrets.Values.FirstOrDefault(s => s.Arn == secretId || s.Name == secretId || (secretId != null && s.Arn.StartsWith(secretId + "-", StringComparison.Ordinal)));

            private FakeHttpResponse Handle(FakeHttpRequest request)
            {
                lock (Secrets)
                {
                    var auth = request.Header("Authorization") ?? "";
                    if (!auth.Contains($"Credential={AccessKey}/"))
                    {
                        return Error("UnrecognizedClientException", "The security token included in the request is invalid.");
                    }

                    var body = Body(request);
                    var region = Regex.Match(auth, @"/([a-z0-9-]+)/secretsmanager/aws4_request").Groups[1].Value;

                    switch (Operation(request))
                    {
                        case "DescribeSecret":
                            var described = Find((string)body["SecretId"]);
                            if (described == null || !described.Arn.Contains($":{region}:"))
                            {
                                return Error("ResourceNotFoundException", "Secrets Manager can't find the specified secret.");
                            }

                            var response = new JsonObject
                            {
                                ["ARN"] = described.Arn,
                                ["Name"] = described.Name,
                                ["RotationEnabled"] = described.RotationEnabled,
                                ["Tags"] = new JsonArray(described.Tags.Select(t => (JsonNode)new JsonObject { ["Key"] = t.Key, ["Value"] = t.Value }).ToArray()),
                                ["VersionIdsToStages"] = new JsonObject(described.Stages.Where(s => s.Value.Count > 0).Select(s => KeyValuePair.Create(s.Key, (JsonNode)new JsonArray(s.Value.Select(v => (JsonNode)v).ToArray()))))
                            };

                            if (described.KmsKeyId != null)
                            {
                                response["KmsKeyId"] = described.KmsKeyId;
                            }

                            if (described.DeletedDate != null)
                            {
                                response["DeletedDate"] = described.DeletedDate.Value.ToUnixTimeSeconds();
                            }

                            if (described.PrimaryRegion != null)
                            {
                                response["PrimaryRegion"] = described.PrimaryRegion;
                            }

                            return Ok(response);

                        case "CreateSecret":
                            if (DenyCreate)
                            {
                                return Error("AccessDeniedException", "User: arn:aws:iam::123456789012:user/certify is not authorized to perform: secretsmanager:CreateSecret");
                            }

                            var name = (string)body["Name"];
                            if (Find(name) != null)
                            {
                                return Error("ResourceExistsException", "The operation failed because the secret already exists.");
                            }

                            var created = new SmSecret
                            {
                                Arn = $"arn:aws:secretsmanager:{region}:123456789012:secret:{name}-{Guid.NewGuid().ToString("N")[..6]}",
                                Name = name,
                                KmsKeyId = (string)body["KmsKeyId"],
                                Tags = body["Tags"]?.AsArray().ToDictionary(t => (string)t["Key"], t => (string)t["Value"]) ?? new()
                            };

                            Put(created, (string)body["SecretString"], (string)body["ClientRequestToken"]);
                            Secrets[created.Arn] = created;
                            return Ok(new JsonObject { ["ARN"] = created.Arn, ["Name"] = created.Name, ["VersionId"] = created.CurrentVersionId });

                        case "PutSecretValue":
                            var target = Find((string)body["SecretId"]);
                            if (target == null)
                            {
                                return Error("ResourceNotFoundException", "Secrets Manager can't find the specified secret.");
                            }

                            var versionId = (string)body["ClientRequestToken"];
                            var value = (string)body["SecretString"];
                            if (target.Versions.TryGetValue(versionId, out var existingValue))
                            {
                                if (existingValue != value)
                                {
                                    return Error("ResourceExistsException", "You can't modify an existing version, you can only create a new version.");
                                }
                            }
                            else
                            {
                                Put(target, value, versionId);
                            }

                            return Ok(new JsonObject { ["ARN"] = target.Arn, ["Name"] = target.Name, ["VersionId"] = versionId, ["VersionStages"] = new JsonArray(target.Stages[versionId].Select(v => (JsonNode)v).ToArray()) });

                        case "UpdateSecretVersionStage":
                            var staged = Find((string)body["SecretId"]);
                            var stage = (string)body["VersionStage"];
                            var moveTo = (string)body["MoveToVersionId"];
                            var removeFrom = (string)body["RemoveFromVersionId"];
                            if (staged == null || !staged.Versions.ContainsKey(moveTo))
                            {
                                return Error("ResourceNotFoundException", "Secrets Manager can't find the specified secret version.");
                            }

                            var holder = staged.Stages.FirstOrDefault(s => s.Value.Contains(stage)).Key;
                            if (holder != null && holder != removeFrom)
                            {
                                return Error("InvalidParameterException", "The staging label is attached to a different version than the one specified in RemoveFromVersionId.");
                            }

                            if (holder != null)
                            {
                                staged.Stages[holder].Remove(stage);
                            }

                            staged.Stages[moveTo].Add(stage);
                            return Ok(new JsonObject { ["ARN"] = staged.Arn, ["Name"] = staged.Name });

                        default:
                            return Error("UnknownOperationException", "Unknown operation");
                    }
                }
            }

            private static FakeHttpResponse Ok(JsonNode body) => new FakeHttpResponse(200, "application/x-amz-json-1.1", body.ToJsonString());

            private static FakeHttpResponse Error(string type, string message)
                => new FakeHttpResponse(400, "application/x-amz-json-1.1", new JsonObject { ["__type"] = type, ["message"] = message }.ToJsonString());

            public void Dispose() => _server.Dispose();
        }
    }
}
