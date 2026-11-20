using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Certify.Tests.DeploymentTaskTests
{
    public sealed class FakeHttpRequest
    {
        public string Method { get; init; }
        public string Path { get; init; }
        public Dictionary<string, string> Query { get; init; }
        public Dictionary<string, string> Headers { get; init; }
        public string Body { get; init; }
        public byte[] BodyBytes { get; init; }

        public string Header(string name) => Headers.GetValueOrDefault(name);
    }

    /// <summary>
    /// A response, with any extra headers. A null response closes the connection without answering.
    /// </summary>
    public sealed record FakeHttpResponse(int Status, string ContentType, string Body, Dictionary<string, string> Headers = null);

    /// <summary>
    /// Local stand-in for a device management API, used to test deployment tasks without the device. HttpListener is not used as it
    /// needs a URL reservation on Windows. Minimal HTTP/1.1 handling: one request per connection, answered with Connection: close.
    /// With a server certificate (which needs its private key), requests are served over HTTPS.
    /// </summary>
    public sealed class FakeHttpServer : IDisposable
    {
        private readonly TcpListener _listener = new TcpListener(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly Func<FakeHttpRequest, FakeHttpResponse> _handler;
        private readonly X509Certificate2 _serverCertificate;

        public string Address { get; }
        public List<FakeHttpRequest> Requests { get; } = new List<FakeHttpRequest>();

        public FakeHttpServer(Func<FakeHttpRequest, FakeHttpResponse> handler, X509Certificate2 serverCertificate = null)
        {
            _handler = handler;
            _serverCertificate = serverCertificate;
            _listener.Start();
            Address = $"{(serverCertificate == null ? "http" : "https")}://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";

            _ = Task.Run(Serve);
        }

        private async Task Serve()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient tcp;
                try
                {
                    tcp = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch (Exception) when (_cts.IsCancellationRequested)
                {
                    return;
                }

                using (tcp)
                {
                    Stream stream = tcp.GetStream();
                    FakeHttpRequest request;
                    try
                    {
                        if (_serverCertificate != null)
                        {
                            var tls = new SslStream(stream);
                            await tls.AuthenticateAsServerAsync(_serverCertificate);
                            stream = tls;
                        }

                        request = await ReadRequest(stream);
                        if (request == null)
                        {
                            continue;
                        }
                    }
                    catch (Exception exp) when (exp is IOException || exp is System.Security.Authentication.AuthenticationException)
                    {
                        // the client refused the TLS certificate, or closed the connection
                        continue;
                    }

                    lock (Requests)
                    {
                        Requests.Add(request);
                    }

                    FakeHttpResponse response;
                    try
                    {
                        response = _handler(request);
                    }
                    catch (Exception exp)
                    {
                        response = new FakeHttpResponse(500, "text/plain", exp.ToString());
                    }

                    if (response == null)
                    {
                        continue;
                    }

                    var body = Encoding.UTF8.GetBytes(response.Body ?? "");
                    var extraHeaders = string.Concat((response.Headers ?? new()).Select(h => $"{h.Key}: {h.Value}\r\n"));
                    var head = $"HTTP/1.1 {response.Status} {(response.Status < 400 ? "OK" : "Error")}\r\nContent-Type: {response.ContentType}\r\nContent-Length: {body.Length}\r\n{extraHeaders}Connection: close\r\n\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(head));
                    await stream.WriteAsync(body);
                }
            }
        }

        private static async Task<FakeHttpRequest> ReadRequest(Stream stream)
        {
            // read up to the end of the headers
            var buffer = new List<byte>();
            var one = new byte[1];
            while (!(buffer.Count >= 4 && buffer[^4] == '\r' && buffer[^3] == '\n' && buffer[^2] == '\r' && buffer[^1] == '\n'))
            {
                if (await stream.ReadAsync(one) == 0)
                {
                    break;
                }

                buffer.Add(one[0]);
            }

            if (buffer.Count == 0)
            {
                // closed without a request
                return null;
            }

            var lines = Encoding.ASCII.GetString(buffer.ToArray()).Split("\r\n");
            var requestLine = lines[0].Split(' ');
            var headers = lines.Skip(1).Where(l => l.Contains(':')).ToDictionary(l => l[..l.IndexOf(':')].Trim(), l => l[(l.IndexOf(':') + 1)..].Trim(), StringComparer.OrdinalIgnoreCase);

            var body = Array.Empty<byte>();
            if (headers.TryGetValue("Content-Length", out var lengthText) && int.TryParse(lengthText, out var length) && length > 0)
            {
                body = new byte[length];
                await stream.ReadExactlyAsync(body);
            }

            var target = new Uri("http://localhost" + requestLine[1]);
            var query = System.Web.HttpUtility.ParseQueryString(target.Query);

            return new FakeHttpRequest
            {
                Method = requestLine[0],
                Path = Uri.UnescapeDataString(target.AbsolutePath),
                Query = query.AllKeys.Where(k => k != null).ToDictionary(k => k, k => query[k]),
                Headers = headers,
                Body = Encoding.UTF8.GetString(body),
                BodyBytes = body
            };
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
        }
    }

    public static class TestCertificates
    {
        /// <summary>
        /// Create a PFX (no password) containing a leaf certificate and key for www.example.com, its intermediates and a root.
        /// Thumbprints (lower case) are of the intermediates in chain order, from the issuer of the leaf upwards.
        /// </summary>
        public static (string Path, List<string> IntermediateThumbprints) CreatePfxWithChain(int intermediateCount = 1)
        {
            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            var notAfter = DateTimeOffset.UtcNow.AddDays(30);

            using var rootKey = RSA.Create(2048);
            var rootReq = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            var issuer = rootReq.CreateSelfSigned(notBefore, notAfter.AddDays(10));
            var root = X509CertificateLoader.LoadCertificate(issuer.RawData);

            var intermediates = new List<X509Certificate2>();
            for (var i = 0; i < intermediateCount; i++)
            {
                using var intKey = RSA.Create(2048);
                var intReq = new CertificateRequest($"CN=Test Intermediate {i + 1}", intKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                intReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                intReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                using var intPublic = intReq.Create(issuer, notBefore, notAfter.AddDays(5), new byte[] { 1, 2, 3, (byte)(4 + i) });

                issuer.Dispose();
                issuer = intPublic.CopyWithPrivateKey(intKey);
                intermediates.Insert(0, X509CertificateLoader.LoadCertificate(intPublic.RawData));
            }

            using var leafKey = RSA.Create(2048);
            var leafReq = new CertificateRequest("CN=www.example.com", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var leafPublic = leafReq.Create(issuer, notBefore, notAfter, new byte[] { 5, 6, 7, 8 });
            using var leaf = leafPublic.CopyWithPrivateKey(leafKey);
            issuer.Dispose();

            var collection = new X509Certificate2Collection { leaf };
            collection.AddRange(intermediates.ToArray());
            collection.Add(root);

            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"certify-device-test-{Guid.NewGuid():N}.pfx");
            File.WriteAllBytes(path, collection.Export(X509ContentType.Pkcs12, ""));

            return (path, intermediates.Select(c => c.Thumbprint.ToLowerInvariant()).ToList());
        }
    }
}
