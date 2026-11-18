using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Certify.Models;
using Certify.Models.Config.Migration;

namespace Certify.Plugin.CertificateManagers.Migration
{
    /// <summary>
    /// Secrets a migration source found while describing an item. Each is checked at preview and read again at import, so
    /// no value is held in the description or the plan
    /// </summary>
    internal sealed class MigrationSecrets
    {
        private readonly SourceRenewalDescription _description;
        private readonly Dictionary<string, (Func<string?> Check, Func<string> Resolve)> _values = new();

        public MigrationSecrets(SourceRenewalDescription description)
        {
            _description = description;
        }

        /// <summary>
        /// Record a secret, once per key
        /// </summary>
        /// <param name="isShared">true if other items use the same secret, so one credential serves them all</param>
        /// <param name="isGenerated">true if the value is generated at import rather than held by the source</param>
        /// <param name="check">a cheaper check than reading the value, if reading has side effects</param>
        public string Add(string key, string location, bool isShared, Func<(string? Value, string? Error)> read, bool isGenerated = false, Func<string?>? check = null)
        {
            if (!_values.ContainsKey(key))
            {
                Func<string> resolve = () =>
                {
                    var (value, error) = read();
                    return value ?? throw new InvalidOperationException($"{location} could not be read: {error}");
                };

                _values[key] = (check ?? (() => read().Error), resolve);

                var error = _values[key].Check();
                _description.Secrets.Add(new SourceSecret { Key = key, Location = location, IsReadable = error == null, Reason = error, IsShared = isShared, IsGenerated = isGenerated });
            }

            return key;
        }

        /// <summary>
        /// The values of a credential draft, reading each secret it refers to
        /// </summary>
        public Dictionary<string, string> Resolve(ExternalMigrationCredentialDraft draft)
        {
            var values = new Dictionary<string, string>();

            foreach (var (parameter, reference) in draft.Values)
            {
                if (reference.StartsWith(ExternalMigrationCredentialDraft.LiteralPrefix, StringComparison.Ordinal))
                {
                    values[parameter] = reference[ExternalMigrationCredentialDraft.LiteralPrefix.Length..];
                    continue;
                }

                if (!_values.TryGetValue(reference, out var secret))
                {
                    throw new InvalidOperationException($"{draft.Title} refers to a setting the source no longer has.");
                }

                values[parameter] = secret.Resolve();
            }

            return values;
        }
    }

    /// <summary>
    /// Reading the files migration sources keep: PEM certificates and keys, JWK account keys, and tool processes
    /// </summary>
    internal static class MigrationFiles
    {
        /// <summary>
        /// The certificate and key in PEM files as a PFX, recording the certificate's details on the description
        /// </summary>
        /// <param name="certPath">the certificate, optionally followed by its chain</param>
        /// <param name="chainPath">intermediate certificates, if kept separately</param>
        public static SourceCertificateMaterial? LoadPemCertificate(SourceRenewalDescription description, string tool, string certPath, string keyPath, string? chainPath, string? expectedThumbprint, bool keepData, out string? note)
        {
            note = null;

            if (!File.Exists(certPath))
            {
                note = $"{tool}'s certificate {certPath} was not found.";
                return null;
            }

            if (!File.Exists(keyPath))
            {
                note = $"{tool}'s private key {keyPath} was not found.";
                return null;
            }

            try
            {
                using var leaf = X509Certificate2.CreateFromPemFile(certPath, keyPath);

                if (!string.IsNullOrWhiteSpace(expectedThumbprint) && !leaf.Thumbprint.Equals(expectedThumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    note = $"{certPath} is not the certificate {tool} last issued.";
                    return null;
                }

                description.CurrentCertificateReadable = true;
                description.CurrentCertificateThumbprint = leaf.Thumbprint;
                description.CurrentCertificateExpiry = new DateTimeOffset(leaf.NotAfter);

                if (!keepData)
                {
                    return new SourceCertificateMaterial { Thumbprint = leaf.Thumbprint, SourcePath = certPath };
                }

                var collection = new X509Certificate2Collection(leaf);

                foreach (var file in new[] { certPath, chainPath }.Where(f => !string.IsNullOrWhiteSpace(f) && File.Exists(f)))
                {
                    var certificates = new X509Certificate2Collection();
                    certificates.ImportFromPemFile(file!);

                    foreach (var certificate in certificates)
                    {
                        if (collection.Cast<X509Certificate2>().Any(c => c.Thumbprint == certificate.Thumbprint))
                        {
                            certificate.Dispose();
                        }
                        else
                        {
                            collection.Add(certificate);
                        }
                    }
                }

                var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                var data = collection.Export(X509ContentType.Pkcs12, password);

                foreach (var certificate in collection.Cast<X509Certificate2>().Where(c => c != leaf))
                {
                    certificate.Dispose();
                }

                return new SourceCertificateMaterial { PfxData = data, PfxPassword = password, Thumbprint = leaf.Thumbprint, SourcePath = certPath };
            }
            catch (Exception exp) when (exp is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
            {
                note = $"{certPath} or {keyPath} could not be read: {exp.Message}";
                return null;
            }
        }

        /// <summary>
        /// The key type of a certificate, for sources which do not record the key settings they used
        /// </summary>
        public static void DescribeKeyFromCertificate(SourceRenewalDescription description, string certPath)
        {
            try
            {
                using var certificate = X509CertificateLoader.LoadCertificateFromFile(certPath);
                using var ec = certificate.GetECDsaPublicKey();

                if (ec != null)
                {
                    description.KeyType = "ec";
                    description.EcCurve = ec.KeySize switch { 256 => "secp256r1", 384 => "secp384r1", _ => "secp521r1" };
                    return;
                }

                using var rsa = certificate.GetRSAPublicKey();
                if (rsa != null)
                {
                    description.KeyType = "rsa";
                    description.RsaKeyBits = rsa.KeySize;
                }
            }
            catch (Exception exp) when (exp is CryptographicException or IOException or UnauthorizedAccessException)
            {
                // the request keeps the default key type, which the preview shows
            }
        }

        /// <summary>
        /// A JSON Web Key (RFC 7517) private key as a PKCS#8 PEM key
        /// </summary>
        public static string ConvertJwkToPem(string jwkJson)
        {
            using var jwk = JsonDocument.Parse(jwkJson);
            var values = jwk.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : "", StringComparer.Ordinal);

            byte[] Get(string name, int length = 0)
            {
                if (!values.TryGetValue(name, out var text) || string.IsNullOrEmpty(text))
                {
                    throw new InvalidOperationException($"The account key has no {name} value.");
                }

                var bytes = Base64UrlDecode(text);

                // leading zero bytes are dropped by the encoding, but the key import needs the full length
                return length > bytes.Length ? new byte[length - bytes.Length].Concat(bytes).ToArray() : bytes;
            }

            switch (values.GetValueOrDefault("kty"))
            {
                case "RSA":
                    {
                        var modulus = Get("n");
                        var half = (modulus.Length + 1) / 2;

                        using var rsa = RSA.Create();
                        rsa.ImportParameters(new RSAParameters
                        {
                            Modulus = modulus,
                            Exponent = Get("e"),
                            D = Get("d", modulus.Length),
                            P = Get("p", half),
                            Q = Get("q", half),
                            DP = Get("dp", half),
                            DQ = Get("dq", half),
                            InverseQ = Get("qi", half)
                        });

                        return rsa.ExportPkcs8PrivateKeyPem();
                    }

                case "EC":
                    {
                        var (curve, size) = values.GetValueOrDefault("crv") switch
                        {
                            "P-256" => (ECCurve.NamedCurves.nistP256, 32),
                            "P-384" => (ECCurve.NamedCurves.nistP384, 48),
                            "P-521" => (ECCurve.NamedCurves.nistP521, 66),
                            var other => throw new InvalidOperationException($"The account key curve {other} is not supported.")
                        };

                        using var ec = ECDsa.Create(new ECParameters
                        {
                            Curve = curve,
                            D = Get("d", size),
                            Q = new ECPoint { X = Get("x", size), Y = Get("y", size) }
                        });

                        return ec.ExportPkcs8PrivateKeyPem();
                    }

                default:
                    throw new InvalidOperationException($"The account key type {values.GetValueOrDefault("kty")} is not supported.");
            }
        }

        /// <summary>
        /// A PEM RSA or EC private key, in any of the PKCS#1, SEC 1 or PKCS#8 forms, as a PKCS#8 PEM key
        /// </summary>
        public static string NormalizeKeyPem(string pem)
        {
            if (pem.Contains("EC PRIVATE KEY", StringComparison.Ordinal))
            {
                using var ec = ECDsa.Create();
                ec.ImportFromPem(pem);
                return ec.ExportPkcs8PrivateKeyPem();
            }

            try
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(pem);
                return rsa.ExportPkcs8PrivateKeyPem();
            }
            catch (CryptographicException)
            {
                // a PKCS#8 EC key
                using var ec = ECDsa.Create();
                ec.ImportFromPem(pem);
                return ec.ExportPkcs8PrivateKeyPem();
            }
        }

        public static byte[] Base64UrlDecode(string value)
        {
            var text = value.Trim().Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '='));
        }

        public static string FileHash(byte[] content) => Convert.ToHexString(SHA256.HashData(content));

        /// <summary>
        /// True if a process of one of the names is running. Errors listing processes count as not running
        /// </summary>
        public static bool IsProcessRunning(params string[] names)
        {
            try
            {
                return names.Any(n => Process.GetProcessesByName(n).Any());
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// DNS validation described through a catalogue alias, from a tool's option values
    /// </summary>
    internal static class MigrationDns
    {
        private static readonly HashSet<string> FalseValues = new(StringComparer.OrdinalIgnoreCase) { "", "false", "0", "no", "off" };

        /// <param name="options">the tool's option values, which are inspected but never stored</param>
        /// <param name="addSecret">records an option's value as a secret, returning its key</param>
        /// <param name="addFileSecret">records the content of the file at a path as a secret, returning its key</param>
        /// <param name="describeAmbient">how the tool authenticates when an ambient authentication option is set</param>
        public static void Describe(SourceValidation validation, DnsProviderAlias alias, IEnumerable<KeyValuePair<string, string>> options,
            Func<string, string> addSecret, Func<string, string> addFileSecret, Func<string, string> describeAmbient)
        {
            validation.Kind = SourceValidationKinds.Dns;
            validation.DnsProvider = alias.Key;
            validation.SourceName = MigrationCatalogue.GetDnsProvider(alias.Key)?.Title ?? alias.Key;

            foreach (var (option, value) in options)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                if (alias.AmbientAuthOptions.Contains(option, StringComparer.OrdinalIgnoreCase))
                {
                    if (!FalseValues.Contains(value.Trim()))
                    {
                        validation.AmbientAuthentication = describeAmbient(option);
                    }

                    continue;
                }

                if (alias.FileOptions.TryGetValue(option, out var fileParameter))
                {
                    validation.SecretParameters[fileParameter] = addFileSecret(value);
                    continue;
                }

                if (!alias.Options.TryGetValue(option, out var parameter))
                {
                    validation.UnmappedOptions.Add(option);
                    continue;
                }

                if (parameter.Length == 0)
                {
                    continue;
                }

                if (alias.ValueMaps.TryGetValue(parameter, out var values))
                {
                    // a setting such as an algorithm or cloud name, which is not secret
                    if (values.TryGetValue(value.Trim(), out var mapped))
                    {
                        validation.Parameters[parameter] = mapped;
                    }
                    else
                    {
                        validation.Notes.Add($"{option} {value} is not recognised, so {values.Values.First()} is assumed.");
                        validation.Parameters[parameter] = values.Values.First();
                    }

                    continue;
                }

                validation.SecretParameters[parameter] = addSecret(option);
            }
        }
    }

    /// <summary>
    /// Scripts written at import so this instance can run a source's own commands the way the source ran them
    /// </summary>
    internal static class MigrationScripts
    {
        public static string WrapperPath(string tool, string itemName, string name, string extension)
        {
            var folder = Path.Combine(EnvironmentUtil.EnsuredAppDataPath(), "scripts", "migrated");
            Directory.CreateDirectory(folder);

            var safeName = string.Concat($"{tool}-{itemName}-{name}".Select(c => char.IsLetterOrDigit(c) || c is '-' or '.' or '_' ? c : '_'));
            return Path.Combine(folder, safeName + extension);
        }

        private static string PowerShellQuote(string? value) => $"'{(value ?? "").Replace("'", "''")}'";

        /// <summary>
        /// A PowerShell deployment task script which runs a shell command (cmd on Windows, sh elsewhere) after each
        /// renewal, with environment variables set from the renewal result
        /// </summary>
        /// <param name="environment">variable name and a PowerShell expression for its value, which can use $item (the managed certificate)</param>
        public static string WriteCommandTask(string path, string header, string command, IEnumerable<(string Name, string Expression)> environment)
        {
            var variables = string.Join("\n", environment.Select(e => $"$psi.EnvironmentVariables[{PowerShellQuote(e.Name)}] = [string]({e.Expression})"));

            var content = $@"# {header}
param($result)

$item = $result.ManagedItem
$command = {PowerShellQuote(command)}

$psi = New-Object System.Diagnostics.ProcessStartInfo
if ($IsLinux -or $IsMacOS) {{
    $psi.FileName = '/bin/sh'
    $psi.Arguments = '-c ""' + $command.Replace('\', '\\').Replace('""', '\""') + '""'
}} else {{
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = '/c ' + $command
}}
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
{variables}

$process = [System.Diagnostics.Process]::Start($psi)
$output = $process.StandardOutput.ReadToEndAsync()
$errors = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()

if ($output.Result) {{ Write-Output $output.Result }}
if ($process.ExitCode -ne 0) {{ throw ""$command exited with code $($process.ExitCode). $($errors.Result)"" }}
";

            File.WriteAllText(path, content);
            return path;
        }

        /// <summary>
        /// A script for the script DNS provider here, which runs it with "{identifier} {record name} {record value}
        /// {zone id}", that runs the source's hook command with the environment variables the source gave it
        /// </summary>
        /// <param name="environment">variable name and value, which can use $IDENTIFIER (without a leading *.), $RECORD and $VALUE</param>
        public static string WriteDnsHook(string pathWithoutExtension, string header, string command, IEnumerable<(string Name, string Value)> environment)
        {
            string path;
            var content = new StringBuilder();

            if (OperatingSystem.IsWindows())
            {
                path = pathWithoutExtension + ".cmd";
                content.Append($"@echo off\r\nrem {header}\r\nsetlocal\r\nset \"IDENTIFIER=%~1\"\r\nif \"%IDENTIFIER:~0,2%\"==\"*.\" set \"IDENTIFIER=%IDENTIFIER:~2%\"\r\nset \"RECORD=%~2\"\r\nset \"VALUE=%~3\"\r\n");

                foreach (var (name, value) in environment)
                {
                    content.Append($"set \"{name}={value.Replace("$IDENTIFIER", "%IDENTIFIER%").Replace("$RECORD", "%RECORD%").Replace("$VALUE", "%VALUE%")}\"\r\n");
                }

                content.Append($"{command}\r\nexit /b %ERRORLEVEL%\r\n");
            }
            else
            {
                path = pathWithoutExtension + ".sh";
                content.Append($"#!/bin/sh\n# {header}\nIDENTIFIER=\"${{1#\\*.}}\"\nRECORD=\"$2\"\nVALUE=\"$3\"\n");

                foreach (var (name, value) in environment)
                {
                    content.Append($"{name}=\"{value}\"\nexport {name}\n");
                }

                content.Append($"exec /bin/sh -c '{command.Replace("'", "'\\''")}'\n");
            }

            File.WriteAllText(path, content.ToString());

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
            }

            return path;
        }
    }
}
