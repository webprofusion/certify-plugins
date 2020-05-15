using System;
using System.Collections.Generic;
using System.IO;
using Certify.Config;
using Certify.Models.Providers;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace Certify.Providers.Deployment.Core.Shared
{
    public class SshConnectionConfig
    {
        public string Host { get; set; }
        public int Port { get; set; } = 22;

        public string Username { get; set; }
        public string Password { get; set; }
        public string PrivateKeyPath { get; set; }
        public string KeyPassphrase { get; set; }
    }

    public class CommandResult
    {
        public string Command { get; set; }
        public string Result { get; set; }
        public bool IsError { get; set; }
    }

    public class SshClient
    {
        SshConnectionConfig _config;

        public SshClient(SshConnectionConfig config)
        {
            _config = config;
        }

        public static SshConnectionConfig GetConnectionConfig(DeploymentTaskConfig config, Dictionary<string, string> credentials)
        {
            var sshConfig = new SshConnectionConfig
            {
                Host = config.TargetHost,
            };

            credentials.TryGetValue("username", out var username);
            if (username != null)
            {
                sshConfig.Username = username;
            }

            credentials.TryGetValue("password", out var password);
            if (password != null)
            {
                sshConfig.Password = password;
            }

            credentials.TryGetValue("privatekey", out var privatekey);
            if (privatekey != null)
            {
                sshConfig.PrivateKeyPath = privatekey;
            }

            credentials.TryGetValue("key_passphrase", out var passphrase);
            if (passphrase != null)
            {
                sshConfig.KeyPassphrase = passphrase;
            }
            return sshConfig;
        }

        private static PrivateKeyFile GetPrivateKeyFile(SshConnectionConfig config)
        {
            PrivateKeyFile pk;
            if (!string.IsNullOrEmpty(config.KeyPassphrase))
            {
                pk = new PrivateKeyFile(config.PrivateKeyPath, config.KeyPassphrase);
            }
            else
            {
                pk = new PrivateKeyFile(config.PrivateKeyPath);
            }
            return pk;
        }

        public static ConnectionInfo GetConnectionInfo(SshConnectionConfig config)
        {
            var authMethods = new List<AuthenticationMethod>();

            if (!string.IsNullOrEmpty(config.PrivateKeyPath))
            {
                // public key auth via private key
                var privateKey = GetPrivateKeyFile(config);
                var keyauth = new PrivateKeyAuthenticationMethod(config.Username, privateKey);
                authMethods.Add(keyauth);
            }

            if (!string.IsNullOrEmpty(config.Password))
            {

                // https://stackoverflow.com/questions/15686276/unable-to-connect-to-aixunix-box-with-ssh-net-library-error-value-cannot-b
                var kbdi = new KeyboardInteractiveAuthenticationMethod(config.Username);
                kbdi.AuthenticationPrompt += new EventHandler<AuthenticationPromptEventArgs>(
                    (Object sender, AuthenticationPromptEventArgs e) =>
                    {
                        foreach (AuthenticationPrompt prompt in e.Prompts)
                        {
                            if (prompt.Request.IndexOf("Password:", StringComparison.InvariantCultureIgnoreCase) != -1)
                            {
                                prompt.Response = config.Password;
                            }
                        }
                    });

                // password auth
                authMethods.Add(new PasswordAuthenticationMethod(config.Username, config.Password));

                // keyboard interactive auth
                authMethods.Add(kbdi);
            }

            // TODO : proxy support?
            return new ConnectionInfo(config.Host, config.Port, config.Username, authMethods.ToArray());
        }

        public List<CommandResult> ExecuteCommands(List<string> commands, ILog log)
        {

            var results = new List<CommandResult>();

            var connectionInfo = GetConnectionInfo(_config);

            using (var ssh = new Renci.SshNet.SshClient(connectionInfo))
            {
                try
                {
                    ssh.Connect();

                    foreach (var command in commands)
                    {
                        try
                        {
                            var cmd = ssh.RunCommand(command);

                            results.Add(new CommandResult { Command = command, Result = cmd.Result, IsError = false });
                        }
                        catch (Exception exp)
                        {
                            results.Add(new CommandResult { Command = command, Result = exp.ToString(), IsError = true });
                            break;
                        }
                    }

                    ssh.Disconnect();
                }
                catch (Exception e)
                {
                    log?.Error($"SShClient :: Error executing command {e}");
                }
            }

            return results;
        }

    }
}
