using Certify.Models.Providers;
using Certify.Providers.DeploymentTasks;
using Plugin.DeploymentTasks.Core.Shared.Model;
using Renci.SshNet.Common;
using System;
using System.Collections.Generic;
using System.IO;

namespace Certify.Providers.Deployment.Core.Shared
{

    public class SftpClient
    {
        private SshConnectionConfig _config;

        public SftpClient(SshConnectionConfig config)
        {
            _config = config;
        }

        public bool CopyLocalToRemote(List<FileCopy> filesSrcDest, ILog log)
        {
            // read source files as original user
            var destFiles = new Dictionary<string, byte[]>();
            foreach (var item in filesSrcDest)
            {
                var content = File.ReadAllBytes(item.SourcePath);
                destFiles.Add(item.DestinationPath, content);
            }

            return CopyLocalToRemote(destFiles, log);
        }

        public bool CopyLocalToRemote(Dictionary<string, byte[]> files, ILog log)
        {

            var isSuccess = true;

            // upload new files as destination user

            var connectionInfo = SshClient.GetConnectionInfo(_config);

            using (var sftp = new Renci.SshNet.SftpClient(connectionInfo))
            {
                try
                {
                    sftp.Connect();

                    foreach (var dest in files)
                    {
                        try
                        {
                            sftp.WriteAllBytes(dest.Key, dest.Value);
                        }
                        catch (SftpPathNotFoundException exp)
                        {
                            // path not found, folder is probably wrong
                            log?.Error($"SftpClient :: Failed to copy file. Check that the full path to {dest} is valid and that 'sudo' is not required to perform file copy. {exp}");

                            // failed to copy the file. TODO: retries
                            isSuccess = false;
                            break;
                        }
                        catch (Exception exp)
                        {

                            log?.Error($"SftpClient :: Failed to perform CopyLocalToRemote [{connectionInfo.Host}:{connectionInfo.Port}]: {exp}");

                            // failed to copy the file. TODO: retries
                            isSuccess = false;
                            break;
                        }
                    }
                    sftp.Disconnect();
                }
                catch (Exception exp)
                {
                    isSuccess = false;
                    log?.Error($"SftpClient :: Failed to perform CopyLocalToRemote [{connectionInfo.Host}:{connectionInfo.Port}]: {exp}");
                }
            }

            return isSuccess;
        }


        /// <summary>
        /// List a remote directory in the console.
        /// </summary>
        public List<string> ListFiles(string remoteDirectory, ILog log)
        {
            var connectionInfo = SshClient.GetConnectionInfo(_config);

            var fileList = new List<string>();

            using (var sftp = new Renci.SshNet.SftpClient(connectionInfo))
            {
                try
                {
                    sftp.Connect();

                    var files = sftp.ListDirectory(remoteDirectory);

                    foreach (var file in files)
                    {
                        fileList.Add(file.Name);
                    }

                    sftp.Disconnect();
                }
                catch (Renci.SshNet.Common.SshConnectionException e)
                {
                    throw new RemoteConnectionException(e.Message, e);
                }
                catch (Exception e)
                {
                    log?.Error($"SftpClient.ListFiles :: Error listing files {e}");
                }
            }
            return fileList;
        }

    }
}
