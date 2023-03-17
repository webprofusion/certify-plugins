using Certify.Models.Config;
using Certify.Models.Providers;
using Plugin.DeploymentTasks.Core.Shared.Model;
using SimpleImpersonation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;

namespace Certify.Providers.Deployment.Core.Shared
{
    public class WindowsNetworkFileClient
    {
        private UserCredentials _credentials;
        private LogonType _defaultLogonType = LogonType.NewCredentials;

        public WindowsNetworkFileClient(UserCredentials credentials)
        {
            _credentials = credentials;
        }

        public List<string> ListFiles(string remoteDirectory)
        {
            var fileList = new List<string>();

            using (var userHandle = _credentials.LogonUser(_defaultLogonType))
            {
                WindowsIdentity.RunImpersonated(userHandle, () =>
                 {
                     fileList.AddRange(Directory.GetFiles(remoteDirectory));
                 });
            }

            return fileList;
        }

        public List<ActionResult> CopyLocalToRemote(ILog log, List<FileCopy> filesSrcDest)
        {
            // read source files as original user
            var destFiles = new Dictionary<string, byte[]>();
            foreach (var item in filesSrcDest)
            {
                var content = File.ReadAllBytes(item.SourcePath);
                destFiles.Add(item.DestinationPath, content);
            }

            return CopyLocalToRemote(log, destFiles);
        }

        public List<ActionResult> CopyLocalToRemote(ILog log, Dictionary<string, byte[]> destFiles)
        {
            if (_credentials == null)
            {
                // cannot impersonate without credentials, attempt as current user
                var results = PerformFileWrites(log, destFiles);
                return results;
            }
            else
            {
                // write new files as destination user
                try
                {
                    using (var userHandle = _credentials.LogonUser(_defaultLogonType))
                    {
                        var results = WindowsIdentity.RunImpersonated(userHandle, () =>
                          {
                              return PerformFileWrites(log, destFiles);
                          });

                        return results;
                    }
                }
                catch (Exception exp)
                {
                    return new List<ActionResult> { new ActionResult(exp.Message, false) };
                }
            }
        }

        private static List<ActionResult> PerformFileWrites(ILog log, Dictionary<string, byte[]> destFiles)
        {
            var results = new List<ActionResult>();

            foreach (var dest in destFiles)
            {
                var destPath = dest.Key;
                try
                {
                    destPath = Path.GetFullPath(dest.Key);

                    // get the file attributes for existing file or directory
                    if (File.Exists(destPath))
                    {
                        var attr = File.GetAttributes(destPath);

                        if (attr.HasFlag(FileAttributes.Directory))
                        {
                            throw new Exception("Cannot write file to a directory name. Please specify the full file path.");
                        }
                    }

                }
                catch (Exception exp)
                {
                    var msg = "Failed to copy to destination file: " + destPath + ": " + exp.Message;
                    log.Error(msg);
                    results.Add(new ActionResult(msg, false));
                    break;
                }

                try
                {
                    // For this to succeed the user must have write permissions to the share and the underlying folder
                    File.WriteAllBytes(dest.Key, dest.Value);

                    log.Information("File Copy completed: " + destPath);
                }
                catch (Exception exp)
                {
                    var msg = "Failed to copy to destination file: " + destPath + ":" + exp.Message;
                    log.Error(msg);
                    results.Add(new ActionResult(msg, false));
                    break;
                }
            }

            return results;
        }
    }
}
