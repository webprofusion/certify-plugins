using System;
using System.Collections.Generic;
using System.Text;

namespace Plugin.DeploymentTasks.Core.Shared.Model
{
    public class FileCopy
    {
        public string SourcePath { get; set; }
        public byte[] SourceBytes { get; set; }
        public string DestinationPath { get; set; }
    }
}
