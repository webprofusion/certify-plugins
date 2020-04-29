using System;

namespace Certify.Providers.DeploymentTasks
{
    /// <summary>
    /// An attempt to establish or use a remote connection has failed
    /// </summary>
    public class RemoteConnectionException : Exception
    {
        public RemoteConnectionException(string message)
       : base(message)
        {
        }

        public RemoteConnectionException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
