using System;
using System.Threading;
using System.Threading.Tasks;

namespace Certify.Datastore
{
    /// <summary>
    /// Serialises a data store's operations within this process. Hold the lock with a using statement on the result of
    /// Acquire, which is the only way to release it, so it is released once and only by the operation that acquired it.
    /// </summary>
    internal sealed class DbMutex
    {
        private static readonly TimeSpan _maxWait = TimeSpan.FromSeconds(10);

        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Wait for the lock. A wait that times out throws rather than letting the operation proceed unlocked.
        /// </summary>
        public async Task<IDisposable> Acquire()
        {
            if (!await _semaphore.WaitAsync(_maxWait).ConfigureAwait(false))
            {
                throw new TimeoutException($"Timed out after {_maxWait.TotalSeconds}s waiting for another data store operation to complete.");
            }

            return new Releaser(_semaphore);
        }

        private sealed class Releaser : IDisposable
        {
            private SemaphoreSlim _semaphore;

            public Releaser(SemaphoreSlim semaphore)
            {
                _semaphore = semaphore;
            }

            public void Dispose()
            {
                Interlocked.Exchange(ref _semaphore, null)?.Release();
            }
        }
    }
}
