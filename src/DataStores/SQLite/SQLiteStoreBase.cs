using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Providers;
using Polly;
using Polly.Retry;

namespace Certify.Datastore.SQLite
{
    public class SQLiteStoreBase
    {
        public const string ITEMMANAGERCONFIG = "manageditems";
        protected const int _semaphoreMaxWaitMS = 10 * 1000;
        protected static readonly SemaphoreSlim _dbMutex = new SemaphoreSlim(1);

        protected string _storageSubFolder = ""; //if specified will be appended to AppData path as subfolder to load/save to

        /// <summary>
        /// path to storage db, actual path is determined on init
        /// </summary>
        protected string _dbPath = $"C:\\programdata\\certify\\{ITEMMANAGERCONFIG}.db";
        protected string _connectionString;
        protected AsyncRetryPolicy _retryPolicy;
        protected ILog _log;
        private bool _initialised = false;

        public bool IsSingleInstanceMode { get; set; } = true; //if true, access to this resource is centralised so we can make assumptions about when reload of settings is required etc

        public SQLiteStoreBase()
        {

        }

        public SQLiteStoreBase(string storageSubfolder = null, ILog log = null)
        {
            Init(storageSubfolder, log);
        }

        public bool Init(string storageSubfolder, ILog log)
        {
            return Init(storageSubfolder, log, performBackup: false);
        }

        public bool Init(string storageSubfolder, ILog log, bool performBackup = false)
        {
            _log = log;

            _retryPolicy = Policy
                    .Handle<ArgumentException>()
                    .WaitAndRetryAsync(3, i => TimeSpan.FromSeconds(1), onRetry: (exception, retryCount, context) =>
                    {
                        _log.Warning($"Retrying DB operation..{retryCount} {exception}");
                    });

            if (!string.IsNullOrEmpty(storageSubfolder))
            {
                _storageSubFolder = storageSubfolder;
            }

            _dbPath = GetDbPath();

            _connectionString = $"Data Source={_dbPath};PRAGMA journal_mode=WAL;";

            try
            {
                if (File.Exists(_dbPath))
                {
                    // upgrade schema if db exists
                    var upgraded = UpgradeSchema().Result;
                }
                else
                {
                    CreateManagedItemsSchema().Wait();
                }

                if (performBackup)
                {
                    PerformDBBackup();
                }

                //enable write ahead logging mode
                EnableDBWriteAheadLogging();

                _initialised = true;
            }
            catch (Exception exp)
            {
                var msg = "Failed to initialise item manager. Database may be inaccessible. " + exp;
                _log?.Error(msg);

                _initialised = false;
            }

            return _initialised;
        }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        protected virtual async Task<bool> UpgradeSettings()
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
        {
            throw new NotImplementedException();
        }

        public Task<bool> IsInitialised()
        {
            return Task.FromResult(_initialised);
        }

        public Task PerformMaintenance()
        {
            try
            {
                PerformDBBackup();

                using (var db = new SQLiteConnection(_connectionString))
                {
                    db.Open();
                    var walCmd = db.CreateCommand();
                    walCmd.CommandText =
                    @"
                    PRAGMA wal_checkpoint(FULL);
                    VACUUM;
                ";
                    walCmd.ExecuteNonQuery();
                    db.Close();
                }
            }
            catch (Exception exp)
            {
                _log?.Error("An error occurred during database maintenance. Check storage free space and disk IO. " + exp);
            }

            return Task.CompletedTask;
        }

        private void EnableDBWriteAheadLogging()
        {
            try
            {
                using (var db = new SQLiteConnection(_connectionString))
                {
                    db.Open();
                    var walCmd = db.CreateCommand();
                    walCmd.CommandText =
                    @"
                    PRAGMA journal_mode = 'wal';
                ";
                    walCmd.ExecuteNonQuery();
                    db.Close();
                }
            }
            catch (SQLiteException exp)
            {
                if (exp.ResultCode == SQLiteErrorCode.ReadOnly)
                {
                    _log?.Error($"Encountered a read only database. A backup of the original database was recently performed to {_dbPath}.bak, you should revert to this backup.");
                }
            }
        }

        protected string GetDbPath()
        {
            var appDataPath = EnvironmentUtil.EnsuredAppDataPath(_storageSubFolder);
            return Path.Combine(appDataPath, $"{ITEMMANAGERCONFIG}.db");
        }

        private void PerformDBBackup()
        {
            try
            {
                if (File.Exists(_dbPath))
                {
                    using (var db = new SQLiteConnection(_connectionString))
                    {
                        db.Open();

                        var backupFile = $"{_dbPath}.bak";
                        try
                        {
                            // archive previous backup if it looks valid
                            if (File.Exists(backupFile) && new System.IO.FileInfo(backupFile).Length > 1024)
                            {

                                File.Copy($"{_dbPath}.bak", $"{_dbPath}.bak.old", true);
                            }

                            // remove previous backup (invalid backups can be corrupt and cause subsequent backups to fail)
                            if (File.Exists(backupFile))
                            {
                                File.Delete(backupFile);
                            }

                            // create new backup

                            using (var backupDB = new SQLiteConnection($"Data Source ={backupFile}"))
                            {
                                backupDB.Open();
                                db.BackupDatabase(backupDB, "main", "main", -1, null, 1000);
                                backupDB.Close();

                                _log?.Information($"Performed db backup to {backupFile}. To switch to the backup, rename the old manageditems.db file and rename the .bak file as manageditems.db, then restart service to recover. ");
                            }
                        }
                        catch (Exception exp)
                        {
                            _log?.Error($"Failed to performed db backup to {backupFile}. Check file permissions and delete old file if there is a conflict. " + exp.ToString());

                        }

                        db.Close();
                    }
                }
            }
            catch (SQLiteException exp)
            {
                _log?.Error("Failed to perform db backup: " + exp);
            }
        }

        public async Task Delete(string id, string itemType)
        {
            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);
                // save modified items into settings database
                using (var db = new SQLiteConnection(_connectionString))
                {
                    await db.OpenAsync();
                    using (var tran = db.BeginTransaction())
                    {
                        using (var cmd = new SQLiteCommand($"DELETE FROM manageditem WHERE id=@id AND @itemtype=itemtype", db))
                        {
                            cmd.Parameters.Add(new SQLiteParameter("@id", id));
                            cmd.Parameters.Add(new SQLiteParameter("@itemtype", itemType.ToLowerInvariant()));
                            await cmd.ExecuteNonQueryAsync();
                        }

                        tran.Commit();
                    }

                    db.Close();
                }
            }
            finally
            {
                _dbMutex.Release();
            }
        }

        private async Task<bool> UpgradeSchema()
        {
            // attempt column upgrades
            var cols = new List<string>();

            using (var db = new SQLiteConnection(_connectionString))
            {
                await db.OpenAsync();
                try
                {
                    using (var cmd = new SQLiteCommand("PRAGMA table_info(manageditem);", db))
                    {

                        using (var reader = await cmd.ExecuteReaderAsync())
                        {

                            while (await reader.ReadAsync())
                            {
                                var colname = (string)reader["name"];
                                cols.Add(colname);
                            }
                        }
                    }

                    // perform any further schema checks and upgrades..

                    if (cols.Contains("json"))
                    {
                        using (var cmd = new SQLiteCommand("ALTER TABLE manageditem RENAME COLUMN json TO config;", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    if (!cols.Contains("itemtype"))
                    {
                        using (var cmd = new SQLiteCommand($"ALTER TABLE manageditem ADD COLUMN itemtype TEXT NOT NULL DEFAULT 'managedcertificate';", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    if (!cols.Contains("itemvalue"))
                    {
                        using (var cmd = new SQLiteCommand("ALTER TABLE manageditem ADD COLUMN itemvalue TEXT NULL;", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    if (cols.Contains("parentid"))
                    {
                        using (var cmd = new SQLiteCommand("ALTER TABLE manageditem DROP COLUMN parentid;", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }
                }
                catch (Exception exp)
                {
                    _log?.Error(exp, "Error during schema upgrade");
                    // error checking for upgrade, ensure table exists
                    await CreateManagedItemsSchema();

                    return false;
                }
            }

            return true;
        }

        protected async Task CreateManagedItemsSchema()
        {

            try
            {
                using (var db = new SQLiteConnection(_connectionString))
                {
                    await db.OpenAsync();
                    using (var cmd = new SQLiteCommand("CREATE TABLE manageditem (id TEXT NOT NULL UNIQUE PRIMARY KEY, itemtype TEXT NOT NULL, config TEXT NOT NULL, itemvalue TEXT NULL)", db))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }

                    db.Close();
                }
            }
            catch { }
        }
    }
}
