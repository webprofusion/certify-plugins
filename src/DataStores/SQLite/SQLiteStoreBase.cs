using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Providers;
using Microsoft.Data.Sqlite;
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
        protected string _customDbFileName = null;
        protected string _connectionString;
        protected AsyncRetryPolicy _retryPolicy;
        protected ILog _log;
        private bool _initialised = false;

        public bool IsSingleInstanceMode { get; set; } = true; //if true, access to this resource is centralised so we can make assumptions about when reload of settings is required etc

        public SQLiteStoreBase()
        {

        }

        /// <summary>
        /// Default dn file is manageditems.db, this allows override for other uses
        /// </summary>
        /// <param name="name"></param>
        public void SetCustomDbFileName(string name)
        {
            _customDbFileName = name;
        }

        public SQLiteStoreBase(string storageSubfolder = null, ILog log = null, string customDbFileName = null)
        {
            if (customDbFileName != null)
            {
                _customDbFileName = customDbFileName;
            }

            Init(storageSubfolder, log, performBackup: false);
        }

        public bool Init(string storageSubfolder, ILog log, string instanceId = null)
        {
            return Init(storageSubfolder, log, performBackup: false);
        }

        public bool Init(string storageSubfolder, ILog log, bool performBackup = false)
        {
            _log = log;

            _retryPolicy = Policy
                .Handle<SqliteException>()
                .Or<ArgumentException>()
                .Or<InvalidOperationException>()
                .WaitAndRetryAsync(3, i => TimeSpan.FromSeconds(1), onRetry: (exception, retryCount, context) =>
                {
                    _log?.Warning($"Retrying DB operation..{retryCount} {exception}");
                });

            if (!string.IsNullOrEmpty(storageSubfolder))
            {
                _storageSubFolder = storageSubfolder;
            }

            _dbPath = GetDbPath();

            _connectionString = $"Data Source={_dbPath};";

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

                using (var db = new SqliteConnection(_connectionString))
                {
                    db.Open();

                    using (var walCmd = db.CreateCommand())
                    {
                        // checkpoint (commit transaction log to main db file) and truncate log to reduce size
                        // then run VACUUM to defragment db and reduce size

                        walCmd.CommandText =
                            @"
                        PRAGMA wal_checkpoint(TRUNCATE);
                        VACUUM;
                        ";

                        walCmd.ExecuteNonQuery();
                    }

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
                using (var db = new SqliteConnection(_connectionString))
                {
                    db.Open();

                    using (var walCmd = db.CreateCommand())
                    {
                        // Enable WRITE AHEAD LOGGING to allow concurrent reads and writes
                        walCmd.CommandText = "PRAGMA journal_mode = 'wal';";

                        walCmd.ExecuteNonQuery();
                    }

                    db.Close();
                }
            }
            catch (SqliteException exp)
            {
                // Check for readonly error (SQLITE_READONLY = 8)
                if (exp.SqliteErrorCode == 8)
                {
                    _log?.Error($"Encountered a read only database. A backup of the original database was recently performed to {_dbPath}.bak, you should revert to this backup.");
                }
            }
        }

        protected string GetDbPath()
        {
            var appDataPath = EnvironmentUtil.EnsuredAppDataPath(_storageSubFolder);
            return Path.Combine(appDataPath, $"{_customDbFileName ?? ITEMMANAGERCONFIG}.db");
        }

        private void PerformDBBackup()
        {
            try
            {
                if (File.Exists(_dbPath))
                {
                    using (var db = new SqliteConnection(_connectionString))
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
                            using (var backupDB = new SqliteConnection($"Data Source ={backupFile}"))
                            {
                                backupDB.Open();

                                // Microsoft.Data.Sqlite doesn't have BackupDatabase method, so we'll use SQL VACUUM INTO
                                using (var cmd = new SqliteCommand($"VACUUM INTO '{backupFile}'", db))
                                {
                                    cmd.ExecuteNonQuery();
                                }

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
            catch (SqliteException exp)
            {
                _log?.Error("Failed to perform db backup: " + exp);
            }

            // clear connection pool to release file locks
            SqliteConnection.ClearAllPools();
        }

        public async Task Delete(string id, string itemType)
        {
            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                // delete specific item
                using (var db = new SqliteConnection(_connectionString))
                {
                    await db.OpenAsync();
                    using (var tran = db.BeginTransaction())
                    {
                        using (var cmd = new SqliteCommand($"DELETE FROM manageditem WHERE id=@id AND itemtype=@itemtype", db))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqliteParameter("@id", id));
                            cmd.Parameters.Add(new SqliteParameter("@itemtype", itemType.ToLowerInvariant()));
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

            using (var db = new SqliteConnection(_connectionString))
            {
                await db.OpenAsync();
                try
                {
                    using (var cmd = new SqliteCommand("PRAGMA table_info(manageditem);", db))
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

                    if (!cols.Contains("itemtype"))
                    {
                        EnsurePermanentBackupBeforeItemTypeMigration(db);
                    }

                    if (cols.Contains("json"))
                    {
                        using (var cmd = new SqliteCommand("ALTER TABLE manageditem RENAME COLUMN json TO config;", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    if (!cols.Contains("itemtype"))
                    {
                        using (var cmd = new SqliteCommand($"ALTER TABLE manageditem ADD COLUMN itemtype TEXT NOT NULL DEFAULT 'managedcertificate';", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    if (!cols.Contains("itemvalue"))
                    {
                        using (var cmd = new SqliteCommand("ALTER TABLE manageditem ADD COLUMN itemvalue TEXT NULL;", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    if (cols.Contains("parentid"))
                    {
                        using (var cmd = new SqliteCommand("ALTER TABLE manageditem DROP COLUMN parentid;", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    //migrate legacy securityprinciple items TODO: can be removed post-beta

                    try
                    {
                        using (var cmd = new SqliteCommand("UPDATE manageditem SET id=replace(id,'securityprinciple','securityprincipal') WHERE id like 'securityprinciple%';", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }
                    catch
                    {
                        // remove any failing items ebcuase they clash on id
                        using (var cmd = new SqliteCommand("DELETE FROM manageditem WHERE id like 'securityprinciple%';", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    using (var cmd = new SqliteCommand("UPDATE manageditem SET itemtype='securityprincipal' WHERE itemtype ='securityprinciple';", db))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }

                    using (var cmd = new SqliteCommand("UPDATE manageditem SET config=replace(config,'Principle','Principal') WHERE config like '%Principle%';", db))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }

                    using (var cmd = new SqliteCommand("UPDATE manageditem SET config=replace(config,'principle','principal') WHERE config like '%principle%';", db))
                    {
                        await cmd.ExecuteNonQueryAsync();
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

        private void EnsurePermanentBackupBeforeItemTypeMigration(SqliteConnection db)
        {
            var permanentBackupFile = $"{_dbPath}.old";

            if (File.Exists(permanentBackupFile))
            {
                _log?.Information($"Permanent pre-itemtype schema backup already exists at {permanentBackupFile}.");
                return;
            }

            try
            {
                var escapedBackupFile = permanentBackupFile.Replace("'", "''");

                using (var cmd = new SqliteCommand($"VACUUM INTO '{escapedBackupFile}'", db))
                {
                    cmd.ExecuteNonQuery();
                }

                _log?.Warning($"Created permanent pre-itemtype schema backup at {permanentBackupFile} before applying schema migration.");
            }
            catch (Exception exp)
            {
                _log?.Error(exp, "Failed to create permanent pre-itemtype schema backup at {backupFile}", permanentBackupFile);
                throw;
            }
        }

        protected async Task CreateManagedItemsSchema()
        {

            try
            {
                using (var db = new SqliteConnection(_connectionString))
                {
                    await db.OpenAsync();
                    using (var cmd = new SqliteCommand("CREATE TABLE manageditem (id TEXT NOT NULL UNIQUE PRIMARY KEY, itemtype TEXT NOT NULL, config TEXT NOT NULL, itemvalue TEXT NULL)", db))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                _log?.Error(ex, "Failed to create managed items schema");
                throw;
            }
        }
    }
}
