using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;
using Polly;
using Polly.Retry;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Certify.Datastore.SQLite
{
    /// <summary>
    /// SQLiteItemManager is the storage service implementation for Managed Certificate information using SQLite
    /// This provider features use of semaphore and retry policies as the underlying SQLite file database is susceptible to interference/locking from external apps like windows real-time protection etc.
    /// </summary>
    public class SQLiteManagedItemStore : IManagedItemStore
    {
        public const string ITEMMANAGERCONFIG = "manageditems";

        private string _storageSubFolder = ""; //if specified will be appended to AppData path as subfolder to load/save to
        public bool IsSingleInstanceMode { get; set; } = true; //if true, access to this resource is centralised so we can make assumptions about when reload of settings is required etc

        // TODO: make db path configurable on service start
        private string _dbPath = $"C:\\programdata\\certify\\{ITEMMANAGERCONFIG}.db";
        private string _connectionString;

        private AsyncRetryPolicy _retryPolicy;

        private static readonly SemaphoreSlim _dbMutex = new SemaphoreSlim(1);
        private const int _semaphoreMaxWaitMS = 10 * 1000;

        private ILog _log;

        private bool _initialised { get; set; } = false;
        private bool _highPerformanceMode { get; set; } = false;

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "Plugin.DataStores.ManagedItem.SQLite",
                    ProviderCategoryId = "sqlite",
                    Title = "SQLite",
                    Description = "SQLite DataStore provider"
                };
            }
        }

        public bool Init(string connectionString, ILog log)
        {
            var storageSubfolder = connectionString;

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

            _connectionString = $"Data Source={_dbPath};PRAGMA temp_store=MEMORY;Cache=Shared;PRAGMA journal_mode=WAL;";

            if (_highPerformanceMode)
            {
                // for tests only, not suitable for production. https://www.sqlite.org/faq.html#q19
                _connectionString += "PRAGMA synchronous=OFF;";
            }

            try
            {
                if (!_highPerformanceMode)
                {
                    if (File.Exists(_dbPath))
                    {
                        // upgrade schema if db exists
                        var upgraded = UpgradeSchema().Result;
                    }
                    else
                    {
                        // upgrade from JSON storage if db doesn't exist yet
                        var settingsUpgraded = UpgradeSettings().Result;
                    }

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

        public SQLiteManagedItemStore() { }
        public SQLiteManagedItemStore(string storageSubfolder = null, ILog log = null, bool highPerformanceMode = false)
        {
            _highPerformanceMode = highPerformanceMode;
            Init(storageSubfolder, log);
        }

        public Task<bool> IsInitialised()
        {
            return Task.FromResult(_initialised);
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

            return Task.FromResult(true);
        }

        private string GetDbPath()
        {
            var appDataPath = EnvironmentUtil.GetAppDataFolder(_storageSubFolder);
            return Path.Combine(appDataPath, $"{ITEMMANAGERCONFIG}.db");
        }

        private async Task CreateManagedItemsSchema()
        {

            try
            {
                using (var db = new SQLiteConnection(_connectionString))
                {
                    await db.OpenAsync();
                    using (var cmd = new SQLiteCommand("CREATE TABLE manageditem (id TEXT NOT NULL UNIQUE PRIMARY KEY, json TEXT NOT NULL)", db))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }

                    db.Close();
                }
            }
            catch { }
        }

        /// <summary>
        /// Perform a full backup and save of the current set of managed sites
        /// </summary>
        public async Task StoreAll(IEnumerable<ManagedCertificate> list)
        {
            var watch = Stopwatch.StartNew();

            // create database if it doesn't exist
            if (!File.Exists(_dbPath))
            {
                await CreateManagedItemsSchema();
            }

            // save all new/modified items into settings database

            using (var db = new SQLiteConnection(_connectionString))
            {

                await db.OpenAsync();
                using (var tran = db.BeginTransaction())
                {
                    foreach (var item in list)
                    {
                        using (var cmd = new SQLiteCommand("INSERT OR REPLACE INTO manageditem (id, json) VALUES (@id, @json)", db))
                        {
                            cmd.Parameters.Add(new SQLiteParameter("@id", item.Id));
                            cmd.Parameters.Add(new SQLiteParameter("@json", JsonConvert.SerializeObject(item)));
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    tran.Commit();
                }
            }

            Debug.WriteLine($"StoreSettings[SQLite] took {watch.ElapsedMilliseconds}ms for {list.Count()} records");
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
                }
                catch
                {
                    // error checking for upgrade, ensure table exists
                    await CreateManagedItemsSchema();

                    return false;
                }
            }

            return true;
        }
        public async Task DeleteAll()
        {
            var items = await Find(ManagedCertificateFilter.ALL);
            foreach (var item in items)
            {
                await Delete(item);
            }
        }

        public (string sql, List<SQLiteParameter> queryParameters) BuildQuery(ManagedCertificateFilter filter, bool countMode)
        {
            var sql = @"SELECT i.id, i.json, i.json ->> 'Name' as Name FROM manageditem i ";

            if (countMode)
            {
                sql = "SELECT COUNT (1) as numItems, i.json ->> 'Name' as Name  FROM manageditem i ";
            }

            var queryParameters = new List<SQLiteParameter>();
            var conditions = new List<string>();

            if (!string.IsNullOrEmpty(filter.Id))
            {
                conditions.Add(" i.id = @id");
                queryParameters.Add(new SQLiteParameter("@id", filter.Id));
            }

            if (!string.IsNullOrEmpty(filter.Name))
            {
                conditions.Add(" Name LIKE @name"); // case insensitive string match
                queryParameters.Add(new SQLiteParameter("@name", filter.Name));
            }

            if (!string.IsNullOrEmpty(filter.Keyword))
            {
                conditions.Add(" (Name LIKE '%' || @keyword || '%')"); // case insensitive string contains
                queryParameters.Add(new SQLiteParameter("@keyword", filter.Keyword));
            }

            if (filter.LastOCSPCheckMins != null)
            {
                conditions.Add(" datetime(i.json ->> 'DateLastOcspCheck') < @ocspCheckDate");
                queryParameters.Add(new SQLiteParameter("@ocspCheckDate", DateTime.Now.AddMinutes((int)-filter.LastOCSPCheckMins).ToUniversalTime()));
            }

            if (filter.LastRenewalInfoCheckMins != null)
            {
                conditions.Add(" datetime(i.json ->> 'DateLastRenewalInfoCheck') < @renewalInfoCheckDate");
                queryParameters.Add(new SQLiteParameter("@renewalInfoCheckDate", DateTime.Now.AddMinutes((int)-filter.LastRenewalInfoCheckMins).ToUniversalTime()));
            }

            if (filter.ChallengeType != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM json_each(i.json -> 'RequestConfig' -> 'Challenges') challenges WHERE challenges.value->>'ChallengeType'=@challengeType)"); // challenges.value->>'ChallengeType'=@challengeType
                queryParameters.Add(new SQLiteParameter("@challengeType", filter.ChallengeType));
            }

            if (filter.ChallengeProvider != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM json_each(i.json -> 'RequestConfig' -> 'Challenges') challenges WHERE challenges.value->>'ChallengeProvider'=@challengeProvider)");
                queryParameters.Add(new SQLiteParameter("@challengeProvider", filter.ChallengeProvider));
            }

            if (filter.StoredCredentialKey != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM json_each(i.json -> 'RequestConfig' -> 'Challenges') challenges WHERE challenges.value->>'ChallengeCredentialKey'=@challengeCredentialKey)");
                queryParameters.Add(new SQLiteParameter("@challengeCredentialKey", filter.StoredCredentialKey));
            }

            if (conditions.Any())
            {
                sql += " WHERE ";
                var isFirstCondition = true;
                foreach (var c in conditions)
                {
                    sql += (!isFirstCondition ? " AND " + c : c);

                    isFirstCondition = false;
                }
            }

            if (!countMode)
            {
                sql += $" ORDER BY Name COLLATE NOCASE ASC";
            }

            return (sql, queryParameters);
        }

        public async Task<long> CountAll(ManagedCertificateFilter filter)
        {
            long count = 0;

            var watch = Stopwatch.StartNew();

            if (File.Exists(_dbPath))
            {
                (string sql, List<SQLiteParameter> queryParameters) = BuildQuery(filter, countMode: true);

                try
                {
                    await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                    await _retryPolicy.ExecuteAsync(async () =>
                    {
                        using (var db = new SQLiteConnection(_connectionString))
                        using (var cmd = new SQLiteCommand(sql, db))
                        {
                            cmd.Parameters.AddRange(queryParameters.ToArray());

                            await db.OpenAsync();
                            count = (long)await cmd.ExecuteScalarAsync();

                            db.Close();
                        }
                    });
                }
                finally
                {
                    _dbMutex.Release();
                }
            }

            Debug.WriteLine($"CountAll[SQLite] took {watch.ElapsedMilliseconds}ms for {count} records");

            return count;
        }

        private async Task<IEnumerable<ManagedCertificate>> LoadAllManagedCertificates(ManagedCertificateFilter filter)
        {
            var managedCertificates = new List<ManagedCertificate>();

            var watch = Stopwatch.StartNew();

            if (File.Exists(_dbPath))
            {
                (string sql, List<SQLiteParameter> queryParameters) = BuildQuery(filter, countMode: false);

                if (filter?.PageIndex != null && filter?.PageSize != null)
                {
                    sql += $" LIMIT {filter.PageSize} OFFSET {filter.PageIndex * filter.PageSize}";
                }
                else if (filter?.MaxResults > 0)
                {
                    sql += $" LIMIT {filter.MaxResults}";
                }

                try
                {
                    await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                    await _retryPolicy.ExecuteAsync(async () =>
                    {
                        using (var db = new SQLiteConnection(_connectionString))
                        using (var cmd = new SQLiteCommand(sql, db))
                        {
                            cmd.Parameters.AddRange(queryParameters.ToArray());

                            await db.OpenAsync();

                            using (var reader = await cmd.ExecuteReaderAsync())
                            {
                                while (await reader.ReadAsync())
                                {
                                    var itemId = (string)reader["id"];

                                    var managedCertificate = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["json"]);

                                    // in some cases users may have previously manipulated the id, causing
                                    // duplicates. Correct the ID here (database Id is unique):
                                    if (managedCertificate.Id != itemId)
                                    {
                                        managedCertificate.Id = itemId;
                                        Debug.WriteLine("LoadSettings: Corrected managed site id: " + managedCertificate.Name);
                                    }

                                    managedCertificates.Add(managedCertificate);
                                }

                                reader.Close();
                            }
                            db.Close();
                        }
                    });

                    foreach (var site in managedCertificates)
                    {
                        site.IsChanged = false;
                    }
                }
                finally
                {
                    _dbMutex.Release();
                }
            }

            Debug.WriteLine($"LoadAllManagedCertificates[SQLite] took {watch.ElapsedMilliseconds}ms for {managedCertificates.Count} records");
            return managedCertificates;
        }

        private async Task<bool> UpgradeSettings()
        {
            var appDataPath = EnvironmentUtil.GetAppDataFolder(_storageSubFolder);

            var json = Path.Combine(appDataPath, $"{ITEMMANAGERCONFIG}.json");
            var db = Path.Combine(appDataPath, $"{ITEMMANAGERCONFIG}.db");

            var managedCertificateList = new List<ManagedCertificate>();

            if (File.Exists(json) && !File.Exists(db))
            {
                var watch = Stopwatch.StartNew();

                // read managed sites using tokenize stream, this is useful for large files
                var serializer = new JsonSerializer();
                using (var sr = new StreamReader(json))
                using (var reader = new JsonTextReader(sr))
                {
                    managedCertificateList = serializer.Deserialize<List<ManagedCertificate>>(reader);

                    //safety check, if any dupe id's exists (which they shouldn't but the test data set did) make Id unique in the set.
                    var duplicateKeys = managedCertificateList.GroupBy(x => x.Id).Where(group => group.Count() > 1).Select(group => group.Key);
                    foreach (var dupeKey in duplicateKeys)
                    {
                        var count = 0;
                        foreach (var i in managedCertificateList.Where(m => m.Id == dupeKey))
                        {
                            i.Id = i.Id + "_" + count;
                            count++;
                        }
                    }

                    foreach (var site in managedCertificateList)
                    {
                        site.IsChanged = true;
                    }
                }

                await StoreAll(managedCertificateList); // upgrade to SQLite db storage
                File.Delete($"{json}.bak");
                File.Move(json, $"{json}.bak");
                Debug.WriteLine($"UpgradeSettings[Json->SQLite] took {watch.ElapsedMilliseconds}ms for {managedCertificateList.Count} records");
            }
            else
            {
                if (!File.Exists(db))
                {
                    // no setting to upgrade, create the empty database
                    await StoreAll(managedCertificateList);
                }
            }

            return true;
        }

        private async Task<ManagedCertificate> LoadManagedCertificate(string siteId)
        {
            ManagedCertificate managedCertificate = null;

            await _retryPolicy.ExecuteAsync(async () =>
            {
                using (var db = new SQLiteConnection(_connectionString))
                using (var cmd = new SQLiteCommand("SELECT json FROM manageditem WHERE id=@id", db))
                {
                    cmd.Parameters.Add(new SQLiteParameter("@id", siteId));

                    await db.OpenAsync();
                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            managedCertificate = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["json"]);
                            managedCertificate.IsChanged = false;
                        }

                        reader.Close();
                    }
                }
            });

            return managedCertificate;
        }

        public async Task<ManagedCertificate> GetById(string siteId)
        {
            return await LoadManagedCertificate(siteId);
        }

        public async Task<List<ManagedCertificate>> Find(ManagedCertificateFilter filter)
        {
            var items = await LoadAllManagedCertificates(filter);
            return items.ToList();
        }

        public async Task<ManagedCertificate> Update(ManagedCertificate managedCertificate)
        {
            if (managedCertificate == null)
            {
                return null;
            }

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                if (managedCertificate.Id == null)
                {
                    managedCertificate.Id = Guid.NewGuid().ToString();
                }

                await _retryPolicy.ExecuteAsync(async () =>
                {
                    using (var db = new SQLiteConnection(_connectionString))
                    {
                        await db.OpenAsync();

                        ManagedCertificate current = null;

                        // get current version from DB
                        using (var tran = db.BeginTransaction())
                        {
                            using (var cmd = new SQLiteCommand("SELECT json FROM manageditem WHERE id=@id", db))
                            {
                                cmd.Parameters.Add(new SQLiteParameter("@id", managedCertificate.Id));

                                using (var reader = await cmd.ExecuteReaderAsync())
                                {
                                    if (await reader.ReadAsync())
                                    {
                                        current = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["json"]);
                                        current.IsChanged = false;
                                    }

                                    reader.Close();
                                }
                            }

                            if (current != null)
                            {
                                managedCertificate.Version = current.Version + 1;

                                if (managedCertificate.Version == long.MaxValue)
                                {
                                    // rollover version, unlikely but accommodate it anyway
                                    managedCertificate.Version = -1;
                                }

                                if (managedCertificate.Version != -1 && current.Version >= managedCertificate.Version)
                                {
                                    // version conflict
                                    _log?.Error("Managed certificate DB version conflict - newer managed certificate version already stored.");
                                }
                            }

                            using (var cmd = new SQLiteCommand("INSERT OR REPLACE INTO manageditem (id, json) VALUES (@id,@json)", db))
                            {
                                cmd.Parameters.Add(new SQLiteParameter("@id", managedCertificate.Id));
                                cmd.Parameters.Add(new SQLiteParameter("@json", JsonConvert.SerializeObject(managedCertificate, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore })));

                                await cmd.ExecuteNonQueryAsync();
                            }

                            tran.Commit();
                        }

                        db.Close();
                    }
                });

            }
            finally
            {
                _dbMutex.Release();
            }

            return managedCertificate;
        }

        public async Task Delete(ManagedCertificate site)
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
                        using (var cmd = new SQLiteCommand("DELETE FROM manageditem WHERE id=@id", db))
                        {
                            cmd.Parameters.Add(new SQLiteParameter("@id", site.Id));
                            await cmd.ExecuteNonQueryAsync();
                        }

                        tran.Commit();
                    }
                }
            }
            finally
            {
                _dbMutex.Release();
            }
        }

        public async Task DeleteByName(string nameStartsWith)
        {
            using (var db = new SQLiteConnection(_connectionString))
            {
                await db.OpenAsync();
                using (var tran = db.BeginTransaction())
                {
                    using (var cmd = new SQLiteCommand("DELETE FROM manageditem WHERE json ->>'Name' LIKE @nameStartsWith || '%' ", db))
                    {
                        cmd.Parameters.Add(new SQLiteParameter("@nameStartsWith", nameStartsWith));
                        await cmd.ExecuteNonQueryAsync();
                    }

                    tran.Commit();
                }
            }
        }
    }
}
