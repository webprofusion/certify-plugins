using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Models.Reporting;
using Certify.Providers;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace Certify.Datastore.SQLite
{
    /// <summary>
    /// SQLiteItemManager is the storage service implementation for Managed Certificate information using SQLite
    /// This provider features use of semaphore and retry policies as the underlying SQLite file database is susceptible to interference/locking from external apps like windows real-time protection etc.
    /// </summary>
    public class SQLiteManagedItemStore : SQLiteStoreBase, IManagedItemStore
    {
        private const string _itemType = "managedcertificate";

        public static ProviderDefinition Definition =>
            new ProviderDefinition
            {
                Id = "Plugin.DataStores.ManagedItem.SQLite",
                ProviderCategoryId = "sqlite",
                Title = "SQLite",
                Description = "SQLite DataStore provider"
            };

        private JsonSerializerSettings _jsonSerializerSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Ignore
        };

        public SQLiteManagedItemStore() { }
        public SQLiteManagedItemStore(string storageSubfolder = null, ILog log = null) : base(storageSubfolder, log) { }

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

            using (var db = new SqliteConnection(_connectionString))
            {

                await db.OpenAsync();
                using (var tran = db.BeginTransaction())
                {
                    foreach (var item in list)
                    {
                        using (var cmd = new SqliteCommand($"INSERT OR REPLACE INTO manageditem (id, itemtype, config) VALUES (@id, @itemtype, @config)", db))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqliteParameter("@id", item.Id));
                            cmd.Parameters.Add(new SqliteParameter("@itemtype", _itemType));
                            cmd.Parameters.Add(new SqliteParameter("@config", JsonConvert.SerializeObject(item)));
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    tran.Commit();
                }

                db.Close();
            }

            Debug.WriteLine($"StoreSettings[SQLite] took {watch.ElapsedMilliseconds}ms for {list.Count()} records");
        }

        public async Task DeleteAll()
        {
            var items = await Find(ManagedCertificateFilter.ALL);
            foreach (var item in items)
            {
                await Delete(item);
            }
        }

        public static (string sql, List<SqliteParameter> queryParameters) BuildQuery(ManagedCertificateFilter filter, bool countMode)
        {
            var sql = @"SELECT i.id, i.config, i.config ->> 'Name' as Name, 
                datetime(i.config ->> 'DateRenewed') as DateRenewed, 
                datetime(i.config ->> 'DateLastRenewalAttempt') as DateLastRenewalAttempt ,
                datetime(i.config ->> 'DateExpiry') as DateExpiry 
                FROM manageditem i ";

            if (countMode)
            {
                sql = "SELECT COUNT (1) as numItems, i.config ->> 'Name' as Name  FROM manageditem i ";
            }

            var queryParameters = new List<SqliteParameter>();
            var conditions = new List<string>();

            if (!string.IsNullOrEmpty(filter.Id))
            {
                conditions.Add(" i.id = @id");
                queryParameters.Add(new SqliteParameter("@id", filter.Id));
            }

            if (!string.IsNullOrEmpty(filter.Name))
            {
                conditions.Add(" Name LIKE @name"); // case insensitive string match
                queryParameters.Add(new SqliteParameter("@name", filter.Name));
            }

            if (!string.IsNullOrEmpty(filter.Keyword))
            {
                conditions.Add(" (Name LIKE '%' || @keyword || '%')"); // case insensitive string contains
                queryParameters.Add(new SqliteParameter("@keyword", filter.Keyword));
            }

            if (filter.LastOCSPCheckMins != null)
            {
                conditions.Add(" datetime(i.config ->> 'DateLastOcspCheck') < @ocspCheckDate");
                queryParameters.Add(new SqliteParameter("@ocspCheckDate", DateTime.UtcNow.AddMinutes((int)-filter.LastOCSPCheckMins).ToUniversalTime()));
            }

            if (filter.LastRenewalInfoCheckMins != null)
            {
                conditions.Add(" datetime(i.config ->> 'DateLastRenewalInfoCheck') < @renewalInfoCheckDate");
                queryParameters.Add(new SqliteParameter("@renewalInfoCheckDate", DateTime.UtcNow.AddMinutes((int)-filter.LastRenewalInfoCheckMins).ToUniversalTime()));
            }

            if (filter.ChallengeType != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM json_each(i.config -> 'RequestConfig' -> 'Challenges') challenges WHERE challenges.value->>'ChallengeType'=@challengeType)"); // challenges.value->>'ChallengeType'=@challengeType
                queryParameters.Add(new SqliteParameter("@challengeType", filter.ChallengeType));
            }

            if (filter.ChallengeProvider != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM json_each(i.config -> 'RequestConfig' -> 'Challenges') challenges WHERE challenges.value->>'ChallengeProvider'=@challengeProvider)");
                queryParameters.Add(new SqliteParameter("@challengeProvider", filter.ChallengeProvider));
            }

            if (filter.StoredCredentialKey != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM json_each(i.config -> 'RequestConfig' -> 'Challenges') challenges WHERE challenges.value->>'ChallengeCredentialKey'=@challengeCredentialKey)");
                queryParameters.Add(new SqliteParameter("@challengeCredentialKey", filter.StoredCredentialKey));
            }

            sql += $" WHERE itemtype=@itemtype ";

            queryParameters.Add(new SqliteParameter("@itemtype", _itemType));

            if (conditions.Any())
            {

                foreach (var c in conditions)
                {
                    sql += $" AND {c} ";
                }
            }

            if (!countMode)
            {
                if (filter.OrderBy == ManagedCertificateFilter.SortMode.NAME_ASC)
                {
                    sql += $" ORDER BY Name COLLATE NOCASE ASC";
                }
                else if (filter.OrderBy == ManagedCertificateFilter.SortMode.RENEWAL_ASC)
                {
                    sql += $" ORDER BY DateLastRenewalAttempt ASC";
                }
            }

            return (sql, queryParameters);
        }

        public async Task<long> CountAll(ManagedCertificateFilter filter)
        {
            long count = 0;

            var watch = Stopwatch.StartNew();

            if (File.Exists(_dbPath))
            {
                var (sql, queryParameters) = BuildQuery(filter, countMode: true);

                try
                {
                    await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                    await _retryPolicy.ExecuteAsync(async () =>
                    {
                        using (var db = new SqliteConnection(_connectionString))
                        using (var cmd = new SqliteCommand(sql, db))
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
                var (sql, queryParameters) = BuildQuery(filter, countMode: false);

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
                        using (var db = new SqliteConnection(_connectionString))
                        using (var cmd = new SqliteCommand(sql, db))
                        {
                            cmd.Parameters.AddRange(queryParameters.ToArray());

                            await db.OpenAsync();

                            using (var reader = await cmd.ExecuteReaderAsync())
                            {
                                while (await reader.ReadAsync())
                                {
                                    var itemId = (string)reader["id"];

                                    var managedCertificate = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["config"]);

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

        protected override async Task<bool> UpgradeSettings()
        {
            var appDataPath = EnvironmentUtil.EnsuredAppDataPath(_storageSubFolder);

            var json = Path.Combine(appDataPath, $"{_customDbFileName ?? ITEMMANAGERCONFIG}.json");
            var db = Path.Combine(appDataPath, $"{_customDbFileName ?? ITEMMANAGERCONFIG}.db");

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
                using (var db = new SqliteConnection(_connectionString))
                using (var cmd = new SqliteCommand("SELECT config FROM manageditem WHERE id=@id and itemtype=@itemtype", db))
                {
                    cmd.Parameters.Add(new SqliteParameter("@id", siteId));
                    cmd.Parameters.Add(new SqliteParameter("@itemtype", _itemType));

                    await db.OpenAsync();
                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            managedCertificate = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["config"]);
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
            return (await LoadAllManagedCertificates(filter)) as List<ManagedCertificate>;
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
                    using (var db = new SqliteConnection(_connectionString))
                    {
                        await db.OpenAsync();

                        ManagedCertificate current = null;

                        // get current version from DB
                        using (var tran = db.BeginTransaction())
                        {
                            using (var cmd = new SqliteCommand("SELECT config FROM manageditem WHERE id=@id AND itemtype=@itemtype", db))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqliteParameter("@id", managedCertificate.Id));
                                cmd.Parameters.Add(new SqliteParameter("@itemtype", _itemType));

                                using (var reader = await cmd.ExecuteReaderAsync())
                                {
                                    if (await reader.ReadAsync())
                                    {
                                        current = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["config"]);
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

                            using (var cmd = new SqliteCommand($"INSERT OR REPLACE INTO manageditem (id, itemtype, config) VALUES (@id, @itemtype, @config)", db))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqliteParameter("@id", managedCertificate.Id));
                                cmd.Parameters.Add(new SqliteParameter("@itemtype", _itemType));
                                cmd.Parameters.Add(new SqliteParameter("@config", JsonConvert.SerializeObject(managedCertificate, _jsonSerializerSettings)));

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
            await Delete(site.Id, _itemType);
        }

        public async Task DeleteByName(string nameStartsWith)
        {
            using (var db = new SqliteConnection(_connectionString))
            {
                await db.OpenAsync();
                using (var tran = db.BeginTransaction())
                {
                    using (var cmd = new SqliteCommand($"DELETE FROM manageditem WHERE itemtype=@itemtype AND config ->>'Name' LIKE @nameStartsWith || '%' ", db))
                    {
                        cmd.Transaction = tran;
                        cmd.Parameters.Add(new SqliteParameter("@itemtype", _itemType));
                        cmd.Parameters.Add(new SqliteParameter("@nameStartsWith", nameStartsWith));
                        await cmd.ExecuteNonQueryAsync();
                    }

                    tran.Commit();
                }

                db.Close();
            }
        }

        public async Task<StatusSummary> GetSummary(ManagedCertificateFilter filter)
        {
            var summary = new StatusSummary();

            summary.Total = (int)await CountAll(filter);
            return summary;
        }
    }
}
