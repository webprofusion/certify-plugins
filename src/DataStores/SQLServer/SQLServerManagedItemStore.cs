using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Models.Reporting;
using Certify.Providers;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using Polly;
using Polly.Retry;

namespace Certify.Datastore.SQLServer
{

    public class SQLServerManagedItemStore : IManagedItemStore, IDisposable
    {
        private const string _itemType = "managedcertificate";

        private ILog _log;
        private string _connectionString;
        private string _instanceId = "";
        private AsyncRetryPolicy _retryPolicy;

        private static readonly SemaphoreSlim _dbMutex = new SemaphoreSlim(1);
        private const int _semaphoreMaxWaitMS = 10 * 1000;

        private JsonSerializerSettings _jsonSerializerSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Ignore
        };

        public static ProviderDefinition Definition =>
            new ProviderDefinition
            {
                Id = "Plugin.DataStores.ManagedItem.SQLServer",
                ProviderCategoryId = "sqlserver",
                Title = "SQL Server",
                Description = "SQL Server DataStore provider"
            };

        public bool Init(string connectionString, ILog log, string instanceId = null)
        {
            _connectionString = connectionString;
            _log = log;
            _instanceId = instanceId ?? "";

            _retryPolicy = Policy
                    .Handle<ArgumentException>()
                    .Or<SqlException>()
                    .WaitAndRetryAsync(3, i => TimeSpan.FromSeconds(1), onRetry: (exception, retryCount, context) =>
                    {
                        _log?.Warning($"Retrying DB operation..{retryCount} {exception}");
                    });

            // Perform schema upgrade on init
            UpgradeSchema().Wait();

            return true;
        }

        public SQLServerManagedItemStore() { }

        public SQLServerManagedItemStore(string connectionString = null, ILog log = null, string instanceId = null)
        {
            Init(connectionString, log, instanceId);
        }

        /// <summary>
        /// Upgrade the database schema to support itemtype column
        /// </summary>
        private async Task<bool> UpgradeSchema()
        {
            if (string.IsNullOrEmpty(_connectionString))
            {
                return false;
            }

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    // Check if itemtype column exists
                    var cols = new List<string>();
                    using (var cmd = new SqlCommand(
                        "SELECT c.name FROM sys.columns c WHERE c.object_id = OBJECT_ID('manageditem')", conn))
                    {
                        using (var reader = await cmd.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                cols.Add(reader.GetString(0).ToLowerInvariant());
                            }
                        }
                    }

                    // Rename 'json' column to 'config' if it exists (legacy)
                    if (cols.Contains("json") && !cols.Contains("config"))
                    {
                        using (var cmd = new SqlCommand("EXEC sp_rename 'manageditem.json', 'config', 'COLUMN';", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }

                        _log?.Information("SQL Server: Renamed 'json' column to 'config'");
                    }

                    // Add itemtype column if it doesn't exist
                    if (!cols.Contains("itemtype"))
                    {
                        using (var cmd = new SqlCommand(
                            "ALTER TABLE manageditem ADD itemtype NVARCHAR(100) NOT NULL DEFAULT 'managedcertificate';", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }

                        _log?.Information("SQL Server: Added 'itemtype' column");
                    }

                    // Add itemvalue column if it doesn't exist
                    if (!cols.Contains("itemvalue"))
                    {
                        using (var cmd = new SqlCommand(
                            "ALTER TABLE manageditem ADD itemvalue NVARCHAR(MAX) NULL;", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }

                        _log?.Information("SQL Server: Added 'itemvalue' column");
                    }

                    // Update existing records to have correct itemtype
                    using (var cmd = new SqlCommand(
                        "UPDATE manageditem SET itemtype = 'managedcertificate' WHERE itemtype IS NULL OR itemtype = '';", conn))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }

                    // Create index on itemtype for query performance
                    try
                    {
                        using (var cmd = new SqlCommand(@"
                            IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_itemtype' AND object_id = OBJECT_ID('manageditem'))
                            BEGIN
                                CREATE INDEX idx_manageditem_itemtype ON manageditem(itemtype);
                            END", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }
                    catch (SqlException)
                    {
                        // Index may already exist
                    }

                    // Add instanceid column if it doesn't exist
                    if (!cols.Contains("instanceid"))
                    {
                        using (var cmd = new SqlCommand(
                            "ALTER TABLE manageditem ADD instanceid NVARCHAR(64) NOT NULL DEFAULT '';", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }

                        try
                        {
                            using (var cmd = new SqlCommand(@"
                                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_instanceid' AND object_id = OBJECT_ID('manageditem'))
                                BEGIN
                                    CREATE INDEX idx_manageditem_instanceid ON manageditem(instanceid);
                                END", conn))
                            {
                                await cmd.ExecuteNonQueryAsync();
                            }
                        }
                        catch (SqlException)
                        {
                            // Index may already exist
                        }

                        _log?.Information("SQL Server: Added 'instanceid' column");
                    }

                    if (!string.IsNullOrEmpty(_instanceId))
                    {
                        using (var cmd = new SqlCommand(
                            "UPDATE manageditem SET instanceid = @instanceid WHERE instanceid IS NULL OR instanceid = '';", conn))
                        {
                            cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    conn.Close();
                }

                return true;
            }
            catch (Exception ex)
            {
                _log?.Error($"SQL Server: Schema upgrade failed: {ex.Message}");
                return false;
            }
            finally
            {
                _dbMutex.Release();
            }
        }

        public async Task Delete(ManagedCertificate item)
        {
            _log?.Warning("Deleting managed item", item);

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                await _retryPolicy.ExecuteAsync(async () =>
                {
                    using (var conn = new SqlConnection(_connectionString))
                    {
                        await conn.OpenAsync();
                        using (var tran = conn.BeginTransaction())
                        {
                            using (var cmd = new SqlCommand("DELETE FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", item.Id));
                                cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                await cmd.ExecuteNonQueryAsync();

                                tran.Commit();
                            }
                        }

                        conn.Close();

                    }
                });
            }
            finally
            {
                _dbMutex.Release();
            }
        }

        public async Task DeleteAll()
        {
            _log?.Warning("Deleting all managed items");

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    using (var cmd = new SqlCommand("DELETE FROM manageditem WHERE itemtype=@itemtype AND instanceid=@instanceid", conn))
                    {
                        cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                        cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                        await cmd.ExecuteNonQueryAsync();
                    }

                    conn.Close();
                }
            }
            finally
            {
                _dbMutex.Release();
            }
        }

        public async Task DeleteByName(string nameStartsWith)
        {
            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                using (var db = new SqlConnection(_connectionString))
                {
                    await db.OpenAsync();
                    using (var tran = db.BeginTransaction())
                    {
                        using (var cmd = new SqlCommand("DELETE FROM manageditem WHERE itemtype=@itemtype AND instanceid=@instanceid AND JSON_VALUE(config, '$.Name') LIKE @nameStartsWith + '%' ", db))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                            cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                            cmd.Parameters.Add(new SqlParameter("@nameStartsWith", nameStartsWith));
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

        public void Dispose()
        {

        }

        private (string sql, List<SqlParameter> queryParameters) BuildQuery(ManagedCertificateFilter filter, bool countMode)
        {
            var sql = @"SELECT * FROM (
                        SELECT id, config, JSON_VALUE(config, '$.Name') as [Name], 
                        CAST(JSON_VALUE(config, '$.DateRenewed') AS datetimeoffset(7)) as [DateRenewed], 
                        CAST(JSON_VALUE(config, '$.DateLastRenewalAttempt') AS datetimeoffset(7)) as [DateLastRenewalAttempt] ,
                        CAST(JSON_VALUE(config, '$.DateExpiry') AS datetimeoffset(7)) as [DateExpiry] 
            FROM manageditem WHERE itemtype = @itemtype AND instanceid = @instanceid) i ";

            if (countMode)
            {
                sql = @"SELECT COUNT(1) as numItems FROM(SELECT id, config, JSON_VALUE(config, '$.Name') as Name FROM manageditem WHERE itemtype = @itemtype AND instanceid = @instanceid) i ";
            }

            var queryParameters = new List<SqlParameter>();
            queryParameters.Add(new SqlParameter("@itemtype", _itemType));
            queryParameters.Add(new SqlParameter("@instanceid", _instanceId));

            var conditions = new List<string>();

            if (!string.IsNullOrEmpty(filter.Id))
            {
                conditions.Add(" i.id = @id");
                queryParameters.Add(new SqlParameter("@id", filter.Id));
            }

            if (!string.IsNullOrEmpty(filter.Name))
            {
                conditions.Add(" Name LIKE @name"); // case insensitive string match
                queryParameters.Add(new SqlParameter("@name", filter.Name));
            }

            if (!string.IsNullOrEmpty(filter.Keyword))
            {
                conditions.Add(" ((Name LIKE '%' + @keyword + '%') OR (JSON_VALUE(i.config, '$.Comments') LIKE '%' + @keyword + '%'))"); // case insensitive string contains
                queryParameters.Add(new SqlParameter("@keyword", filter.Keyword));
            }

            if (filter.LastOCSPCheckMins != null)
            {
                conditions.Add(" CAST(JSON_VALUE(i.config, '$.DateLastOcspCheck')  AS datetimeoffset(7)) < @ocspCheckDate");
                queryParameters.Add(new SqlParameter("@ocspCheckDate", DateTime.UtcNow.AddMinutes((int)-filter.LastOCSPCheckMins)));
            }

            if (filter.LastRenewalInfoCheckMins != null)
            {
                conditions.Add(" CAST(JSON_VALUE(i.config, '$.DateLastRenewalInfoCheck')  AS datetimeoffset(7)) < @renewalInfoCheckDate");
                queryParameters.Add(new SqlParameter("@renewalInfoCheckDate", DateTime.UtcNow.AddMinutes((int)-filter.LastRenewalInfoCheckMins)));
            }

            if (filter.ChallengeType != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM OPENJSON(config,'$.RequestConfig.Challenges') WHERE JSON_VALUE(value,'$.ChallengeType')=@challengeType)");
                queryParameters.Add(new SqlParameter("@challengeType", filter.ChallengeType));
            }

            if (filter.ChallengeProvider != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM OPENJSON(config,'$.RequestConfig.Challenges') WHERE JSON_VALUE(value,'$.ChallengeProvider')=@challengeProvider)");
                queryParameters.Add(new SqlParameter("@challengeProvider", filter.ChallengeProvider));
            }

            if (filter.StoredCredentialKey != null)
            {
                conditions.Add(" EXISTS (SELECT 1 FROM OPENJSON(config,'$.RequestConfig.Challenges') WHERE JSON_VALUE(value,'$.ChallengeCredentialKey')=@challengeCredentialKey)");
                queryParameters.Add(new SqlParameter("@challengeCredentialKey", filter.StoredCredentialKey));
            }

            if (filter.Health != null)
            {
                if (filter.Health.ToLower() == "ok")
                {
                    conditions.Add($" (JSON_VALUE(i.config, '$.LastRenewalStatus') = '{(int)RequestState.Success}' OR JSON_VALUE(i.config, '$.LastRenewalStatus') IS NULL) ");
                }
                else if (filter.Health.ToLower() == "nocertificate")
                {
                    conditions.Add(" (JSON_VALUE(i.config, '$.DateExpiry') IS NULL) ");
                }
                else if (filter.Health.ToLower() == "paused")
                {
                    conditions.Add($" (JSON_VALUE(i.config, '$.LastRenewalStatus') = '{(int)RequestState.Paused}') ");
                }
                else if (filter.Health.ToLower() == "warning" || filter.Health.ToLower() == "error")
                {
                    conditions.Add($" (JSON_VALUE(i.config, '$.LastRenewalStatus') = '{(int)RequestState.Error}') ");
                }
            }

            if (filter.IncludeOnlyNextAutoRenew == true)
            {
                conditions.Add(" (JSON_VALUE(i.config, '$.IncludeInAutoRenew') = 'true') ");
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
                if (filter.OrderBy == ManagedCertificateFilter.SortMode.NAME_ASC)
                {
                    sql += $" ORDER BY Name ASC";
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

            var (sql, queryParameters) = BuildQuery(filter, countMode: true);

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                await _retryPolicy.ExecuteAsync(async () =>
                {

                    using (var db = new SqlConnection(_connectionString))
                    using (var cmd = new SqlCommand(sql, db))
                    {
                        cmd.Parameters.AddRange(queryParameters.ToArray());

                        await db.OpenAsync();
                        count = Convert.ToInt64(await cmd.ExecuteScalarAsync());

                        db.Close();
                    }
                });
            }
            finally
            {
                _dbMutex.Release();
            }

            Debug.WriteLine($"CountAll[SQL Server] took {watch.ElapsedMilliseconds}ms for {count} records");

            return count;
        }

        public async Task<List<ManagedCertificate>> Find(ManagedCertificateFilter filter)
        {
            var managedCertificates = new List<ManagedCertificate>();

            var (sql, queryParameters) = BuildQuery(filter, countMode: false);

            if (filter?.PageIndex != null && filter?.PageSize != null)
            {
                sql += $" OFFSET {filter.PageIndex * filter.PageSize} ROWS FETCH NEXT {filter.PageSize} ROWS ONLY;";
            }
            else if (filter?.MaxResults > 0)
            {
                sql += $" OFFSET 0 ROWS FETCH NEXT {filter.MaxResults} ROWS ONLY;";
            }

            await _retryPolicy.ExecuteAsync(async () =>
            {
                using (var conn = new SqlConnection(_connectionString))
                {

                    await conn.OpenAsync();

                    using (var cmd = new SqlCommand(sql, conn))
                    {
                        cmd.Parameters.AddRange(queryParameters.ToArray());

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
                                    _log?.Debug("SQL Server: Corrected managed item id: " + managedCertificate.Name);
                                }

                                managedCertificates.Add(managedCertificate);
                            }
                        }
                    }

                    conn.Close();
                }
            });

            return managedCertificates;
        }

        public async Task<ManagedCertificate> GetById(string itemId)
        {
            ManagedCertificate managedCertificate = null;

            await _retryPolicy.ExecuteAsync(async () =>
            {
                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();
                    using (var cmd = new SqlCommand("SELECT config FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                    {
                        cmd.Parameters.Add(new SqlParameter("@id", itemId));
                        cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                        cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));

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

                    conn.Close();
                }
            });

            return managedCertificate;
        }

        public async Task<bool> IsInitialised()
        {

            const string sql = @"SELECT TOP 1 * from manageditem;";
            var queryOK = false;
            try
            {
                await _retryPolicy.ExecuteAsync(async () =>
                {
                    using (var conn = new SqlConnection(_connectionString))
                    {
                        await conn.OpenAsync();

                        using (var cmd = new SqlCommand(sql, conn))
                        {
                            await cmd.ExecuteReaderAsync();
                            queryOK = true;
                        }

                        conn.Close();
                    }
                });
            }
            catch (Exception ex)
            {
                _log?.Error("Failed to init data store: " + ex.Message);
            }

            return await Task.FromResult(queryOK);

        }

        public Task PerformMaintenance()
        {
            _log?.Warning("SQL Server: Maintenance not implemented");
            return Task.CompletedTask;
        }

        public async Task StoreAll(IEnumerable<ManagedCertificate> list)
        {
            foreach (var item in list)
            {
                await Update(item);
            }
        }

        public async Task<ManagedCertificate> Update(ManagedCertificate managedCertificate)
        {
            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                if (managedCertificate == null)
                {
                    return null;
                }

                if (managedCertificate.Id == null)
                {
                    managedCertificate.Id = Guid.NewGuid().ToString();
                }

                await _retryPolicy.ExecuteAsync(async () =>
                {
                    using (var conn = new SqlConnection(_connectionString))
                    {
                        await conn.OpenAsync();

                        ManagedCertificate current = null;

                        // get current version from DB
                        using (var tran = conn.BeginTransaction())
                        {
                            using (var cmd = new SqlCommand("SELECT config FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", managedCertificate.Id));
                                cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));

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

                                try
                                {
                                    using (var cmd = new SqlCommand("UPDATE manageditem SET config = @config WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                                    {
                                        cmd.Transaction = tran;

                                        cmd.Parameters.Add(new SqlParameter("@id", managedCertificate.Id));
                                        cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                                        cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                        cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(managedCertificate, _jsonSerializerSettings)));

                                        await cmd.ExecuteNonQueryAsync();
                                    }

                                    tran.Commit();
                                }
                                catch (SqlException exp)
                                {
                                    tran.Rollback();
                                    _log?.Error(exp.ToString());
                                    throw;
                                }
                            }
                            else
                            {

                                try
                                {
                                    using (var cmd = new SqlCommand("INSERT INTO manageditem(id, itemtype, instanceid, config) VALUES(@id, @itemtype, @instanceid, @config)", conn))
                                    {
                                        cmd.Transaction = tran;
                                        cmd.Parameters.Add(new SqlParameter("@id", managedCertificate.Id));
                                        cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                                        cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                        cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(managedCertificate, _jsonSerializerSettings)));

                                        await cmd.ExecuteNonQueryAsync();
                                    }

                                    tran.Commit();
                                }
                                catch (SqlException exp)
                                {
                                    tran.Rollback();
                                    _log?.Error(exp.ToString());
                                    throw;
                                }
                            }
                        }

                        conn.Close();
                    }
                });
                return managedCertificate;
            }
            finally
            {
                _dbMutex.Release();
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
