using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using Polly;
using Polly.Retry;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Certify.Datastore.SQLServer
{

    public class SQLServerManagedItemStore : IManagedItemStore, IDisposable
    {
        private ILog _log;
        private string _connectionString;
        private AsyncRetryPolicy _retryPolicy;

        private static readonly SemaphoreSlim _dbMutex = new SemaphoreSlim(1);
        private const int _semaphoreMaxWaitMS = 10 * 1000;

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "Plugin.DataStores.ManagedItem.SQLServer",
                    ProviderCategoryId = "sqlserver",
                    Title = "SQL Server",
                    Description = "SQL Server DataStore provider"
                };
            }
        }

        public bool Init(string connectionString, ILog log)
        {
            _connectionString = connectionString;
            _log = log;

            _retryPolicy = Policy
                    .Handle<ArgumentException>()
                    .WaitAndRetryAsync(3, i => TimeSpan.FromSeconds(1), onRetry: (exception, retryCount, context) =>
                    {
                        _log.Warning($"Retrying DB operation..{retryCount} {exception}");
                    });

            return true;
        }

        public SQLServerManagedItemStore() { }

        public SQLServerManagedItemStore(string connectionString = null, ILog log = null)
        {
            Init(connectionString, log);
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
                            using (var cmd = new SqlCommand("DELETE FROM manageditem WHERE id=@id", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", item.Id));
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

                    using (var cmd = new SqlCommand("DELETE FROM manageditem", conn))
                    {
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
                        using (var cmd = new SqlCommand("DELETE FROM manageditem WHERE JSON_VALUE(config, '$.Name') LIKE @nameStartsWith + '%' ", db))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqlParameter("@nameStartsWith", nameStartsWith));
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

        public void Dispose()
        {

        }

        public (string sql, List<SqlParameter> queryParameters) BuildQuery(ManagedCertificateFilter filter, bool countMode)
        {
            var sql = @"SELECT * FROM (
                        SELECT id, config, JSON_VALUE(config, '$.Name') as [Name], 
                        CAST(JSON_VALUE(config, '$.DateRenewed') AS datetimeoffset(7)) as [DateRenewed], 
                        CAST(JSON_VALUE(config, '$.DateLastRenewalAttempt') AS datetimeoffset(7)) as [DateLastRenewalAttempt] ,
                        CAST(JSON_VALUE(config, '$.DateExpiry') AS datetimeoffset(7)) as [DateExpiry] 
            FROM manageditem) i ";

            if (countMode)
            {
                sql = @"SELECT COUNT(1) as numItems FROM(SELECT id, config, JSON_VALUE(config, '$.Name') as Name FROM manageditem) i ";
            }

            var queryParameters = new List<SqlParameter>();
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
                conditions.Add(" (Name LIKE '%' + @keyword + '%')"); // case insensitive string contains
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

            (string sql, List<SqlParameter> queryParameters) = BuildQuery(filter, countMode: true);

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
                        count = (int)await cmd.ExecuteScalarAsync();

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

            (string sql, List<SqlParameter> queryParameters) = BuildQuery(filter, countMode: false);

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
                    using (var cmd = new SqlCommand("SELECT config FROM manageditem WHERE id=@id", conn))
                    {
                        cmd.Parameters.Add(new SqlParameter("@id", itemId));

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

            var sql = @"SELECT TOP 1 * from manageditem;";
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
                _log.Error("Failed to init data store: " + ex.Message);
            }

            return await Task.FromResult(queryOK);

        }

        public async Task PerformMaintenance()
        {
            _log?.Warning("SQL Server: Maintenance not implemented");

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
                            using (var cmd = new SqlCommand("SELECT config FROM manageditem WHERE id=@id", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", managedCertificate.Id));

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
                                    using (var cmd = new SqlCommand("UPDATE manageditem SET config = @config WHERE id=@id", conn))
                                    {
                                        cmd.Transaction = tran;

                                        cmd.Parameters.Add(new SqlParameter("@id", managedCertificate.Id));
                                        cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(managedCertificate, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore })));

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
                                    using (var cmd = new SqlCommand("INSERT INTO manageditem(id,config) VALUES(@id,@config)", conn))
                                    {
                                        cmd.Transaction = tran;
                                        cmd.Parameters.Add(new SqlParameter("@id", managedCertificate.Id));
                                        cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(managedCertificate, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore })));

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
    }
}
