using Certify.Models;
using Certify.Models.Providers;
using Certify.Providers;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using Polly;
using Polly.Retry;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Datastore.SQLServer
{

    public class SQLServerManagedItemStore : IManagedItemStore, IDisposable
    {
        private readonly ILog _log;
        private readonly string _connectionString;
        private readonly AsyncRetryPolicy _retryPolicy = Policy.Handle<Exception>()
                                            .WaitAndRetryAsync(3, i => TimeSpan.FromSeconds(1), onRetry: (exception, retryCount, context) =>
                                            {
                                                System.Diagnostics.Debug.WriteLine($"Retrying..{retryCount} {exception}");
                                            });

        public SQLServerManagedItemStore(string connectionString = null, ILog log = null)
        {

            _log = log;
            _connectionString = connectionString;
        }

        public async Task Delete(ManagedCertificate item)
        {
            _log?.Warning("Deleting managed item", item);

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
        }

        public async Task DeleteAll()
        {
            _log?.Warning("Deleting all managed items");

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

        public async Task DeleteByName(string nameStartsWith)
        {
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

        public void Dispose()
        {

        }

        public async Task<List<ManagedCertificate>> Find(ManagedCertificateFilter filter)
        {
            var managedCertificates = new List<ManagedCertificate>();

            var sql = @"SELECT * FROM (SELECT id, config, JSON_VALUE(config, '$.Name') as Name FROM manageditem) i ";

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
                queryParameters.Add(new SqlParameter("@ocspCheckDate", DateTime.Now.AddMinutes((int)-filter.LastOCSPCheckMins).ToUniversalTime()));
            }

            if (filter.LastRenewalInfoCheckMins != null)
            {
                conditions.Add(" CAST(JSON_VALUE(i.config, '$.DateLastRenewalInfoCheck')  AS datetimeoffset(7)) < @renewalInfoCheckDate");
                queryParameters.Add(new SqlParameter("@renewalInfoCheckDate", DateTime.Now.AddMinutes((int)-filter.LastRenewalInfoCheckMins).ToUniversalTime()));
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
                bool isFirstCondition = true;
                foreach (var c in conditions)
                {
                    sql += (!isFirstCondition ? " AND " + c : c);

                    isFirstCondition = false;
                }
            }

            sql += $" ORDER BY Name ASC";

            if (filter?.PageIndex != null && filter?.PageSize != null)
            {
                sql += $" OFFSET {filter.PageIndex * filter.PageSize} ROWS FETCH NEXT {filter.PageSize} ROWS ONLY;";
            }
            else if (filter?.MaxResults > 0)
            {
                sql += $" OFFSET 0 ROWS FETCH NEXT {filter.MaxResults} ROWS ONLY;";
            } 

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

            return managedCertificates;
        }

        public async Task<ManagedCertificate> GetById(string itemId)
        {
            ManagedCertificate managedCertificate = null;

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

            return managedCertificate;
        }

        public async Task<bool> IsInitialised()
        {
            _log?.Warning("SQL Server: IsInitialised not implemented");
            // TODO: open connection and check for read/write
            return await Task.FromResult(true);
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
            if (managedCertificate == null)
            {
                return null;
            }

            if (managedCertificate.Id == null)
            {
                managedCertificate.Id = Guid.NewGuid().ToString();
            }

            managedCertificate.Version++;

            if (managedCertificate.Version == long.MaxValue)
            {
                // rollover version, unlikely but accomodate it anyway
                managedCertificate.Version = -1;
            }

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

            return managedCertificate;
        }
    }
}
