using Certify.Models;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;
using Npgsql;
using Polly;
using Polly.Retry;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Datastore.Postgres
{
    public class PostgresItemManager : IManagedItemStore, IDisposable
    {
        private readonly ILog _log;
        private readonly string _connectionString;
        private readonly AsyncRetryPolicy _retryPolicy = Policy.Handle<ArgumentException>()
            .WaitAndRetryAsync(3, i => TimeSpan.FromSeconds(1), onRetry: (exception, retryCount, context) =>
            {
                System.Diagnostics.Debug.WriteLine($"Retrying..{retryCount} {exception}");
            });

        public PostgresItemManager(string connectionString = null, ILog log = null)
        {

            _log = log;
            _connectionString = connectionString;
        }

        public async Task Delete(ManagedCertificate item)
        {
            _log?.Warning("Deleting managed item", item);

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                await conn.OpenAsync();
                using (var tran = conn.BeginTransaction())
                {
                    using (var cmd = new NpgsqlCommand("DELETE FROM manageditem WHERE id=@id", conn))
                    {
                        cmd.Parameters.Add(new NpgsqlParameter("@id", item.Id));
                        await cmd.ExecuteNonQueryAsync();

                        tran.Commit();
                    }
                }
                await conn.CloseAsync();

            }
        }

        public async Task DeleteAll()
        {
            _log?.Warning("Deleting all managed items");

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                using (var cmd = new NpgsqlCommand("DELETE FROM manageditem", conn))
                {
                    await cmd.ExecuteNonQueryAsync();
                }

                await conn.CloseAsync();
            }
        }

        public async Task DeleteByName(string nameStartsWith)
        {
            var items = await Find(new ManagedCertificateFilter { Name = nameStartsWith });

            foreach (var item in items.Where(i => i.Name.StartsWith(nameStartsWith)))
            {
                await Delete(item);
            }
        }

        public void Dispose()
        {

        }

        public async Task<List<ManagedCertificate>> Find(ManagedCertificateFilter filter)
        {
            var managedCertificates = new List<ManagedCertificate>();

            var sql = "SELECT id, config FROM manageditem";
            var conditions = "";
            if (!string.IsNullOrEmpty(filter?.Keyword))
            {
                conditions += "config::jsonb ->> 'Name' LIKE '%'+@keyword+'%'";
            }

            if (!string.IsNullOrEmpty(conditions))
            {
                sql += " WHERE " + conditions;
            }

            if (filter?.PageIndex != null && filter?.PageSize != null)
            {
                sql += $" LIMIT {filter.PageSize} OFFSET {filter.PageIndex}";
                //sql += $" WHERE id NOT IN (SELECT id FROM manageditem ORDER BY id ASC LIMIT {filter.PageSize * filter.PageIndex}) ORDER BY id ASC LIMIT {filter.PageIndex}";
            }

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                using (var cmd = new NpgsqlCommand(sql, conn))
                {
                    if (!string.IsNullOrEmpty(filter?.Keyword))
                    {
                        cmd.Parameters.Add(new NpgsqlParameter("@keyword", filter.Keyword));
                    }

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
                                _log?.Debug("Postgres: Corrected managed item id: " + managedCertificate.Name);
                            }

                            managedCertificates.Add(managedCertificate);
                        }
                    }
                }
                await conn.CloseAsync();
            }

            return managedCertificates;
        }

        public async Task<ManagedCertificate> GetById(string itemId)
        {
            ManagedCertificate managedCertificate = null;

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                await conn.OpenAsync();
                using (var cmd = new NpgsqlCommand("SELECT config FROM manageditem WHERE id=@id", conn))
                {
                    cmd.Parameters.Add(new NpgsqlParameter("@id", itemId));

                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            managedCertificate = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["config"]);
                            managedCertificate.IsChanged = false;
                        }

                        await reader.CloseAsync();
                    }
                }
                await conn.CloseAsync();

            }

            return managedCertificate;
        }

        public async Task<bool> IsInitialised()
        {
            _log?.Warning("Postgres: IsInitialised not implemented");
            // TODO: open connection and check for read/write
            return await Task.FromResult(true);
        }

        public Task PerformMaintenance()
        {
            _log?.Warning("Postgres: Maintenance not implemented");
            return Task.CompletedTask;
        }

        public Task StoreAll(IEnumerable<ManagedCertificate> list)
        {
            throw new NotImplementedException();
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

            //await _retryPolicy.ExecuteAsync(async () =>
            {
                using (var conn = new NpgsqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    ManagedCertificate current = null;

                    // get current version from DB
                    using (var tran = conn.BeginTransaction())
                    {
                        using (var cmd = new NpgsqlCommand("SELECT config FROM manageditem WHERE id=@id", conn))
                        {
                            cmd.Parameters.Add(new NpgsqlParameter("@id", managedCertificate.Id));

                            using (var reader = await cmd.ExecuteReaderAsync())
                            {
                                if (await reader.ReadAsync())
                                {
                                    current = JsonConvert.DeserializeObject<ManagedCertificate>((string)reader["config"]);
                                    current.IsChanged = false;
                                }

                                await reader.CloseAsync();
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
                                using (var cmd = new NpgsqlCommand("UPDATE manageditem SET config = CAST(@config as jsonb), primary_subject=@primary_subject WHERE id=@id;", conn))
                                {
                                    cmd.Parameters.Add(new NpgsqlParameter("@id", managedCertificate.Id));
                                    cmd.Parameters.Add(new NpgsqlParameter("@config", NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = JsonConvert.SerializeObject(managedCertificate, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore }) });

                                    cmd.Parameters.Add(new NpgsqlParameter("@primary_subject", managedCertificate.RequestConfig.PrimaryDomain));
                                    //cmd.Parameters.Add(new NpgsqlParameter("@date_expiry", managedCertificate.DateExpiry));

                                    await cmd.ExecuteNonQueryAsync();
                                }

                                tran.Commit();
                            }
                            catch (NpgsqlException exp)
                            {
                                await tran.RollbackAsync();
                                _log?.Error(exp.ToString());
                                throw;
                            }
                        }
                        else
                        {
                            try
                            {
                                using (var cmd = new NpgsqlCommand("INSERT INTO manageditem(id,config,primary_subject) VALUES(@id,@config,@primary_subject);", conn))
                                {
                                    cmd.Parameters.Add(new NpgsqlParameter("@id", managedCertificate.Id));
                                    cmd.Parameters.Add(new NpgsqlParameter("@config", NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = JsonConvert.SerializeObject(managedCertificate, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore }) });

                                    cmd.Parameters.Add(new NpgsqlParameter("@primary_subject", managedCertificate.RequestConfig.PrimaryDomain));
                                    //cmd.Parameters.Add(new NpgsqlParameter("@date_expiry", managedCertificate.DateExpiry));

                                    await cmd.ExecuteNonQueryAsync();
                                }

                                tran.Commit();
                            }
                            catch (NpgsqlException exp)
                            {
                                await tran.RollbackAsync();
                                _log?.Error(exp.ToString());
                                throw;
                            }
                        }


                    }

                    await conn.CloseAsync();
                }
            }
            //);




            return managedCertificate;
        }
    }
}
