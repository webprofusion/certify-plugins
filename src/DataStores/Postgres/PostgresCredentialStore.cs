using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;
using Npgsql;

namespace Certify.Datastore.Postgres
{
    public class PostgresCredentialStore : ICredentialsManager
    {
        private ILog _log;
        private string _connectionString;
        private string _instanceId = "";

        private const string _itemType = "credential";
        private const string PROTECTIONENTROPY = "Certify.Credentials";

        private static readonly SemaphoreSlim _dbMutex = new SemaphoreSlim(1);
        private const int _semaphoreMaxWaitMS = 10 * 1000;

        private JsonSerializerSettings _jsonSerializerSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Ignore
        };

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "Plugin.DataStores.CredentialStore.Postgres",
                    ProviderCategoryId = "postgres",
                    Title = "Postgres",
                    Description = "Postgres DataStore provider"
                };
            }
        }

        public PostgresCredentialStore() { }
        public bool Init(string connectionString, ILog log, string instanceId = null)
        {
            _log = log;
            _connectionString = connectionString;
            _instanceId = instanceId ?? "";
            MigrateLegacyCredentialTable().Wait();
            return true;
        }

        public PostgresCredentialStore(string connectionString, ILog log = null, string instanceId = null)
        {
            Init(connectionString, log, instanceId);
        }

        /// <summary>
        /// Migrate credentials from the legacy 'credential' table into the 'manageditem' table
        /// </summary>
        private async Task MigrateLegacyCredentialTable()
        {
            if (string.IsNullOrEmpty(_connectionString))
            {
                return;
            }

            try
            {
                using (var conn = new NpgsqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    // Check if legacy credential table exists
                    bool hasLegacyTable;
                    using (var cmd = new NpgsqlCommand("SELECT 1 FROM information_schema.tables WHERE table_name = 'credential'", conn))
                    {
                        var result = await cmd.ExecuteScalarAsync();
                        hasLegacyTable = result != null;
                    }

                    if (!hasLegacyTable)
                    {
                        await conn.CloseAsync();
                        return;
                    }

                    // Check if there are any rows to migrate
                    int legacyCount;
                    using (var cmd = new NpgsqlCommand("SELECT COUNT(*) FROM credential", conn))
                    {
                        legacyCount = Convert.ToInt32(await cmd.ExecuteScalarAsync());
                    }

                    if (legacyCount > 0)
                    {
                        _log?.Information($"Postgres: Migrating {legacyCount} credentials from legacy credential table to manageditem table");

                        // Determine which columns exist in legacy table
                        var hasInstanceId = false;
                        using (var cmd = new NpgsqlCommand("SELECT 1 FROM information_schema.columns WHERE table_name = 'credential' AND column_name = 'instanceid'", conn))
                        {
                            var result = await cmd.ExecuteScalarAsync();
                            hasInstanceId = result != null;
                        }

                        var selectSql = hasInstanceId
                            ? "SELECT id, config, protectedvalue, instanceid FROM credential"
                            : "SELECT id, config, protectedvalue FROM credential";

                        using (var readCmd = new NpgsqlCommand(selectSql, conn))
                        {
                            using (var reader = await readCmd.ExecuteReaderAsync())
                            {
                                var rows = new List<(string Id, string Config, string ProtectedValue, string InstanceId)>();
                                while (await reader.ReadAsync())
                                {
                                    var id = (string)reader["id"];
                                    var config = (string)reader["config"];
                                    var protectedValue = reader["protectedvalue"] as string;
                                    var instId = hasInstanceId ? (reader["instanceid"] as string ?? "") : "";
                                    rows.Add((id, config, protectedValue, instId));
                                }

                                await reader.CloseAsync();

                                foreach (var row in rows)
                                {
                                    // Check if already migrated
                                    using (var checkCmd = new NpgsqlCommand("SELECT 1 FROM manageditem WHERE id = @id AND itemtype = @itemtype AND instanceid = @instanceid", conn))
                                    {
                                        checkCmd.Parameters.Add(new NpgsqlParameter("@id", row.Id));
                                        checkCmd.Parameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                                        checkCmd.Parameters.Add(new NpgsqlParameter("@instanceid", row.InstanceId));
                                        var exists = await checkCmd.ExecuteScalarAsync();
                                        if (exists != null)
                                        {
                                            continue;
                                        }
                                    }

                                    using (var insertCmd = new NpgsqlCommand(
                                        "INSERT INTO manageditem (id, itemtype, instanceid, config, itemvalue) VALUES (@id, @itemtype, @instanceid, CAST(@config AS jsonb), @itemvalue)", conn))
                                    {
                                        insertCmd.Parameters.Add(new NpgsqlParameter("@id", row.Id));
                                        insertCmd.Parameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                                        insertCmd.Parameters.Add(new NpgsqlParameter("@instanceid", row.InstanceId));
                                        insertCmd.Parameters.Add(new NpgsqlParameter("@config", NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = row.Config });
                                        insertCmd.Parameters.Add(new NpgsqlParameter("@itemvalue", (object)row.ProtectedValue ?? DBNull.Value));
                                        await insertCmd.ExecuteNonQueryAsync();
                                    }
                                }
                            }
                        }

                        _log?.Information("Postgres: Credential migration to manageditem table complete");

                        // Rename legacy table so we don't migrate again
                        using (var cmd = new NpgsqlCommand("ALTER TABLE credential RENAME TO credential_legacy", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }

                        _log?.Information("Postgres: Legacy credential table renamed to credential_legacy");
                    }
                    else
                    {
                        // No rows, just rename the empty table
                        using (var cmd = new NpgsqlCommand("ALTER TABLE credential RENAME TO credential_legacy", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    await conn.CloseAsync();
                }
            }
            catch (Exception ex)
            {
                _log?.Error(ex, "Failed to migrate legacy credential table");
            }
        }

        public async Task<bool> IsInitialised()
        {
            try
            {
                await GetCredentials();
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Delete credential by key. This will fail if the credential is currently in use. 
        /// </summary>
        /// <param name="storageKey"></param>
        /// <returns></returns>
        public async Task<ActionResult> Delete(IManagedItemStore itemStore, string storageKey)
        {
            var inUse = await CredentialsUtil.IsCredentialInUse(itemStore, storageKey);

            if (!inUse)
            {
                _log?.Warning("Deleting stored credential ", storageKey);

                try
                {
                    await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                    using (var conn = new NpgsqlConnection(_connectionString))
                    {
                        await conn.OpenAsync();
                        using (var tran = conn.BeginTransaction())
                        {
                            using (var cmd = new NpgsqlCommand("DELETE FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                            {
                                cmd.Parameters.Add(new NpgsqlParameter("@id", storageKey));
                                cmd.Parameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                                cmd.Parameters.Add(new NpgsqlParameter("@instanceid", _instanceId));
                                await cmd.ExecuteNonQueryAsync();
                            }

                            await tran.CommitAsync();
                        }

                        await conn.CloseAsync();
                    }
                }
                finally
                {
                    _dbMutex.Release();
                }

                return new ActionResult("Credential Deleted", true);
            }
            else
            {
                return new ActionResult("Credential in use, could not delete.", false);
            }
        }

        /// <summary>
        /// Return summary list of stored credentials (excluding secrets) for given type 
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public async Task<List<StoredCredential>> GetCredentials(string type = null, string storageKey = null)
        {
            var credentials = new List<StoredCredential>();

            using (var db = new NpgsqlConnection(_connectionString))
            {
                await db.OpenAsync();

                var queryParameters = new List<NpgsqlParameter>();
                var sql = @"SELECT id, config FROM manageditem WHERE itemtype = @itemtype AND instanceid = @instanceid";

                queryParameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                queryParameters.Add(new NpgsqlParameter("@instanceid", _instanceId));

                if (!string.IsNullOrEmpty(storageKey))
                {
                    sql += " AND id = @id";
                    queryParameters.Add(new NpgsqlParameter("@id", storageKey));
                }

                if (!string.IsNullOrEmpty(type))
                {
                    sql += " AND config->>'ProviderType' = @providerType";
                    queryParameters.Add(new NpgsqlParameter("@providerType", type));
                }

                sql += " ORDER BY config->>'Title' ";

                using (var cmd = new NpgsqlCommand(sql, db))
                {
                    cmd.Parameters.AddRange(queryParameters.ToArray());

                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            var storedCredential = JsonConvert.DeserializeObject<StoredCredential>((string)reader["config"]);
                            credentials.Add(storedCredential);
                        }
                    }
                }

                db.Close();
            }

            return credentials;
        }

        public async Task<StoredCredential> GetCredential(string storageKey)
        {
            var credentials = await GetCredentials(type: null, storageKey: storageKey);
            return credentials.FirstOrDefault(c => c.StorageKey == storageKey);
        }

        public async Task<string> GetUnlockedCredential(string storageKey)
        {
            if (string.IsNullOrEmpty(storageKey))
            {
                return null;
            }

            string protectedString = null;
            var itemExists = false;

            using (var db = new NpgsqlConnection(_connectionString))
            using (var cmd = new NpgsqlCommand("SELECT config, itemvalue FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", db))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@id", storageKey));
                cmd.Parameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                cmd.Parameters.Add(new NpgsqlParameter("@instanceid", _instanceId));

                db.Open();
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        itemExists = true;
                        protectedString = reader["itemvalue"] as string;
                    }
                }

                db.Close();
            }

            if (!itemExists)
            {
                return null;
            }

            try
            {
                return CredentialsUtil.Unprotect(protectedString, PROTECTIONENTROPY, DataProtectionScope.CurrentUser);
            }
            catch (Exception exp)
            {
                throw new AggregateException($"Failed to decrypt Credential [{storageKey}] - it was most likely created by a different user account.", exp);
            }
        }

        public async Task<Dictionary<string, string>> GetUnlockedCredentialsDictionary(string storageKey)
        {
            try
            {
                var val = await GetUnlockedCredential(storageKey);

                return JsonConvert.DeserializeObject<Dictionary<string, string>>(val);
            }
            catch (Exception)
            {
                // failed to decrypt or credential inaccessible
                return null;
            }
        }

        public async Task<StoredCredential> Update(StoredCredential credentialInfo)
        {
            if (credentialInfo.Secret == null)
            {
                return null;
            }

            credentialInfo.DateCreated = DateTimeOffset.UtcNow;

            var protectedContent = CredentialsUtil.Protect(credentialInfo.Secret, PROTECTIONENTROPY, DataProtectionScope.CurrentUser);

            credentialInfo.Secret = "protected";

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                using (var conn = new NpgsqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    using (var tran = conn.BeginTransaction())
                    {
                        bool exists = false;
                        using (var checkCmd = new NpgsqlCommand("SELECT 1 FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                        {
                            checkCmd.Parameters.Add(new NpgsqlParameter("@id", credentialInfo.StorageKey));
                            checkCmd.Parameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                            checkCmd.Parameters.Add(new NpgsqlParameter("@instanceid", _instanceId));
                            var result = await checkCmd.ExecuteScalarAsync();
                            exists = result != null;
                        }

                        try
                        {
                            if (exists)
                            {
                                using (var cmd = new NpgsqlCommand("UPDATE manageditem SET config = CAST(@config AS jsonb), itemvalue = @itemvalue WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                                {
                                    cmd.Parameters.Add(new NpgsqlParameter("@id", credentialInfo.StorageKey));
                                    cmd.Parameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                                    cmd.Parameters.Add(new NpgsqlParameter("@instanceid", _instanceId));
                                    cmd.Parameters.Add(new NpgsqlParameter("@config", NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = JsonConvert.SerializeObject(credentialInfo, _jsonSerializerSettings) });
                                    cmd.Parameters.Add(new NpgsqlParameter("@itemvalue", protectedContent));
                                    await cmd.ExecuteNonQueryAsync();
                                }
                            }
                            else
                            {
                                using (var cmd = new NpgsqlCommand("INSERT INTO manageditem (id, itemtype, instanceid, config, itemvalue) VALUES (@id, @itemtype, @instanceid, CAST(@config AS jsonb), @itemvalue)", conn))
                                {
                                    cmd.Parameters.Add(new NpgsqlParameter("@id", credentialInfo.StorageKey));
                                    cmd.Parameters.Add(new NpgsqlParameter("@itemtype", _itemType));
                                    cmd.Parameters.Add(new NpgsqlParameter("@instanceid", _instanceId));
                                    cmd.Parameters.Add(new NpgsqlParameter("@config", NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = JsonConvert.SerializeObject(credentialInfo, _jsonSerializerSettings) });
                                    cmd.Parameters.Add(new NpgsqlParameter("@itemvalue", protectedContent));
                                    await cmd.ExecuteNonQueryAsync();
                                }
                            }

                            await tran.CommitAsync();
                        }
                        catch (NpgsqlException exp)
                        {
                            await tran.RollbackAsync();
                            _log?.Error(exp.ToString());
                            throw;
                        }
                    }

                    await conn.CloseAsync();
                }
            }
            finally
            {
                _dbMutex.Release();
            }

            return credentialInfo;
        }
    }
}
