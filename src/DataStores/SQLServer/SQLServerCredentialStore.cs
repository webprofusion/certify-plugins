using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;

namespace Certify.Datastore.SQLServer
{
    public class SQLServerCredentialStore : ICredentialsManager, IDataStoreSchemaProvider
    {
        private DataStoreSchemaCheckResult _schemaState = new DataStoreSchemaCheckResult();

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
                    Id = "Plugin.DataStores.CredentialStore.SQLServer",
                    ProviderCategoryId = "sqlserver",
                    Title = "SQL Server",
                    Description = "SQL Server DataStore provider"
                };
            }
        }

        public SQLServerCredentialStore() { }
        public bool Init(string connectionString, ILog log, string instanceId = null)
        {
            _log = log;
            _connectionString = connectionString;
            _instanceId = instanceId ?? "";
            EnsureSchema().Wait();
            return true;
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
        /// Bring the schema up to date on connection where the connected user has schema modification rights,
        /// otherwise report the outstanding migrations without failing. Moving rows out of the legacy
        /// 'credential' table is part of the shared migration set - see SQLServerSchema.
        /// </summary>
        private async Task EnsureSchema()
        {
            if (string.IsNullOrEmpty(_connectionString))
            {
                return;
            }

            _schemaState = await SQLServerSchema.TryAutoMigrate(_connectionString, _log);
        }

        /// <summary>
        /// The schema state observed when this store last connected
        /// </summary>
        public DataStoreSchemaCheckResult GetSchemaState() => _schemaState;

        public async Task<DataStoreSchemaCheckResult> CheckSchema(string connectionString, ILog log = null)
            => await SQLServerSchema.CheckSchema(connectionString, log ?? _log);

        public async Task<ActionResult<List<DataStoreSchemaMigration>>> ApplySchemaMigrations(string connectionString, ILog log = null, bool includeOptional = true)
            => await SQLServerSchema.ApplySchemaMigrations(connectionString, log ?? _log, includeOptional);

        public SQLServerCredentialStore(string connectionString, ILog log = null, string instanceId = null)
        {
            Init(connectionString, log, instanceId);
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

                    using (var conn = new SqlConnection(_connectionString))
                    {
                        await conn.OpenAsync();
                        using (var tran = conn.BeginTransaction())
                        {
                            using (var cmd = new SqlCommand("DELETE FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", storageKey));
                                cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                await cmd.ExecuteNonQueryAsync();
                            }

                            tran.Commit();
                        }

                        conn.Close();
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

            using (var db = new SqlConnection(_connectionString))
            {
                await db.OpenAsync();

                var queryParameters = new List<SqlParameter>();
                var sql = @"SELECT id, config FROM manageditem WHERE itemtype = @itemtype AND instanceid = @instanceid";

                queryParameters.Add(new SqlParameter("@itemtype", _itemType));
                queryParameters.Add(new SqlParameter("@instanceid", _instanceId));

                if (!string.IsNullOrEmpty(storageKey))
                {
                    sql += " AND id = @id";
                    queryParameters.Add(new SqlParameter("@id", storageKey));
                }

                if (!string.IsNullOrEmpty(type))
                {
                    sql += " AND JSON_VALUE(config, '$.ProviderType') = @providerType";
                    queryParameters.Add(new SqlParameter("@providerType", type));
                }

                sql += " ORDER BY JSON_VALUE(config, '$.Title') ";

                using (var cmd = new SqlCommand(sql, db))
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

            using (var db = new SqlConnection(_connectionString))
            using (var cmd = new SqlCommand("SELECT config, itemvalue FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", db))
            {
                cmd.Parameters.Add(new SqlParameter("@id", storageKey));
                cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));

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
                return CredentialsUtil.Unprotect(protectedString, PROTECTIONENTROPY);
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
            catch (AggregateException exp)
            {
                // the credential exists but this user account cannot decrypt it, which will not resolve on its
                // own. Callers see the same null as any other unavailable credential, so the reason is logged here
                _log?.Error(exp, "Stored credential [{storageKey}] could not be decrypted. It was most likely created by a different user account.", storageKey);
                return null;
            }
            catch (Exception exp)
            {
                // the credential could not be read at all (e.g. the credential store was briefly unavailable),
                // which may well be temporary. Separating it in the log matters because the caller cannot tell
                // the two apart from the null it receives
                _log?.Error(exp, "Stored credential [{storageKey}] could not be retrieved from the credential store.", storageKey);
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

            var protectedContent = CredentialsUtil.Protect(credentialInfo.Secret, PROTECTIONENTROPY);

            credentialInfo.Secret = "protected";

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    using (var tran = conn.BeginTransaction())
                    {
                        bool exists = false;
                        using (var checkCmd = new SqlCommand("SELECT 1 FROM manageditem WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                        {
                            checkCmd.Transaction = tran;
                            checkCmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
                            checkCmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                            checkCmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                            var result = await checkCmd.ExecuteScalarAsync();
                            exists = result != null;
                        }

                        try
                        {
                            if (exists)
                            {
                                using (var cmd = new SqlCommand("UPDATE manageditem SET config = @config, itemvalue = @itemvalue WHERE id=@id AND itemtype=@itemtype AND instanceid=@instanceid", conn))
                                {
                                    cmd.Transaction = tran;
                                    cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
                                    cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                                    cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                    cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(credentialInfo, _jsonSerializerSettings)));
                                    cmd.Parameters.Add(new SqlParameter("@itemvalue", protectedContent));
                                    await cmd.ExecuteNonQueryAsync();
                                }
                            }
                            else
                            {
                                using (var cmd = new SqlCommand("INSERT INTO manageditem (id, itemtype, instanceid, config, itemvalue) VALUES (@id, @itemtype, @instanceid, @config, @itemvalue)", conn))
                                {
                                    cmd.Transaction = tran;
                                    cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
                                    cmd.Parameters.Add(new SqlParameter("@itemtype", _itemType));
                                    cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                    cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(credentialInfo, _jsonSerializerSettings)));
                                    cmd.Parameters.Add(new SqlParameter("@itemvalue", protectedContent));
                                    await cmd.ExecuteNonQueryAsync();
                                }
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

                    conn.Close();
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
