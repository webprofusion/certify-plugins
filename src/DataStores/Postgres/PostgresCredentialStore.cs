using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Certify.Datastore.Postgres
{
    public class PostgresCredentialStore : CredentialsManagerBase, ICredentialsManager
    {
        private ILog _log;
        private string _connectionString;

        private const string PROTECTIONENTROPY = "Certify.Credentials";

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
        public bool Init(string connectionString, bool useWindowsNativeFeatures, ILog log)
        {
            _log = log;
            _connectionString = connectionString;
            _useWindowsNativeFeatures = useWindowsNativeFeatures;
            return true;
        }

        public PostgresCredentialStore(string connectionString, bool useWindowsNativeFeatures = true, ILog log = null) : base(useWindowsNativeFeatures)
        {
            Init(connectionString, useWindowsNativeFeatures, log);
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
        public async Task<bool> Delete(IManagedItemStore itemStore, string storageKey)
        {
            var inUse = await IsCredentialInUse(itemStore, storageKey);

            if (!inUse)
            {
                //delete credential in database

                _log?.Warning("Deleting stored credential ", storageKey);

                using (var conn = new NpgsqlConnection(_connectionString))
                {
                    await conn.OpenAsync();
                    using (var tran = conn.BeginTransaction())
                    {
                        using (var cmd = new NpgsqlCommand("DELETE FROM credential WHERE id=@id", conn))
                        {
                            cmd.Parameters.Add(new NpgsqlParameter("@id", storageKey));
                            await cmd.ExecuteNonQueryAsync();

                            tran.Commit();
                        }
                    }
                    await conn.CloseAsync();

                }

                return true;
            }
            else
            {
                //could not delete
                return false;
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
                var conditions = new List<string>();
                var sql = @"SELECT id, config FROM credential ";

                if (!string.IsNullOrEmpty(storageKey))
                {
                    conditions.Add("id = @id");
                    queryParameters.Add(new NpgsqlParameter("@id", storageKey));
                }

                if (!string.IsNullOrEmpty(type))
                {
                    conditions.Add(" config->>'ProviderType' = @providerType");
                    queryParameters.Add(new NpgsqlParameter("@providerType", type));
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

                sql += $" ORDER BY config->>'Title' ";

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

        public override async Task<StoredCredential> GetCredential(string storageKey)
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

            using (var db = new NpgsqlConnection(_connectionString))
            using (var cmd = new NpgsqlCommand("SELECT config, protectedvalue FROM credential WHERE id=@id", db))
            {
                cmd.Parameters.Add(new NpgsqlParameter("@id", storageKey));

                db.Open();
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        var storedCredential = JsonConvert.DeserializeObject<StoredCredential>((string)reader["config"]);
                        protectedString = (string)reader["protectedvalue"];
                    }
                }

                db.Close();
            }

            try
            {
                return Unprotect(protectedString, PROTECTIONENTROPY, DataProtectionScope.CurrentUser);
            }
            catch (Exception exp)
            {
                throw new AggregateException($"Failed to decrypt Credential [{storageKey}] - it was most likely created by a different user account.", exp);
            }
        }

        public override async Task<Dictionary<string, string>> GetUnlockedCredentialsDictionary(string storageKey)
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

            credentialInfo.DateCreated = DateTime.UtcNow;

            var protectedContent = Protect(credentialInfo.Secret, PROTECTIONENTROPY, DataProtectionScope.CurrentUser);

            credentialInfo.Secret = "protected";

            using (var conn = new NpgsqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                ManagedCertificate current = null;

                // get current version from DB
                using (var tran = conn.BeginTransaction())
                {
                    using (var cmd = new NpgsqlCommand("SELECT config FROM credential WHERE id=@id", conn))
                    {
                        cmd.Parameters.Add(new NpgsqlParameter("@id", credentialInfo.StorageKey));

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

                        try
                        {
                            using (var cmd = new NpgsqlCommand("UPDATE credential SET config = CAST(@config as jsonb), protectedvalue= @protectedvalue WHERE id=@id;", conn))
                            {
                                cmd.Parameters.Add(new NpgsqlParameter("@id", credentialInfo.StorageKey));
                                cmd.Parameters.Add(new NpgsqlParameter("@config", NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = JsonConvert.SerializeObject(credentialInfo, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore }) });
                                cmd.Parameters.Add(new NpgsqlParameter("@protectedvalue", protectedContent));

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
                            using (var cmd = new NpgsqlCommand("INSERT INTO credential(id,config,protectedvalue) VALUES(@id,@config,@protectedvalue);", conn))
                            {
                                cmd.Parameters.Add(new NpgsqlParameter("@id", credentialInfo.StorageKey));
                                cmd.Parameters.Add(new NpgsqlParameter("@config", NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = JsonConvert.SerializeObject(credentialInfo, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore }) });
                                cmd.Parameters.Add(new NpgsqlParameter("@protectedvalue", protectedContent));

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

            return credentialInfo;
        }
    }
}
