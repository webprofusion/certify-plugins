using System;
using System.Collections.Generic;
using System.Linq;
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
    public class SQLServerCredentialStore : ICredentialsManager
    {
        private ILog _log;
        private string _connectionString;
        private string _instanceId = "";

        private const string PROTECTIONENTROPY = "Certify.Credentials";

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

        private async Task EnsureSchema()
        {
            if (string.IsNullOrEmpty(_connectionString))
            {
                return;
            }

            try
            {
                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    var hasInstanceId = false;
                    using (var cmd = new SqlCommand("SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('credential') AND name = 'instanceid'", conn))
                    {
                        var result = await cmd.ExecuteScalarAsync();
                        hasInstanceId = result != null;
                    }

                    if (!hasInstanceId)
                    {
                        using (var cmd = new SqlCommand("ALTER TABLE credential ADD instanceid NVARCHAR(64) NOT NULL DEFAULT '';", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }

                        using (var cmd = new SqlCommand(@"
                            IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_credential_instanceid' AND object_id = OBJECT_ID('credential'))
                            BEGIN
                                CREATE INDEX idx_credential_instanceid ON credential(instanceid);
                            END", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    if (!string.IsNullOrEmpty(_instanceId))
                    {
                        using (var cmd = new SqlCommand(
                            "UPDATE credential SET instanceid = @instanceid WHERE instanceid IS NULL OR instanceid = '';", conn))
                        {
                            cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }

                    conn.Close();
                }
            }
            catch (Exception ex)
            {
                _log?.Error(ex, "Failed to ensure credential store schema");
                throw;
            }
        }

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
                //delete credential in database

                _log?.Warning("Deleting stored credential ", storageKey);

                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();
                    using (var tran = conn.BeginTransaction())
                    {
                        using (var cmd = new SqlCommand("DELETE FROM credential WHERE id=@id AND instanceid=@instanceid", conn))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqlParameter("@id", storageKey));
                            cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                            await cmd.ExecuteNonQueryAsync();

                            tran.Commit();
                        }
                    }

                    conn.Close();

                }

                return new ActionResult("Credential Deleted", true);
            }
            else
            {
                //could not delete
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
                var conditions = new List<string>();
                var sql = @"SELECT id, config FROM credential ";

                conditions.Add("instanceid = @instanceid");
                queryParameters.Add(new SqlParameter("@instanceid", _instanceId));

                if (!string.IsNullOrEmpty(storageKey))
                {
                    conditions.Add("id = @id");
                    queryParameters.Add(new SqlParameter("@id", storageKey));
                }

                if (!string.IsNullOrEmpty(type))
                {
                    conditions.Add("JSON_VALUE(config, '$.ProviderType') = @providerType");
                    queryParameters.Add(new SqlParameter("@providerType", type));
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

                sql += $" ORDER BY JSON_VALUE(config, '$.Title') ";

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
            using (var cmd = new SqlCommand("SELECT config, protectedvalue FROM credential WHERE id=@id AND instanceid=@instanceid", db))
            {
                cmd.Parameters.Add(new SqlParameter("@id", storageKey));
                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));

                db.Open();
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        itemExists = true;
                        var storedCredential = JsonConvert.DeserializeObject<StoredCredential>((string)reader["config"]);
                        protectedString = (string)reader["protectedvalue"];
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

            var protectedContent = CredentialsUtil.Protect(credentialInfo.Secret, PROTECTIONENTROPY);

            credentialInfo.Secret = "protected";

            using (var conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                ManagedCertificate current = null;

                // get current version from DB
                using (var tran = conn.BeginTransaction())
                {
                    using (var cmd = new SqlCommand("SELECT config FROM credential WHERE id=@id AND instanceid=@instanceid", conn))
                    {
                        cmd.Transaction = tran;
                        cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
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

                        try
                        {
                            using (var cmd = new SqlCommand("UPDATE credential SET config = @config, protectedvalue= @protectedvalue WHERE id=@id AND instanceid=@instanceid;", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
                                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(credentialInfo, _jsonSerializerSettings)));
                                cmd.Parameters.Add(new SqlParameter("@protectedvalue", protectedContent));

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
                            using (var cmd = new SqlCommand("INSERT INTO credential(id,instanceid,config,protectedvalue) VALUES(@id,@instanceid,@config,@protectedvalue);", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
                                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(credentialInfo, _jsonSerializerSettings)));
                                cmd.Parameters.Add(new SqlParameter("@protectedvalue", protectedContent));

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

            return credentialInfo;
        }
    }
}
