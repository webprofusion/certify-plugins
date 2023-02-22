using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;

namespace Certify.Management
{
    public class SQLServerCredentialStore : CredentialsManagerBase, ICredentialsManager
    {
        private readonly ILog _log;
        private readonly string _connectionString;

        private const string PROTECTIONENTROPY = "Certify.Credentials";

        public SQLServerCredentialStore(string connectionString, bool useWindowsNativeFeatures = true, ILog log = null) : base(useWindowsNativeFeatures)
        {
            _log = log;
            _connectionString = connectionString;
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

                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();
                    using (var tran = conn.BeginTransaction())
                    {
                        using (var cmd = new SqlCommand("DELETE FROM credential WHERE id=@id", conn))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqlParameter("@id", storageKey));
                            await cmd.ExecuteNonQueryAsync();

                            tran.Commit();
                        }
                    }
                    conn.Close();

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

            using (var db = new SqlConnection(_connectionString))
            {
                await db.OpenAsync();

                var queryParameters = new List<SqlParameter>();
                var conditions = new List<string>();
                var sql = @"SELECT id, config FROM credential ";

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
                    bool isFirstCondition = true;
                    foreach (var c in conditions)
                    {
                        sql += (!isFirstCondition ? " AND " + c : c);

                        isFirstCondition = false;
                    }
                }

                sql += $" ORDER BY JSON_VALUE(config, '$.Name') ";

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

            using (var db = new SqlConnection(_connectionString))
            using (var cmd = new SqlCommand("SELECT config, protectedvalue FROM credential WHERE id=@id", db))
            {
                cmd.Parameters.Add(new SqlParameter("@id", storageKey));

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

            credentialInfo.DateCreated = DateTime.Now;

            var protectedContent = Protect(credentialInfo.Secret, PROTECTIONENTROPY, DataProtectionScope.CurrentUser);

            credentialInfo.Secret = "protected";

            using (var conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                ManagedCertificate current = null;

                // get current version from DB
                using (var tran = conn.BeginTransaction())
                {
                    using (var cmd = new SqlCommand("SELECT config FROM credential WHERE id=@id", conn))
                    {
                        cmd.Transaction = tran;
                        cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));

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
                            using (var cmd = new SqlCommand("UPDATE credential SET config = CAST(@config as jsonb), protectedvalue= @protectedvalue WHERE id=@id;", conn))
                            {
                                cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
                                cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(credentialInfo, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore })));
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
                            using (var cmd = new SqlCommand("INSERT INTO credential(id,config,protectedvalue) VALUES(@id,@config,@protectedvalue);", conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", credentialInfo.StorageKey));
                                cmd.Parameters.Add(new SqlParameter("@config", JsonConvert.SerializeObject(credentialInfo, new JsonSerializerSettings { Formatting = Formatting.Indented, NullValueHandling = NullValueHandling.Ignore })));
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
