using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Certify.Management;
using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace Certify.Datastore.SQLite
{
    public class SQLiteCredentialStore : SQLiteStoreBase, ICredentialsManager
    {
        private const string _itemType = "credential";

        private const string PROTECTIONENTROPY = "Certify.Credentials";

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "Plugin.DataStores.CredentialStore.SQLite",
                    ProviderCategoryId = "sqlite",
                    Title = "SQLite",
                    Description = "SQLite DataStore provider"
                };
            }
        }
        public SQLiteCredentialStore() { }
        public new bool Init(string connectionString, ILog log, string instanceId = null)
        {
            _log = log;

            base.Init(connectionString, log, performBackup: false);

            MigrateLegacyDB().Wait(); ;

            return true;
        }

        public new async Task<bool> IsInitialised()
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

        public SQLiteCredentialStore(string storageSubfolder = null, ILog log = null)
        {
            Init(storageSubfolder, log);
        }

        private async Task MigrateLegacyDB()
        {
            // old dbs are stored as a separate /credentials/cred.db and this becomes a configurationitem entry in the main manageditems.db
            var appDataPath = EnvironmentUtil.EnsuredAppDataPath("credentials", skipCreation: true);
            var dbPath = Path.Combine(appDataPath, $"cred.db");

            if (File.Exists(dbPath))
            {
                var credentials = new List<StoredCredential>();
                // migrate content from legacy db to configurationitems
                using (var db = new SqliteConnection($"Data Source={dbPath}"))
                {
                    db.Open();

                    var sql = @"SELECT id, json, protectedvalue FROM credential ";
                    using (var cmd = new SqliteCommand(sql, db))
                    {
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                var storedCredential = JsonConvert.DeserializeObject<StoredCredential>((string)reader["json"]);
                                try
                                {
                                    var secret = (string)reader["protectedvalue"];
                                    if (secret != null)
                                    {
                                        storedCredential.Secret = CredentialsUtil.Unprotect(secret, PROTECTIONENTROPY, DataProtectionScope.CurrentUser);
                                    }

                                    credentials.Add(storedCredential);
                                }
                                catch
                                {
                                    _log?.Error("Failed to decrypt stored credential during migration. Item will not be migrated. : {id} {title}", storedCredential.StorageKey, storedCredential.Title);
                                }
                            }
                        }
                    }

                    db.Close();
                }

                if (credentials.Count > 0)
                {

                    // store credentials
                    foreach (var c in credentials)
                    {
                        await Update(c);
                    }

                    _log?.Warning("Stored credentials database migrated to configuration items.");

                    // ensure all connections to old db are closed
                    SqliteConnection.ClearAllPools();

                    // check we have the credentials backup we just tried to store, then remove the old db so we don't try to migrate again
                    File.Copy(dbPath, $"{dbPath}.old", true);

                    if (File.Exists($"{dbPath}.old"))
                    {
                        try
                        {
                            File.Delete(dbPath);
                            _log?.Warning("Legacy credentials database backup created, old db removed.");
                        }
                        catch (Exception exp)
                        {
                            _log?.Error("Failed to delete legacy credentials database after migration: " + exp.ToString());
                        }
                    }
                }
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
                await Delete(storageKey, _itemType);

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
            var path = GetDbPath();

            if (File.Exists(path))
            {
                var credentials = new List<StoredCredential>();

                using (var db = new SqliteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();

                    var queryParameters = new List<SqliteParameter>();
                    var conditions = new List<string>();
                    var sql = @"SELECT id, config FROM manageditem ";

                    if (!string.IsNullOrEmpty(storageKey))
                    {
                        conditions.Add("id = @id");
                        queryParameters.Add(new SqliteParameter("@id", storageKey));
                    }

                    if (!string.IsNullOrEmpty(type))
                    {
                        conditions.Add(" config->>'ProviderType' = @providerType");
                        queryParameters.Add(new SqliteParameter("@providerType", type));
                    }

                    sql += $" WHERE itemtype='{_itemType}' ";

                    if (conditions.Any())
                    {
                        foreach (var c in conditions)
                        {
                            sql += $" AND {c}";
                        }
                    }

                    sql += $" ORDER BY config->>'Title' ASC";

                    using (var cmd = new SqliteCommand(sql, db))
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
            else
            {
                return new List<StoredCredential>();
            }
        }

        public async Task<StoredCredential> GetCredential(string storageKey)
        {
            var credentials = await GetCredentials();
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

            var path = GetDbPath();

            //load protected string from db
            if (File.Exists(path))
            {
                using (var db = new SqliteConnection($"Data Source={path}"))
                using (var cmd = new SqliteCommand("SELECT config, itemvalue FROM manageditem WHERE id=@id and itemtype=@itemtype", db))
                {
                    cmd.Parameters.Add(new SqliteParameter("@id", storageKey));
                    cmd.Parameters.Add(new SqliteParameter("@itemtype", _itemType));

                    db.Open();
                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            itemExists = true;
                            var storedCredential = JsonConvert.DeserializeObject<StoredCredential>((string)reader["config"]);
                            protectedString = (string)reader["itemvalue"];
                        }
                    }

                    db.Close();
                }
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
                var path = GetDbPath();

                // save new/modified item into credentials database
                using (var db = new SqliteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();
                    using (var tran = db.BeginTransaction())
                    {
                        using (var cmd = new SqliteCommand("INSERT OR REPLACE INTO manageditem (id, config, itemtype, itemvalue) VALUES (@id, @config, @itemtype, @itemvalue)", db))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqliteParameter("@id", credentialInfo.StorageKey));
                            cmd.Parameters.Add(new SqliteParameter("@config", JsonConvert.SerializeObject(credentialInfo)));
                            cmd.Parameters.Add(new SqliteParameter("@itemtype", _itemType));
                            cmd.Parameters.Add(new SqliteParameter("@itemvalue", protectedContent));
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

            return credentialInfo;
        }
    }
}
