using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Certify.Management
{
    public class SQLiteCredentialStore : CredentialsManagerBase, ICredentialsManager
    {
        public const string CREDENTIALSTORE = "cred";
        private const string PROTECTIONENTROPY = "Certify.Credentials";

        /// <summary>
        /// if specified will be appended to AppData path as subfolder to load/save to
        /// </summary>
        private string _storageSubFolder = "credentials";

        private ILog _log;

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
        public bool Init(string connectionString, bool useWindowsNativeFeatures, ILog log)
        {
            _log = log;
            _storageSubFolder = connectionString;
            _useWindowsNativeFeatures = useWindowsNativeFeatures;
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

        public SQLiteCredentialStore(bool useWindowsNativeFeatures = true, string storageSubfolder = "credentials", ILog log = null) : base(useWindowsNativeFeatures)
        {
            Init(storageSubfolder, useWindowsNativeFeatures, log);
        }

        private string GetDbPath()
        {
            var appDataPath = EnvironmentUtil.CreateAppDataPath(_storageSubFolder ?? "");
            return Path.Combine(appDataPath, $"{CREDENTIALSTORE}.db");
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
                var path = GetDbPath();

                if (File.Exists(path))
                {
                    using (var db = new SQLiteConnection($"Data Source={path}"))
                    {
                        await db.OpenAsync();
                        using (var tran = db.BeginTransaction())
                        {
                            using (var cmd = new SQLiteCommand("DELETE FROM credential WHERE id=@id", db))
                            {
                                cmd.Parameters.Add(new SQLiteParameter("@id", storageKey));
                                await cmd.ExecuteNonQueryAsync();
                            }

                            tran.Commit();
                        }

                        db.Close();
                    }
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
            var path = GetDbPath();

            if (File.Exists(path))
            {
                var credentials = new List<StoredCredential>();

                using (var db = new SQLiteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();

                    var queryParameters = new List<SQLiteParameter>();
                    var conditions = new List<string>();
                    var sql = @"SELECT id, json FROM credential ";

                    if (!string.IsNullOrEmpty(storageKey))
                    {
                        conditions.Add("id = @id");
                        queryParameters.Add(new SQLiteParameter("@id", storageKey));
                    }

                    if (!string.IsNullOrEmpty(type))
                    {
                        conditions.Add(" json->>'ProviderType' = @providerType");
                        queryParameters.Add(new SQLiteParameter("@providerType", type));
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

                    sql += $" ORDER BY json->>'Title' ASC";

                    using (var cmd = new SQLiteCommand(sql, db))
                    {
                        cmd.Parameters.AddRange(queryParameters.ToArray());

                        using (var reader = await cmd.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                var storedCredential = JsonConvert.DeserializeObject<StoredCredential>((string)reader["json"]);
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

        public override async Task<StoredCredential> GetCredential(string storageKey)
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

            var path = GetDbPath();

            //load protected string from db
            if (File.Exists(path))
            {
                using (var db = new SQLiteConnection($"Data Source={path}"))
                using (var cmd = new SQLiteCommand("SELECT json, protectedvalue FROM credential WHERE id=@id", db))
                {
                    cmd.Parameters.Add(new SQLiteParameter("@id", storageKey));

                    db.Open();
                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            var storedCredential = JsonConvert.DeserializeObject<StoredCredential>((string)reader["json"]);
                            protectedString = (string)reader["protectedvalue"];
                        }
                    }

                    db.Close();
                }
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

            var path = GetDbPath();

            //create database if it doesn't exist
            if (!File.Exists(path))
            {
                try
                {
                    using (var db = new SQLiteConnection($"Data Source={path}"))
                    {
                        await db.OpenAsync();
                        using (var cmd = new SQLiteCommand("CREATE TABLE credential (id TEXT NOT NULL UNIQUE PRIMARY KEY, json TEXT NOT NULL, protectedvalue TEXT NOT NULL)", db))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }
                }
                catch (SQLiteException)
                {
                    // already exists
                }
            }

            // save new/modified item into credentials database
            using (var db = new SQLiteConnection($"Data Source={path}"))
            {
                await db.OpenAsync();
                using (var tran = db.BeginTransaction())
                {
                    using (var cmd = new SQLiteCommand("INSERT OR REPLACE INTO credential (id, json, protectedvalue) VALUES (@id, @json, @protectedvalue)", db))
                    {
                        cmd.Parameters.Add(new SQLiteParameter("@id", credentialInfo.StorageKey));
                        cmd.Parameters.Add(new SQLiteParameter("@json", JsonConvert.SerializeObject(credentialInfo)));
                        cmd.Parameters.Add(new SQLiteParameter("@protectedvalue", protectedContent));
                        await cmd.ExecuteNonQueryAsync();
                    }

                    tran.Commit();
                }

                db.Close();
            }

            return credentialInfo;
        }
    }
}
