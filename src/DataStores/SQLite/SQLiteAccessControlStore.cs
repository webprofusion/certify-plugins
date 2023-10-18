using Certify.Models;
using Certify.Models.Config;
using Certify.Models.Config.AccessControl;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Certify.Management
{
    public class SQLiteAccessControlStore : IAccessControlStore
    {
        public const string STOREDBNAME = "accesscontrol";
        private const string PROTECTIONENTROPY = "Certify.AccessControl";

        /// <summary>
        /// if specified will be appended to AppData path as subfolder to load/save to
        /// </summary>
        private string _storageSubFolder = "credentials";

        private ILog _log;
        private bool _useWindowsNativeFeatures = false;

        public static ProviderDefinition Definition
        {
            get
            {
                return new ProviderDefinition
                {
                    Id = "Plugin.DataStores.AccessControlStore.SQLite",
                    ProviderCategoryId = "sqlite",
                    Title = "SQLite",
                    Description = "SQLite DataStore provider"
                };
            }
        }

        public SQLiteAccessControlStore()
        {
        }

        public SQLiteAccessControlStore(bool useWindowsNativeFeatures = true, string storageSubfolder = "credentials",
            ILog log = null)
        {
            Init(storageSubfolder, useWindowsNativeFeatures, log);
        }

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
                await GetItems();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private string GetDbPath()
        {
            var appDataPath = EnvironmentUtil.GetAppDataFolder(_storageSubFolder ?? "");
            return Path.Combine(appDataPath, $"{STOREDBNAME}.db");
        }

        /// <summary>
        /// Delete item by key
        /// </summary>
        /// <param name="storageKey"></param>
        /// <returns></returns>
        public async Task<bool> Delete<T>(string itemType, string id)
        {
            //delete item in database
            var path = GetDbPath();

            if (File.Exists(path))
            {
                using (var db = new SQLiteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();
                    using (var tran = db.BeginTransaction())
                    {
                        using (var cmd = new SQLiteCommand("DELETE FROM configurationitem WHERE itemtype=@itemtype AND id=@id", db))
                        {
                            cmd.Parameters.Add(new SQLiteParameter("@id", id));
                            cmd.Parameters.Add(new SQLiteParameter("@itemtype", itemType));
                            await cmd.ExecuteNonQueryAsync();
                        }

                        tran.Commit();
                    }

                    db.Close();
                }
            }

            return true;
        }

        class ConfigurationItem
        {
            public string Id { get; set; }
            public string ItemType { get; set; }
            public string Json { get; set; }
        }

        /// <summary>
        /// Return summary list of stored credentials (excluding secrets) for given type 
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        private async Task<List<ConfigurationItem>> GetItems(string itemType = nameof(SecurityPrinciple),
            string id = null)
        {
            var items = new List<ConfigurationItem>();
            var path = GetDbPath();

            if (File.Exists(path))
            {
                using (var db = new SQLiteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();

                    var queryParameters = new List<SQLiteParameter>();
                    var conditions = new List<string>();
                    var sql = @"SELECT id, itemtype, json FROM configurationitem ";

                    conditions.Add("itemtype = @itemType");
                    queryParameters.Add(new SQLiteParameter("@itemType", itemType));

                    if (id != null)
                    {
                        conditions.Add("id = @id");
                        queryParameters.Add(new SQLiteParameter("@id", id));
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

                    using (var cmd = new SQLiteCommand(sql, db))
                    {
                        cmd.Parameters.AddRange(queryParameters.ToArray());

                        using (var reader = await cmd.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                var configItem = new ConfigurationItem
                                {
                                    Id = (string)reader["id"],
                                    ItemType = (string)reader["itemtype"],
                                    Json = (string)reader["json"]
                                };
                                items.Add(configItem);
                            }
                        }
                    }

                    db.Close();
                }
            }

            return items;
        }

        private async Task<ConfigurationItem> Update(ConfigurationItem item)
        {
            var path = GetDbPath();

            //create database if it doesn't exist
            if (!File.Exists(path))
            {
                try
                {
                    using (var db = new SQLiteConnection($"Data Source={path}"))
                    {
                        await db.OpenAsync();
                        using (var cmd = new SQLiteCommand(
                                   "CREATE TABLE configurationitem (id TEXT NOT NULL UNIQUE PRIMARY KEY, itemtype TEXT NOT NULL, json TEXT NOT NULL)",
                                   db))
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
                    using (var cmd = new SQLiteCommand(
                               "INSERT OR REPLACE INTO configurationitem (id, itemtype, json) VALUES (@id, @itemtype, @json)",
                               db))
                    {
                        cmd.Parameters.Add(new SQLiteParameter("@id", item.Id));
                        cmd.Parameters.Add(new SQLiteParameter("@itemtype", item.ItemType));
                        cmd.Parameters.Add(new SQLiteParameter("@json", item.Json));

                        await cmd.ExecuteNonQueryAsync();
                    }

                    tran.Commit();
                }

                db.Close();
            }

            return item;
        }

        public async Task<T> Get<T>(string itemType, string id)
        {
            var items = await GetItems(itemType, id);
            var item = items.FirstOrDefault();
            return JsonConvert.DeserializeObject<T>(item.Json);
        }

        public async Task Add<T>(string itemType, T item)
        {
            await Update(itemType, item);
        }

        public async Task Update<T>(string itemType, T item)
        {

            if (item is AccessStoreItem)
            {

                var configItem = new ConfigurationItem
                {
                    Id = (item as AccessStoreItem).Id,
                    ItemType = typeof(T).Name,
                    Json = JsonConvert.SerializeObject(item)
                };

                await Update(configItem);
            }
            else
            {
                throw new Exception("Could not store item type");
            }
        }

        public async Task<List<T>> GetItems<T>(string itemType)
        {
            var items = await GetItems(itemType, null);
            return items.Select(i => JsonConvert.DeserializeObject<T>(i.Json)).ToList();
        }
    }
}