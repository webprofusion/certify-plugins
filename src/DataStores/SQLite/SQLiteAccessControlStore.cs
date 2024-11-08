using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models.Config;
using Certify.Models.Config.AccessControl;
using Certify.Models.Providers;
using Certify.Providers;
using Newtonsoft.Json;

namespace Certify.Datastore.SQLite
{
    class ConfigurationItem
    {
        public string Id { get; set; }
        public string ItemType { get; set; }
        public string Config { get; set; }
    }

    public class SQLiteAccessControlStore : SQLiteStoreBase, IAccessControlStore
    {
        public SQLiteAccessControlStore() { }
        public SQLiteAccessControlStore(string storageSubfolder = null, ILog log = null) : base(storageSubfolder, log) { }

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

        public new async Task<bool> IsInitialised()
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

        /// <summary>
        /// Delete item by key
        /// </summary>
        /// <param name="storageKey"></param>
        /// <returns></returns>
        public async Task<bool> Delete<T>(string itemType, string id)
        {
            try
            {
                await base.Delete(id, itemType);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Return list of items for given type 
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
                    var sql = @"SELECT id, itemtype, config FROM manageditem ";

                    queryParameters.Add(new SQLiteParameter("@itemType", itemType.ToLowerInvariant()));

                    if (id != null)
                    {
                        conditions.Add("id = @id");
                        queryParameters.Add(new SQLiteParameter("@id", id));
                    }

                    sql += $" WHERE itemtype='{itemType.ToLowerInvariant()}' ";

                    if (conditions.Any())
                    {
                        foreach (var c in conditions)
                        {
                            sql += $" AND {c} ";
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
                                    Config = (string)reader["config"]
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

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);
                // save new/modified item into credentials database
                using (var db = new SQLiteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();
                    using (var tran = db.BeginTransaction())
                    {
                        using (var cmd = new SQLiteCommand(
                                   "INSERT OR REPLACE INTO manageditem (id, itemtype, config) VALUES (@id, @itemtype, @config)",
                                   db))
                        {
                            cmd.Parameters.Add(new SQLiteParameter("@id", item.Id));
                            cmd.Parameters.Add(new SQLiteParameter("@itemtype", item.ItemType.ToLowerInvariant()));
                            cmd.Parameters.Add(new SQLiteParameter("@config", item.Config));

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

            return item;
        }

        public async Task<T> Get<T>(string itemType, string id)
        {
            var items = await GetItems(itemType, id);
            var item = items.FirstOrDefault();
            if (item != null)
            {
                return JsonConvert.DeserializeObject<T>(item.Config);
            }
            else
            {
                return default;
            }
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
                    Config = JsonConvert.SerializeObject(item)
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
            return items.Select(i => JsonConvert.DeserializeObject<T>(i.Config)).ToList();
        }
    }
}
