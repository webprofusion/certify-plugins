using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Certify.Models.Config;
using Certify.Models.Hub;
using Certify.Models.Providers;
using Certify.Providers;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace Certify.Datastore.SQLite
{
    /// <summary>
    /// Base class for individual configuration items stored in the database
    /// </summary>
    public class ConfigurationItem
    {
        public string Id { get; set; }
        public string ItemType { get; set; }
        public string Config { get; set; }
    }

    /// <summary>
    /// Strongly typed configuration item for individual objects
    /// </summary>
    /// <typeparam name="T">The type of object being stored</typeparam>
    public class TypedConfigurationItem<T> : ConfigurationItem
    {
        public TypedConfigurationItem()
        {
            ItemType = typeof(T).Name.ToLowerInvariant();
        }

        public TypedConfigurationItem(string id, T item) : this()
        {
            Id = id;
            SetItem(item);
        }

        public void SetItem(T item)
        {
            Config = JsonConvert.SerializeObject(item, Formatting.Indented, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            });
        }

        public T GetItem()
        {
            if (string.IsNullOrEmpty(Config))
            {
                return default(T);
            }

            return JsonConvert.DeserializeObject<T>(Config);
        }
    }

    public class SQLiteConfigurationStore : SQLiteStoreBase, IConfigurationStore
    {
        public SQLiteConfigurationStore() { }
        public SQLiteConfigurationStore(string storageSubfolder = null, ILog log = null, string customDbFileName = null) : base(storageSubfolder, log, customDbFileName)
        {

        }

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
                    Id = "Plugin.DataStores.Configuration.SQLite",
                    ProviderCategoryId = "sqlite",
                    Title = "SQLite",
                    Description = "SQLite based Config Data Store provider"
                };
            }
        }

        public new async Task<bool> IsInitialised()
        {
            try
            {
                await GetItems<ConfigurationStoreItem>("ConfigurationStoreItem");
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Delete item by key and type
        /// </summary>
        /// <param name="itemType">The type of item to delete</param>
        /// <param name="id">The ID of the item to delete</param>
        /// <returns></returns>
        public async Task<bool> Delete<T>(string itemType, string id)
        {
            try
            {
                await base.Delete(id, GetNormalizedItemType<T>(itemType));
                return true;
            }
            catch (Exception ex)
            {
                _log?.Error(ex, "Failed to delete item {ItemType} with ID {Id}", itemType, id);
                return false;
            }
        }

        /// <summary>
        /// Get a specific item by type and ID
        /// </summary>
        /// <typeparam name="T">The type to deserialize to</typeparam>
        /// <param name="itemType">The item type identifier</param>
        /// <param name="id">The item ID</param>
        /// <returns></returns>
        public async Task<T> Get<T>(string itemType, string id)
        {
            var items = await GetConfigurationItems(GetNormalizedItemType<T>(itemType), id);
            var item = items.FirstOrDefault();
            
            if (item != null)
            {
                return JsonConvert.DeserializeObject<T>(item.Config);
            }
            
            return default(T);
        }

        /// <summary>
        /// Add a new item
        /// </summary>
        /// <typeparam name="T">The type of item to add</typeparam>
        /// <param name="itemType">The item type identifier</param>
        /// <param name="item">The item to add</param>
        /// <returns></returns>
        public async Task Add<T>(string itemType, T item)
        {
            await Update(itemType, item);
        }

        /// <summary>
        /// Update an existing item or add if it doesn't exist
        /// </summary>
        /// <typeparam name="T">The type of item to update</typeparam>
        /// <param name="itemType">The item type identifier</param>
        /// <param name="item">The item to update</param>
        /// <returns></returns>
        public async Task Update<T>(string itemType, T item)
        {
            string itemId;
            string normalizedItemType = GetNormalizedItemType<T>(itemType);

            // Extract ID from the item
            if (item is ConfigurationStoreItem configStoreItem)
            {
                itemId = configStoreItem.Id;
            }
            else if (item is IIdentifiable identifiable)
            {
                itemId = identifiable.Id;
            }
            else
            {
                // Try to find an Id property using reflection
                var idProperty = typeof(T).GetProperty("Id");
                if (idProperty != null && idProperty.PropertyType == typeof(string))
                {
                    itemId = (string)idProperty.GetValue(item);
                }
                else
                {
                    throw new ArgumentException($"Item of type {typeof(T).Name} must have an 'Id' property of type string or implement IIdentifiable");
                }
            }

            if (string.IsNullOrEmpty(itemId))
            {
                throw new ArgumentException("Item ID cannot be null or empty");
            }

            var configItem = new TypedConfigurationItem<T>(itemId, item)
            {
                ItemType = normalizedItemType
            };

            await UpdateConfigurationItem(configItem);
        }

        /// <summary>
        /// Get all items of a specific type
        /// </summary>
        /// <typeparam name="T">The type of items to retrieve</typeparam>
        /// <param name="itemType">The item type identifier</param>
        /// <returns></returns>
        public async Task<List<T>> GetItems<T>(string itemType)
        {
            var items = await GetConfigurationItems(GetNormalizedItemType<T>(itemType), null);
            var results = new List<T>();

            foreach (var item in items)
            {
                try
                {
                    var deserializedItem = JsonConvert.DeserializeObject<T>(item.Config);
                    if (deserializedItem != null)
                    {
                        results.Add(deserializedItem);
                    }
                }
                catch (Exception ex)
                {
                    _log?.Error(ex, "Failed to deserialize item {ItemId} of type {ItemType}", item.Id, item.ItemType);
                }
            }

            return results;
        }

        /// <summary>
        /// Get normalized item type for storage
        /// </summary>
        /// <typeparam name="T">The type being stored</typeparam>
        /// <param name="itemType">The provided item type</param>
        /// <returns></returns>
        private string GetNormalizedItemType<T>(string itemType)
        {
            // Use provided itemType if available, otherwise use the type name
            return string.IsNullOrEmpty(itemType) 
                ? typeof(T).Name.ToLowerInvariant() 
                : itemType.ToLowerInvariant();
        }

        /// <summary>
        /// Get configuration items from database
        /// </summary>
        /// <param name="itemType">The item type to filter by</param>
        /// <param name="id">Optional specific ID to retrieve</param>
        /// <returns></returns>
        private async Task<List<ConfigurationItem>> GetConfigurationItems(string itemType, string id = null)
        {
            var items = new List<ConfigurationItem>();
            var path = GetDbPath();

            if (!File.Exists(path))
            {
                return items;
            }

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                using (var db = new SqliteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();

                    var queryParameters = new List<SqliteParameter>();
                    var conditions = new List<string>();
                    var sql = "SELECT id, itemtype, config FROM manageditem WHERE itemtype = @itemType";

                    queryParameters.Add(new SqliteParameter("@itemType", itemType));

                    if (!string.IsNullOrEmpty(id))
                    {
                        sql += " AND id = @id";
                        queryParameters.Add(new SqliteParameter("@id", id));
                    }

                    sql += " ORDER BY id";

                    using (var cmd = new SqliteCommand(sql, db))
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
                }
            }
            catch (Exception ex)
            {
                _log?.Error(ex, "Failed to get configuration items of type {ItemType}", itemType);
            }
            finally
            {
                _dbMutex.Release();
            }

            return items;
        }

        /// <summary>
        /// Update a configuration item in the database
        /// </summary>
        /// <param name="item">The configuration item to update</param>
        /// <returns></returns>
        private async Task UpdateConfigurationItem(ConfigurationItem item)
        {
            var path = GetDbPath();

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                using (var db = new SqliteConnection($"Data Source={path}"))
                {
                    await db.OpenAsync();
                    using (var tran = db.BeginTransaction())
                    {
#if DEBUG
                        // Debug check: ensure no duplicate IDs with different item types
                        var query = "SELECT id, itemtype FROM manageditem WHERE id = @id AND itemtype != @itemType";
                        
                        using (var checkCmd = new SqliteCommand(query, db))
                        {
                            checkCmd.Transaction = tran;
                            checkCmd.Parameters.Add(new SqliteParameter("@id", item.Id));
                            checkCmd.Parameters.Add(new SqliteParameter("@itemType", item.ItemType));

                            using (var reader = await checkCmd.ExecuteReaderAsync())
                            {
                                if (await reader.ReadAsync())
                                {
                                    var existingType = (string)reader["itemtype"];
                                    _log?.Warning("Config Store: Item {Id} already exists with different type {ExistingType}, updating to {NewType}", 
                                        item.Id, existingType, item.ItemType);
                                }
                            }
                        }
#endif

                        using (var cmd = new SqliteCommand(
                                   "INSERT OR REPLACE INTO manageditem (id, itemtype, config) VALUES (@id, @itemtype, @config)",
                                   db))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqliteParameter("@id", item.Id));
                            cmd.Parameters.Add(new SqliteParameter("@itemtype", item.ItemType));
                            cmd.Parameters.Add(new SqliteParameter("@config", item.Config));

                            await cmd.ExecuteNonQueryAsync();
                        }

                        tran.Commit();
                    }
                }
            }
            catch (Exception ex)
            {
                _log?.Error(ex, "Failed to update configuration item {Id} of type {ItemType}", item.Id, item.ItemType);
                throw;
            }
            finally
            {
                _dbMutex.Release();
            }
        }
    }

    /// <summary>
    /// Interface for objects that can provide their own ID
    /// </summary>
    public interface IIdentifiable
    {
        string Id { get; }
    }
}
