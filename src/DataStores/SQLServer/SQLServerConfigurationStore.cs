using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Certify.Models.Config;
using Certify.Models.Hub;
using Certify.Models.Providers;
using Certify.Providers;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;
using Polly;
using Polly.Retry;

namespace Certify.Datastore.SQLServer
{
    public class SQLServerConfigurationStore : IConfigurationStore, IDataStoreSchemaProvider
    {
        private DataStoreSchemaCheckResult _schemaState = new DataStoreSchemaCheckResult();

        private ILog _log;
        private string _connectionString;
        private string _instanceId = "";

        private AsyncRetryPolicy _retryPolicy;

        private static readonly SemaphoreSlim _dbMutex = new SemaphoreSlim(1);
        private const int _semaphoreMaxWaitMS = 10 * 1000;

        private JsonSerializerSettings _jsonSerializerSettings = new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Ignore
        };

        public static ProviderDefinition Definition =>
            new ProviderDefinition
            {
                Id = "Plugin.DataStores.Configuration.SQLServer",
                ProviderCategoryId = "sqlserver",
                Title = "SQL Server",
                Description = "SQL Server based Config Data Store provider"
            };

        public SQLServerConfigurationStore() { }

        public bool Init(string connectionString, ILog log, string instanceId = null)
        {
            _connectionString = connectionString;
            _log = log;
            _instanceId = instanceId ?? "";

            _retryPolicy = Policy
                    .Handle<ArgumentException>()
                    .Or<SqlException>()
                    .WaitAndRetryAsync(3, i => TimeSpan.FromSeconds(1), onRetry: (exception, retryCount, context) =>
                    {
                        _log?.Warning($"Retrying DB operation..{retryCount} {exception}");
                    });

            EnsureSchema().Wait();

            return true;
        }

        public SQLServerConfigurationStore(string connectionString, ILog log = null, string instanceId = null)
        {
            Init(connectionString, log, instanceId);
        }

        /// <summary>
        /// Bring the schema up to date on connection where the connected user has schema modification rights,
        /// otherwise report the outstanding migrations without failing. See SQLServerSchema for the migration set.
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

        public async Task<bool> IsInitialised()
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
        public async Task<bool> Delete<T>(string itemType, string id)
        {
            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                var normalizedItemType = GetNormalizedItemType<T>(itemType);

                using (var conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();
                    using (var tran = conn.BeginTransaction())
                    {
                        using (var cmd = new SqlCommand("DELETE FROM manageditem WHERE id = @id AND itemtype = @itemtype AND instanceid = @instanceid", conn))
                        {
                            cmd.Transaction = tran;
                            cmd.Parameters.Add(new SqlParameter("@id", id));
                            cmd.Parameters.Add(new SqlParameter("@itemtype", normalizedItemType));
                            cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                            await cmd.ExecuteNonQueryAsync();
                        }

                        tran.Commit();
                    }

                    conn.Close();
                }

                return true;
            }
            catch (Exception ex)
            {
                _log?.Error(ex, "Failed to delete item {ItemType} with ID {Id}", itemType, id);
                return false;
            }
            finally
            {
                _dbMutex.Release();
            }
        }

        /// <summary>
        /// Get a specific item by type and ID
        /// </summary>
        public async Task<T> Get<T>(string itemType, string id)
        {
            var items = await GetConfigurationItems(GetNormalizedItemType<T>(itemType), id);
            var item = items.Count > 0 ? items[0] : null;

            if (item != null)
            {
                return JsonConvert.DeserializeObject<T>(item.Config);
            }

            return default(T);
        }

        /// <summary>
        /// Add a new item
        /// </summary>
        public async Task Add<T>(string itemType, T item)
        {
            await Update(itemType, item);
        }

        /// <summary>
        /// Update an existing item or add if it doesn't exist
        /// </summary>
        public async Task Update<T>(string itemType, T item)
        {
            string itemId;
            string normalizedItemType = GetNormalizedItemType<T>(itemType);

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

        public async Task<List<SerializedConfigurationItem>> GetAllSerializedItems()
        {
            return await GetConfigurationItems(itemType: null, id: null);
        }

        public async Task UpsertSerializedItem(SerializedConfigurationItem item)
        {
            await UpdateConfigurationItem(item);
        }

        private string GetNormalizedItemType<T>(string itemType)
        {
            return string.IsNullOrEmpty(itemType)
                ? typeof(T).Name.ToLowerInvariant()
                : itemType.ToLowerInvariant();
        }

        private async Task<List<SerializedConfigurationItem>> GetConfigurationItems(string itemType, string id = null)
        {
            var items = new List<SerializedConfigurationItem>();

            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                await _retryPolicy.ExecuteAsync(async () =>
                {
                    using (var conn = new SqlConnection(_connectionString))
                    {
                        await conn.OpenAsync();

                        var queryParameters = new List<SqlParameter>();
                        var sql = "SELECT id, itemtype, config, itemvalue FROM manageditem WHERE instanceid = @instanceid";
                        queryParameters.Add(new SqlParameter("@instanceid", _instanceId));

                        if (!string.IsNullOrEmpty(itemType))
                        {
                            sql += " AND itemtype = @itemType";
                            queryParameters.Add(new SqlParameter("@itemType", itemType));
                        }

                        if (!string.IsNullOrEmpty(id))
                        {
                            sql += " AND id = @id";
                            queryParameters.Add(new SqlParameter("@id", id));
                        }

                        sql += " ORDER BY id";

                        using (var cmd = new SqlCommand(sql, conn))
                        {
                            cmd.Parameters.AddRange(queryParameters.ToArray());

                            using (var reader = await cmd.ExecuteReaderAsync())
                            {
                                while (await reader.ReadAsync())
                                {
                                    var configItem = new SerializedConfigurationItem
                                    {
                                        Id = (string)reader["id"],
                                        ItemType = (string)reader["itemtype"],
                                        Config = (string)reader["config"],
                                        ItemValue = reader["itemvalue"] as string
                                    };
                                    items.Add(configItem);
                                }
                            }
                        }

                        conn.Close();
                    }
                });
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

        private async Task UpdateConfigurationItem(SerializedConfigurationItem item)
        {
            try
            {
                await _dbMutex.WaitAsync(_semaphoreMaxWaitMS).ConfigureAwait(false);

                await _retryPolicy.ExecuteAsync(async () =>
                {
                    using (var conn = new SqlConnection(_connectionString))
                    {
                        await conn.OpenAsync();

                        using (var tran = conn.BeginTransaction())
                        {
                            // Use MERGE for upsert in SQL Server
                            var sql = @"
                                MERGE INTO manageditem WITH (HOLDLOCK) AS target
                                USING (SELECT @id AS id, @itemtype AS itemtype, @instanceid AS instanceid) AS source
                                ON target.id = source.id AND target.itemtype = source.itemtype AND target.instanceid = source.instanceid
                                WHEN MATCHED THEN
                                    UPDATE SET config = @config, itemvalue = @itemvalue
                                WHEN NOT MATCHED THEN
                                    INSERT (id, itemtype, instanceid, config, itemvalue) VALUES (@id, @itemtype, @instanceid, @config, @itemvalue);";

                            using (var cmd = new SqlCommand(sql, conn))
                            {
                                cmd.Transaction = tran;
                                cmd.Parameters.Add(new SqlParameter("@id", item.Id));
                                cmd.Parameters.Add(new SqlParameter("@itemtype", item.ItemType));
                                cmd.Parameters.Add(new SqlParameter("@instanceid", _instanceId));
                                cmd.Parameters.Add(new SqlParameter("@config", item.Config));
                                cmd.Parameters.Add(new SqlParameter("@itemvalue", (object)item.ItemValue ?? DBNull.Value));
                                await cmd.ExecuteNonQueryAsync();
                            }

                            tran.Commit();
                        }

                        conn.Close();
                    }
                });
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
}
