using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Certify.Models.Config;
using Certify.Models.Providers;
using Certify.Providers;
using Microsoft.Data.SqlClient;

namespace Certify.Datastore.SQLServer
{
    /// <summary>
    /// The parts of the schema the migrations care about, read in one pass. Migrations decide whether they are
    /// required from this rather than by querying, so that a check can report the outcome of applying the whole
    /// ordered set rather than only the steps which apply to the schema exactly as it stands right now.
    /// </summary>
    internal class SQLServerSchemaSnapshot
    {
        public bool TableExists { get; set; }
        public HashSet<string> Columns { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Indexes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> PrimaryKeyColumns { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool HasLegacyCredentialTable { get; set; }
        public bool HasRowsWithoutItemType { get; set; }

        public bool HasColumn(string name) => Columns.Contains(name);

        public bool HasCompositePrimaryKey => PrimaryKeyColumns.Count == 3
            && PrimaryKeyColumns.Contains("id")
            && PrimaryKeyColumns.Contains("itemtype")
            && PrimaryKeyColumns.Contains("instanceid");
    }

    /// <summary>
    /// A single schema migration step, which can be independently detected and applied
    /// </summary>
    internal class SQLServerMigrationStep
    {
        public string Id { get; set; }
        public string Description { get; set; }

        /// <summary>
        /// Optional steps are structural changes to an existing table. The store works without them, so they
        /// are never applied unattended - only when the operator explicitly asks to upgrade.
        /// </summary>
        public bool IsOptional { get; set; }

        public string OptionalReason { get; set; }

        /// <summary>
        /// Determines whether this step still needs to be applied, given the schema as it will be by the time
        /// this step is reached
        /// </summary>
        public Func<SQLServerSchemaSnapshot, bool> IsRequired { get; set; }

        public Func<SqlConnection, Task> Apply { get; set; }

        /// <summary>
        /// Updates the snapshot to describe the schema after this step has been applied
        /// </summary>
        public Action<SQLServerSchemaSnapshot> Project { get; set; }

        public DataStoreSchemaMigration ToModel() => new DataStoreSchemaMigration
        {
            Id = Id,
            Description = Description,
            IsOptional = IsOptional,
            OptionalReason = OptionalReason ?? string.Empty
        };
    }

    /// <summary>
    /// Schema definition and migrations for the SQL Server 'manageditem' table, shared by the managed item,
    /// credential and configuration stores.
    ///
    /// Schema changes are kept separate from normal data access so that the runtime database user can be
    /// restricted to db_datareader/db_datawriter. Migrations are applied explicitly (using a data store
    /// connection whose credentials have schema modification rights), or opportunistically on startup where the
    /// runtime user happens to have those rights. Structural changes to an existing table are marked optional
    /// and are only ever applied when explicitly requested.
    /// </summary>
    internal static class SQLServerSchema
    {
        /// <summary>
        /// Set to 'true' to stop the service applying any schema change on connection, leaving all migrations
        /// to be applied explicitly
        /// </summary>
        public const string DisableAutoMigrationEnvVar = "CERTIFY_DISABLE_AUTO_SCHEMA_MIGRATION";

        /// <summary>
        /// Guards the migration run so that instances sharing a database cannot apply the same step
        /// concurrently. Session scoped so it can span the multiple statements a step is made of.
        /// </summary>
        private const string SchemaLockResource = "certify_manageditem_schema";
        private const int SchemaLockTimeoutMS = 30 * 1000;

        /// <summary>
        /// The full current schema, used when creating the table from scratch
        /// </summary>
        private const string CreateManagedItemTableSql = @"
            CREATE TABLE manageditem
            (
                id NVARCHAR(255) NOT NULL,
                itemtype NVARCHAR(100) NOT NULL DEFAULT 'managedcertificate',
                instanceid NVARCHAR(64) NOT NULL DEFAULT '',
                config NVARCHAR(MAX) NOT NULL,
                itemvalue NVARCHAR(MAX) NULL,
                CONSTRAINT PK_manageditem PRIMARY KEY (id, itemtype, instanceid)
            );";

        /// <summary>
        /// The ordered set of migrations which take any supported historic schema up to the current one.
        /// Each step is skipped if it has already been applied, so the set is safe to run repeatedly.
        /// </summary>
        private static List<SQLServerMigrationStep> GetMigrations()
        {
            return new List<SQLServerMigrationStep>
            {
                new SQLServerMigrationStep
                {
                    Id = "create-manageditem",
                    Description = "Create the manageditem table",
                    IsRequired = s => !s.TableExists,
                    Apply = async conn =>
                    {
                        await ExecuteNonQuery(conn, CreateManagedItemTableSql);
                        await ExecuteNonQuery(conn, "CREATE INDEX idx_manageditem_itemtype ON manageditem(itemtype);");
                        await ExecuteNonQuery(conn, "CREATE INDEX idx_manageditem_instanceid ON manageditem(instanceid);");
                    },
                    Project = s =>
                    {
                        s.TableExists = true;
                        s.Columns.UnionWith(new[] { "id", "itemtype", "instanceid", "config", "itemvalue" });
                        s.Indexes.UnionWith(new[] { "idx_manageditem_itemtype", "idx_manageditem_instanceid" });
                        s.PrimaryKeyColumns.UnionWith(new[] { "id", "itemtype", "instanceid" });
                        s.HasRowsWithoutItemType = false;
                    }
                },
                new SQLServerMigrationStep
                {
                    Id = "rename-json-to-config",
                    Description = "Rename the legacy 'json' column to 'config'",
                    IsRequired = s => s.TableExists && s.HasColumn("json") && !s.HasColumn("config"),
                    Apply = async conn => await ExecuteNonQuery(conn, "EXEC sp_rename 'manageditem.json', 'config', 'COLUMN';"),
                    Project = s => { s.Columns.Remove("json"); s.Columns.Add("config"); }
                },
                new SQLServerMigrationStep
                {
                    Id = "add-itemtype",
                    Description = "Add the 'itemtype' column",
                    IsRequired = s => s.TableExists && !s.HasColumn("itemtype"),
                    Apply = async conn => await ExecuteNonQuery(conn,
                        "ALTER TABLE manageditem ADD itemtype NVARCHAR(100) NOT NULL DEFAULT 'managedcertificate';"),
                    // the column default backfills existing rows, so the default-itemtype step is not needed after this
                    Project = s => { s.Columns.Add("itemtype"); s.HasRowsWithoutItemType = false; }
                },
                new SQLServerMigrationStep
                {
                    Id = "add-itemvalue",
                    Description = "Add the 'itemvalue' column",
                    IsRequired = s => s.TableExists && !s.HasColumn("itemvalue"),
                    Apply = async conn => await ExecuteNonQuery(conn, "ALTER TABLE manageditem ADD itemvalue NVARCHAR(MAX) NULL;"),
                    Project = s => s.Columns.Add("itemvalue")
                },
                new SQLServerMigrationStep
                {
                    Id = "add-instanceid",
                    Description = "Add the 'instanceid' column, which scopes rows to a certify instance",
                    IsRequired = s => s.TableExists && !s.HasColumn("instanceid"),
                    Apply = async conn => await ExecuteNonQuery(conn,
                        "ALTER TABLE manageditem ADD instanceid NVARCHAR(64) NOT NULL DEFAULT '';"),
                    Project = s => s.Columns.Add("instanceid")
                },
                new SQLServerMigrationStep
                {
                    Id = "default-itemtype",
                    Description = "Set the item type of existing rows to 'managedcertificate'",
                    IsRequired = s => s.TableExists && s.HasColumn("itemtype") && s.HasRowsWithoutItemType,
                    Apply = async conn => await ExecuteNonQuery(conn,
                        "UPDATE manageditem SET itemtype = 'managedcertificate' WHERE itemtype IS NULL OR itemtype = '';"),
                    Project = s => s.HasRowsWithoutItemType = false
                },
                new SQLServerMigrationStep
                {
                    Id = "index-itemtype",
                    Description = "Create the itemtype index",
                    IsRequired = s => s.TableExists && s.HasColumn("itemtype") && !s.Indexes.Contains("idx_manageditem_itemtype"),
                    Apply = async conn => await ExecuteNonQuery(conn, "CREATE INDEX idx_manageditem_itemtype ON manageditem(itemtype);"),
                    Project = s => s.Indexes.Add("idx_manageditem_itemtype")
                },
                new SQLServerMigrationStep
                {
                    Id = "index-instanceid",
                    Description = "Create the instanceid index",
                    IsRequired = s => s.TableExists && s.HasColumn("instanceid") && !s.Indexes.Contains("idx_manageditem_instanceid"),
                    Apply = async conn => await ExecuteNonQuery(conn, "CREATE INDEX idx_manageditem_instanceid ON manageditem(instanceid);"),
                    Project = s => s.Indexes.Add("idx_manageditem_instanceid")
                },
                new SQLServerMigrationStep
                {
                    Id = "composite-primary-key",
                    Description = "Change the primary key to (id, itemtype, instanceid) so multiple instances can share the database",
                    IsOptional = true,
                    OptionalReason = "Only needed if several certify instances share this database, or if the same item id is used for more than one item type. "
                        + "An existing single instance database keeps working with the original primary key. "
                        + "Applying this rebuilds the table's clustered index and briefly locks the table.",
                    IsRequired = s => s.TableExists && s.HasColumn("itemtype") && s.HasColumn("instanceid") && !s.HasCompositePrimaryKey,
                    Apply = ApplyCompositePrimaryKey,
                    Project = s =>
                    {
                        s.PrimaryKeyColumns.Clear();
                        s.PrimaryKeyColumns.UnionWith(new[] { "id", "itemtype", "instanceid" });
                        s.Indexes.UnionWith(new[] { "idx_manageditem_itemtype", "idx_manageditem_instanceid" });
                    }
                },
                new SQLServerMigrationStep
                {
                    Id = "migrate-legacy-credential-table",
                    Description = "Move rows from the legacy 'credential' table into 'manageditem' and rename it",
                    IsRequired = s => s.HasLegacyCredentialTable && s.TableExists
                        && s.HasColumn("itemtype") && s.HasColumn("instanceid") && s.HasColumn("itemvalue"),
                    Apply = MigrateLegacyCredentialTable,
                    Project = s => s.HasLegacyCredentialTable = false
                }
            };
        }

        /// <summary>
        /// Inspect the schema without modifying it, reporting which migrations are outstanding and whether
        /// these credentials are able to apply them.
        /// </summary>
        public static async Task<DataStoreSchemaCheckResult> CheckSchema(string connectionString, ILog log)
        {
            var result = new DataStoreSchemaCheckResult();

            if (string.IsNullOrEmpty(connectionString))
            {
                result.State = DataStoreSchemaState.Unknown;
                result.Message = "No connection string was provided.";
                return result;
            }

            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    await conn.OpenAsync();

                    var snapshot = await LoadSnapshot(conn);
                    var tableExists = snapshot.TableExists;

                    // walk the ordered set, projecting each pending step onto the snapshot so that later steps
                    // are judged against the schema as it will actually be when they are reached
                    foreach (var migration in GetMigrations())
                    {
                        if (migration.IsRequired(snapshot))
                        {
                            result.PendingMigrations.Add(migration.ToModel());
                            migration.Project?.Invoke(snapshot);
                        }
                    }

                    result.CanApplySchemaChanges = await CanApplySchemaChanges(conn, tableExists);

                    var requiredCount = result.RequiredMigrations.Count;
                    var optionalCount = result.OptionalMigrations.Count;

                    if (!tableExists)
                    {
                        result.State = DataStoreSchemaState.NotPresent;
                        result.Message = "The manageditem table does not exist and needs to be created.";
                    }
                    else if (requiredCount > 0)
                    {
                        result.State = DataStoreSchemaState.MigrationRequired;
                        result.Message = $"{requiredCount} schema migration(s) need to be applied.";
                    }
                    else if (optionalCount > 0)
                    {
                        // the store works as it is - an existing installation is not obliged to upgrade
                        result.State = DataStoreSchemaState.Current;
                        result.Message = $"The schema is up to date for normal use. {optionalCount} optional schema upgrade(s) are available.";
                    }
                    else
                    {
                        result.State = DataStoreSchemaState.Current;
                        result.Message = "The schema is up to date.";
                    }

                    conn.Close();
                }
            }
            catch (Exception ex)
            {
                log?.Error(ex, "SQL Server: Failed to check data store schema");
                result.State = DataStoreSchemaState.Unknown;
                result.Message = $"Failed to check the schema: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// Apply outstanding migrations, creating the schema first if it is not present
        /// </summary>
        /// <param name="includeOptional">
        /// When true, optional structural steps are applied as well. Only set this for an explicit operator action.
        /// </param>
        public static async Task<ActionResult<List<DataStoreSchemaMigration>>> ApplySchemaMigrations(string connectionString, ILog log, bool includeOptional = true)
        {
            var applied = new List<DataStoreSchemaMigration>();

            if (string.IsNullOrEmpty(connectionString))
            {
                return new ActionResult<List<DataStoreSchemaMigration>>("No connection string was provided.", false) { Result = applied };
            }

            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    await conn.OpenAsync();

                    if (!await AcquireSchemaLock(conn, log))
                    {
                        return new ActionResult<List<DataStoreSchemaMigration>>(
                            "Timed out waiting for another instance to finish applying schema migrations. Try again shortly.", false)
                        { Result = applied };
                    }

                    try
                    {
                        // re-read inside the lock, another instance may have applied migrations while we waited
                        var snapshot = await LoadSnapshot(conn);

                        foreach (var migration in GetMigrations())
                        {
                            if (!migration.IsRequired(snapshot))
                            {
                                continue;
                            }

                            if (migration.IsOptional && !includeOptional)
                            {
                                log?.Information($"SQL Server: Skipping optional schema migration '{migration.Id}' - apply it explicitly to upgrade.");
                                continue;
                            }

                            try
                            {
                                await migration.Apply(conn);
                                migration.Project?.Invoke(snapshot);
                                applied.Add(migration.ToModel());
                                log?.Information($"SQL Server: Applied schema migration '{migration.Id}' - {migration.Description}");
                            }
                            catch (Exception ex)
                            {
                                log?.Error(ex, $"SQL Server: Schema migration '{migration.Id}' failed");
                                return new ActionResult<List<DataStoreSchemaMigration>>(
                                    $"Schema migration '{migration.Id}' ({migration.Description}) failed: {ex.Message}", false)
                                { Result = applied };
                            }
                        }
                    }
                    finally
                    {
                        await ReleaseSchemaLock(conn, log);
                    }

                    conn.Close();
                }
            }
            catch (Exception ex)
            {
                log?.Error(ex, "SQL Server: Failed to apply schema migrations");
                return new ActionResult<List<DataStoreSchemaMigration>>($"Failed to apply schema migrations: {ex.Message}", false) { Result = applied };
            }

            var message = applied.Count == 0
                ? "The schema was already up to date, no migrations were applied."
                : $"Applied {applied.Count} schema migration(s).";

            return new ActionResult<List<DataStoreSchemaMigration>>(message, true) { Result = applied };
        }

        /// <summary>
        /// Opportunistically bring the schema up to date on startup. Schema changes are not required to succeed:
        /// where the runtime user has no schema modification rights the caller continues with the schema as it is
        /// and reports that a migration is outstanding. Optional structural migrations are never applied here -
        /// an existing installation carries on working untouched until the operator chooses to upgrade.
        /// </summary>
        public static async Task<DataStoreSchemaCheckResult> TryAutoMigrate(string connectionString, ILog log)
        {
            var check = await CheckSchema(connectionString, log);

            if (check.HasOptionalMigrations)
            {
                log?.Information($"SQL Server: {check.OptionalMigrations.Count} optional schema upgrade(s) are available for this data store. The store works without them - apply them from the data store connection settings when convenient.");
            }

            if (!check.IsMigrationRequired)
            {
                return check;
            }

            if (IsAutoMigrationDisabled())
            {
                log?.Warning($"SQL Server: {check.RequiredMigrations.Count} schema migration(s) are outstanding but automatic schema migration is disabled ({DisableAutoMigrationEnvVar}). Apply them from the data store connection settings.");
                return check;
            }

            if (!check.CanApplySchemaChanges)
            {
                log?.Warning($"SQL Server: {check.RequiredMigrations.Count} schema migration(s) are outstanding but this connection does not have schema modification rights. Apply migrations using a data store connection with the required permissions.");
                return check;
            }

            var applyResult = await ApplySchemaMigrations(connectionString, log, includeOptional: false);

            if (!applyResult.IsSuccess)
            {
                log?.Warning($"SQL Server: Automatic schema migration did not complete: {applyResult.Message}");
            }

            return await CheckSchema(connectionString, log);
        }

        private static bool IsAutoMigrationDisabled()
            => string.Equals(Environment.GetEnvironmentVariable(DisableAutoMigrationEnvVar), "true", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Read everything the migration set needs to know about the current schema in one pass
        /// </summary>
        private static async Task<SQLServerSchemaSnapshot> LoadSnapshot(SqlConnection conn)
        {
            var snapshot = new SQLServerSchemaSnapshot
            {
                TableExists = await ScalarExists(conn, "SELECT OBJECT_ID('manageditem', 'U')"),
                HasLegacyCredentialTable = await ScalarExists(conn, "SELECT OBJECT_ID('credential', 'U')")
            };

            if (!snapshot.TableExists)
            {
                return snapshot;
            }

            await ReadStrings(conn, "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('manageditem')", snapshot.Columns);

            await ReadStrings(conn,
                "SELECT name FROM sys.indexes WHERE object_id = OBJECT_ID('manageditem') AND name IS NOT NULL", snapshot.Indexes);

            await ReadStrings(conn, @"
                SELECT c.name
                FROM sys.key_constraints kc
                JOIN sys.index_columns ic ON ic.object_id = kc.parent_object_id AND ic.index_id = kc.unique_index_id
                JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
                WHERE kc.parent_object_id = OBJECT_ID('manageditem') AND kc.type = 'PK'", snapshot.PrimaryKeyColumns);

            if (snapshot.HasColumn("itemtype"))
            {
                snapshot.HasRowsWithoutItemType = await ScalarExists(conn,
                    "SELECT TOP 1 1 FROM manageditem WHERE itemtype IS NULL OR itemtype = ''");
            }

            return snapshot;
        }

        private static async Task<bool> AcquireSchemaLock(SqlConnection conn, ILog log)
        {
            try
            {
                using (var cmd = new SqlCommand("sp_getapplock", conn) { CommandType = System.Data.CommandType.StoredProcedure })
                {
                    cmd.Parameters.Add(new SqlParameter("@Resource", SchemaLockResource));
                    cmd.Parameters.Add(new SqlParameter("@LockMode", "Exclusive"));
                    // session scoped so the lock spans the multiple statements a migration step is made of
                    cmd.Parameters.Add(new SqlParameter("@LockOwner", "Session"));
                    cmd.Parameters.Add(new SqlParameter("@LockTimeout", SchemaLockTimeoutMS));

                    var returnValue = new SqlParameter { Direction = System.Data.ParameterDirection.ReturnValue };
                    cmd.Parameters.Add(returnValue);

                    cmd.CommandTimeout = (SchemaLockTimeoutMS / 1000) + 30;

                    await cmd.ExecuteNonQueryAsync();

                    // >= 0 means the lock was granted
                    return returnValue.Value != null && returnValue.Value != DBNull.Value && Convert.ToInt32(returnValue.Value) >= 0;
                }
            }
            catch (SqlException ex)
            {
                // a restricted user may not be able to take an application lock - migrations will fail on
                // permissions shortly anyway, so carry on rather than blocking here
                log?.Warning($"SQL Server: Could not acquire the schema migration lock, continuing without it: {ex.Message}");
                return true;
            }
        }

        private static async Task ReleaseSchemaLock(SqlConnection conn, ILog log)
        {
            try
            {
                using (var cmd = new SqlCommand("sp_releaseapplock", conn) { CommandType = System.Data.CommandType.StoredProcedure })
                {
                    cmd.Parameters.Add(new SqlParameter("@Resource", SchemaLockResource));
                    cmd.Parameters.Add(new SqlParameter("@LockOwner", "Session"));
                    await cmd.ExecuteNonQueryAsync();
                }
            }
            catch (SqlException ex)
            {
                log?.Warning($"SQL Server: Could not release the schema migration lock: {ex.Message}");
            }
        }

        private static async Task<bool> CanApplySchemaChanges(SqlConnection conn, bool tableExists)
        {
            try
            {
                // ALTER on the table covers the column/index/constraint changes, CREATE TABLE covers first time setup
                var sql = tableExists
                    ? "SELECT HAS_PERMS_BY_NAME('manageditem', 'OBJECT', 'ALTER')"
                    : "SELECT HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE TABLE')";

                using (var cmd = new SqlCommand(sql, conn))
                {
                    var result = await cmd.ExecuteScalarAsync();
                    return result != null && result != DBNull.Value && Convert.ToInt32(result) == 1;
                }
            }
            catch (SqlException)
            {
                return false;
            }
        }

        /// <summary>
        /// Rebuild the primary key as (id, itemtype, instanceid). Applied as a single transaction so that a
        /// failure part way through cannot leave the table without its key or its supporting indexes.
        /// </summary>
        private static async Task ApplyCompositePrimaryKey(SqlConnection conn)
        {
            using (var tran = conn.BeginTransaction())
            {
                try
                {
                    // key columns must be non-nullable to take part in a primary key
                    await ExecuteNonQuery(conn, @"
                        UPDATE manageditem SET itemtype = 'managedcertificate' WHERE itemtype IS NULL;
                        UPDATE manageditem SET instanceid = '' WHERE instanceid IS NULL;", tran);

                    // a column cannot be altered from NULL to NOT NULL while it is part of an index, so drop the
                    // supporting indexes first and recreate them once the constraint is in place
                    await ExecuteNonQuery(conn, @"
                        IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_itemtype' AND object_id = OBJECT_ID('manageditem'))
                        BEGIN
                            DROP INDEX idx_manageditem_itemtype ON manageditem;
                        END
                        IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_instanceid' AND object_id = OBJECT_ID('manageditem'))
                        BEGIN
                            DROP INDEX idx_manageditem_instanceid ON manageditem;
                        END", tran);

                    // only alter a key column if it is actually nullable - existing column widths are otherwise left alone
                    await SetKeyColumnNotNull(conn, tran, "id", "NVARCHAR(255)");
                    await SetKeyColumnNotNull(conn, tran, "itemtype", "NVARCHAR(100)");
                    await SetKeyColumnNotNull(conn, tran, "instanceid", "NVARCHAR(64)");

                    // drop the existing primary key (the name is normally auto-generated, e.g. PK__managedi__3213E83F...)
                    await ExecuteNonQuery(conn, @"
                        DECLARE @pkName SYSNAME;
                        SELECT @pkName = name FROM sys.key_constraints WHERE parent_object_id = OBJECT_ID('manageditem') AND type = 'PK';
                        IF @pkName IS NOT NULL
                        BEGIN
                            DECLARE @sql NVARCHAR(MAX) = N'ALTER TABLE manageditem DROP CONSTRAINT ' + QUOTENAME(@pkName);
                            EXEC sp_executesql @sql;
                        END", tran);

                    await ExecuteNonQuery(conn, "ALTER TABLE manageditem ADD CONSTRAINT PK_manageditem PRIMARY KEY (id, itemtype, instanceid);", tran);

                    await ExecuteNonQuery(conn, @"
                        IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_itemtype' AND object_id = OBJECT_ID('manageditem'))
                        BEGIN
                            CREATE INDEX idx_manageditem_itemtype ON manageditem(itemtype);
                        END
                        IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_instanceid' AND object_id = OBJECT_ID('manageditem'))
                        BEGIN
                            CREATE INDEX idx_manageditem_instanceid ON manageditem(instanceid);
                        END", tran);

                    tran.Commit();
                }
                catch
                {
                    tran.Rollback();
                    throw;
                }
            }
        }

        private static async Task MigrateLegacyCredentialTable(SqlConnection conn)
        {
            var hasInstanceId = await ScalarExists(conn,
                "SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('credential') AND name = 'instanceid'");

            var sourceInstanceId = hasInstanceId ? "ISNULL(c.instanceid, '')" : "''";

            // moving the rows and retiring the source table have to succeed or fail together
            using (var tran = conn.BeginTransaction())
            {
                try
                {
                    await ExecuteNonQuery(conn, $@"
                        INSERT INTO manageditem (id, itemtype, instanceid, config, itemvalue)
                        SELECT c.id, 'credential', {sourceInstanceId}, c.config, c.protectedvalue
                        FROM credential c
                        WHERE NOT EXISTS (
                            SELECT 1 FROM manageditem m
                            WHERE m.id = c.id AND m.itemtype = 'credential' AND m.instanceid = {sourceInstanceId}
                        );", tran);

                    await ExecuteNonQuery(conn, "EXEC sp_rename 'credential', 'credential_legacy';", tran);

                    tran.Commit();
                }
                catch
                {
                    tran.Rollback();
                    throw;
                }
            }
        }

        private static async Task SetKeyColumnNotNull(SqlConnection conn, SqlTransaction tran, string columnName, string columnType)
        {
            using (var cmd = new SqlCommand(
                "SELECT is_nullable FROM sys.columns WHERE object_id = OBJECT_ID('manageditem') AND name = @name", conn, tran))
            {
                cmd.Parameters.Add(new SqlParameter("@name", columnName));
                var result = await cmd.ExecuteScalarAsync();
                if (result == null || result == DBNull.Value || !Convert.ToBoolean(result))
                {
                    return;
                }
            }

            // column names are from a fixed internal list, not user input
            await ExecuteNonQuery(conn, $"ALTER TABLE manageditem ALTER COLUMN {columnName} {columnType} NOT NULL;", tran);
        }

        private static async Task ReadStrings(SqlConnection conn, string sql, HashSet<string> target)
        {
            using (var cmd = new SqlCommand(sql, conn))
            {
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        if (!reader.IsDBNull(0))
                        {
                            target.Add(reader.GetString(0));
                        }
                    }
                }
            }
        }

        private static async Task<bool> ScalarExists(SqlConnection conn, string sql)
        {
            using (var cmd = new SqlCommand(sql, conn))
            {
                var result = await cmd.ExecuteScalarAsync();
                return result != null && result != DBNull.Value;
            }
        }

        private static async Task ExecuteNonQuery(SqlConnection conn, string sql, SqlTransaction tran = null)
        {
            using (var cmd = new SqlCommand(sql, conn, tran))
            {
                await cmd.ExecuteNonQueryAsync();
            }
        }
    }
}
