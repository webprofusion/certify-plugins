-- SQL Server Schema Upgrade Script for Certify DataStore
-- Run this script against your existing database if you need to manually upgrade the schema.
-- The plugin will also attempt to auto-upgrade on startup.
--
-- This script is idempotent - it can be run multiple times safely.

-- Step 1: Rename 'json' column to 'config' if it exists (legacy compatibility)
IF EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('manageditem') AND name = 'json')
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('manageditem') AND name = 'config')
    BEGIN
        EXEC sp_rename 'manageditem.json', 'config', 'COLUMN';
        PRINT 'Renamed json column to config';
    END
END
GO

-- Step 2: Add itemtype column if it doesn't exist
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('manageditem') AND name = 'itemtype')
BEGIN
    ALTER TABLE manageditem ADD itemtype NVARCHAR(100) NOT NULL DEFAULT 'managedcertificate';
    PRINT 'Added itemtype column';
END
GO

-- Step 3: Add itemvalue column if it doesn't exist
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('manageditem') AND name = 'itemvalue')
BEGIN
    ALTER TABLE manageditem ADD itemvalue NVARCHAR(MAX) NULL;
    PRINT 'Added itemvalue column';
END
GO

-- Step 4: Update existing records to have correct itemtype if not set
UPDATE manageditem SET itemtype = 'managedcertificate' WHERE itemtype IS NULL OR itemtype = '';
GO

-- Step 5: Create index on itemtype for query performance
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_itemtype' AND object_id = OBJECT_ID('manageditem'))
BEGIN
    CREATE INDEX idx_manageditem_itemtype ON manageditem(itemtype);
    PRINT 'Created index idx_manageditem_itemtype';
END
GO

-- Step 6: Add instanceid column if it doesn't exist
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('manageditem') AND name = 'instanceid')
BEGIN
    ALTER TABLE manageditem ADD instanceid NVARCHAR(64) NOT NULL DEFAULT '';
    PRINT 'Added instanceid column';
END
GO

-- Step 7: Create index on instanceid for query performance
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_instanceid' AND object_id = OBJECT_ID('manageditem'))
BEGIN
    CREATE INDEX idx_manageditem_instanceid ON manageditem(instanceid);
    PRINT 'Created index idx_manageditem_instanceid';
END
GO

-- ---------------------------------------------------------------------------------------------------------
-- Step 8 (OPTIONAL): Migrate the primary key from (id) to (id, itemtype, instanceid).
--
-- SKIP THIS STEP IF YOU DO NOT NEED IT. An existing single instance database keeps working with the original
-- primary key, and the application never applies this change on its own - it is only applied when you run it
-- here or choose "Apply Migrations" on the data store connection.
--
-- Apply it if either of the following is true:
--   * more than one certify instance shares this database, or
--   * the same item id is used for more than one item type
-- in which case an upsert for an existing id under a different itemtype or instanceid takes the insert path
-- and fails with "Violation of PRIMARY KEY constraint ... Cannot insert duplicate key in object 'dbo.manageditem'".
--
-- This rebuilds the table's clustered index and briefly locks the table, so run it in a maintenance window on
-- a large table. It runs in a transaction so a failure leaves the table as it was.
-- ---------------------------------------------------------------------------------------------------------
BEGIN TRANSACTION;

IF NOT EXISTS (
    SELECT 1
    FROM sys.key_constraints kc
    WHERE kc.parent_object_id = OBJECT_ID('manageditem')
        AND kc.type = 'PK'
        AND (SELECT COUNT(*) FROM sys.index_columns ic WHERE ic.object_id = kc.parent_object_id AND ic.index_id = kc.unique_index_id) = 3
        AND NOT EXISTS (
            SELECT 1 FROM sys.index_columns ic
            JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
            WHERE ic.object_id = kc.parent_object_id AND ic.index_id = kc.unique_index_id
                AND c.name NOT IN ('id', 'itemtype', 'instanceid')
        )
)
BEGIN
    UPDATE manageditem SET itemtype = 'managedcertificate' WHERE itemtype IS NULL;
    UPDATE manageditem SET instanceid = '' WHERE instanceid IS NULL;

    -- key columns cannot be altered to NOT NULL while indexed, so drop the supporting indexes first
    IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_itemtype' AND object_id = OBJECT_ID('manageditem'))
        DROP INDEX idx_manageditem_itemtype ON manageditem;
    IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'idx_manageditem_instanceid' AND object_id = OBJECT_ID('manageditem'))
        DROP INDEX idx_manageditem_instanceid ON manageditem;

    ALTER TABLE manageditem ALTER COLUMN id NVARCHAR(255) NOT NULL;
    ALTER TABLE manageditem ALTER COLUMN itemtype NVARCHAR(100) NOT NULL;
    ALTER TABLE manageditem ALTER COLUMN instanceid NVARCHAR(64) NOT NULL;

    DECLARE @pkName SYSNAME;
    SELECT @pkName = name FROM sys.key_constraints WHERE parent_object_id = OBJECT_ID('manageditem') AND type = 'PK';
    IF @pkName IS NOT NULL
    BEGIN
        DECLARE @sql NVARCHAR(MAX) = N'ALTER TABLE manageditem DROP CONSTRAINT ' + QUOTENAME(@pkName);
        EXEC sp_executesql @sql;
    END

    ALTER TABLE manageditem ADD CONSTRAINT PK_manageditem PRIMARY KEY (id, itemtype, instanceid);

    CREATE INDEX idx_manageditem_itemtype ON manageditem(itemtype);
    CREATE INDEX idx_manageditem_instanceid ON manageditem(instanceid);

    PRINT 'Migrated manageditem primary key to (id, itemtype, instanceid)';
END

COMMIT TRANSACTION;
GO

-- Step 9: Migrate credentials from legacy credential table to manageditem table (if legacy table exists)
IF OBJECT_ID('credential', 'U') IS NOT NULL
BEGIN
    -- the oldest credential tables have no instanceid column, so build that part of the statement to suit
    DECLARE @sourceInstanceId NVARCHAR(64) = CASE
        WHEN EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('credential') AND name = 'instanceid')
            THEN N'ISNULL(c.instanceid, '''')'
        ELSE N''''''
    END;

    DECLARE @migrateSql NVARCHAR(MAX) = N'
        INSERT INTO manageditem (id, itemtype, instanceid, config, itemvalue)
        SELECT c.id, ''credential'', ' + @sourceInstanceId + N', c.config, c.protectedvalue
        FROM credential c
        WHERE NOT EXISTS (
            SELECT 1 FROM manageditem m
            WHERE m.id = c.id AND m.itemtype = ''credential'' AND m.instanceid = ' + @sourceInstanceId + N'
        );';

    -- Migrate rows that don't already exist in manageditem
    EXEC sp_executesql @migrateSql;

    -- Rename legacy table
    EXEC sp_rename 'credential', 'credential_legacy';
    PRINT 'Migrated credentials from credential table to manageditem table and renamed legacy table';
END
GO

-- Verify the upgrade
SELECT c.name, t.name as type, c.is_nullable
FROM sys.columns c
JOIN sys.types t ON c.user_type_id = t.user_type_id
WHERE c.object_id = OBJECT_ID('manageditem')
ORDER BY c.column_id;
GO
