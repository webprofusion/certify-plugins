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

-- Verify the upgrade
SELECT c.name, t.name as type, c.is_nullable
FROM sys.columns c
JOIN sys.types t ON c.user_type_id = t.user_type_id
WHERE c.object_id = OBJECT_ID('manageditem')
ORDER BY c.column_id;
GO
