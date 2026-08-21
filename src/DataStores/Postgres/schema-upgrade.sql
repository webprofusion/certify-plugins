-- PostgreSQL Schema Upgrade Script for Certify DataStore
-- Run this script against your existing database if you need to manually upgrade the schema.
-- The plugin will also attempt to auto-upgrade on startup.
--
-- This script is idempotent - it can be run multiple times safely.

-- Step 1: Rename 'json' column to 'config' if it exists (legacy compatibility)
DO $$ 
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'manageditem' AND column_name = 'json') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'manageditem' AND column_name = 'config') THEN
            ALTER TABLE manageditem RENAME COLUMN json TO config;
            RAISE NOTICE 'Renamed json column to config';
        END IF;
    END IF;
END $$;

-- Step 2: Add itemtype column if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'manageditem' AND column_name = 'itemtype') THEN
        ALTER TABLE manageditem ADD COLUMN itemtype TEXT NOT NULL DEFAULT 'managedcertificate';
        RAISE NOTICE 'Added itemtype column';
    END IF;
END $$;

-- Step 3: Add itemvalue column if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'manageditem' AND column_name = 'itemvalue') THEN
        ALTER TABLE manageditem ADD COLUMN itemvalue TEXT NULL;
        RAISE NOTICE 'Added itemvalue column';
    END IF;
END $$;

-- Step 4: Update existing records to have correct itemtype if not set
UPDATE manageditem SET itemtype = 'managedcertificate' WHERE itemtype IS NULL OR itemtype = '';

-- Step 5: Create index on itemtype for query performance
CREATE INDEX IF NOT EXISTS idx_manageditem_itemtype ON manageditem(itemtype);

-- Step 6: Add instanceid column if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'manageditem' AND column_name = 'instanceid') THEN
        ALTER TABLE manageditem ADD COLUMN instanceid TEXT NOT NULL DEFAULT '';
        RAISE NOTICE 'Added instanceid column';
    END IF;
END $$;

-- Step 7: Create index on instanceid for query performance
CREATE INDEX IF NOT EXISTS idx_manageditem_instanceid ON manageditem(instanceid);

-- -----------------------------------------------------------------------------------------------------------
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
-- and fails with a duplicate key error.
--
-- This rewrites the primary key index and briefly locks the table, so run it in a maintenance window on a
-- large table. The DO block is a single transaction, so a failure leaves the table as it was.
-- -----------------------------------------------------------------------------------------------------------
DO $$
DECLARE pk_name TEXT;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        WHERE c.conrelid = 'manageditem'::regclass
            AND c.contype = 'p'
            AND (
                SELECT array_agg(a.attname::text ORDER BY a.attname::text)
                FROM unnest(c.conkey) k
                JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k
            ) = ARRAY['id', 'instanceid', 'itemtype']
    ) THEN
        UPDATE manageditem SET itemtype = 'managedcertificate' WHERE itemtype IS NULL;
        UPDATE manageditem SET instanceid = '' WHERE instanceid IS NULL;

        ALTER TABLE manageditem ALTER COLUMN id SET NOT NULL;
        ALTER TABLE manageditem ALTER COLUMN itemtype SET NOT NULL;
        ALTER TABLE manageditem ALTER COLUMN instanceid SET NOT NULL;

        SELECT conname INTO pk_name FROM pg_constraint
        WHERE conrelid = 'manageditem'::regclass AND contype = 'p';

        IF pk_name IS NOT NULL THEN
            EXECUTE format('ALTER TABLE manageditem DROP CONSTRAINT %I', pk_name);
        END IF;

        ALTER TABLE manageditem ADD CONSTRAINT manageditem_pkey PRIMARY KEY (id, itemtype, instanceid);
        RAISE NOTICE 'Migrated manageditem primary key to (id, itemtype, instanceid)';
    END IF;
END $$;

-- Step 9: Migrate credentials from legacy credential table to manageditem table (if legacy table exists)
DO $$
DECLARE source_instanceid TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'credential') THEN
        -- the oldest credential tables have no instanceid column, so build that part of the statement to suit
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'credential' AND column_name = 'instanceid'
        ) THEN
            source_instanceid := 'COALESCE(c.instanceid, '''')';
        ELSE
            source_instanceid := '''''';
        END IF;

        -- Migrate rows that don't already exist in manageditem
        EXECUTE format($fmt$
            INSERT INTO manageditem (id, itemtype, instanceid, config, itemvalue)
            SELECT c.id, 'credential', %1$s, c.config, c.protectedvalue
            FROM credential c
            WHERE NOT EXISTS (
                SELECT 1 FROM manageditem m
                WHERE m.id = c.id AND m.itemtype = 'credential' AND m.instanceid = %1$s
            )$fmt$, source_instanceid);

        -- Rename legacy table
        ALTER TABLE credential RENAME TO credential_legacy;
        RAISE NOTICE 'Migrated credentials from credential table to manageditem table and renamed legacy table';
    END IF;
END $$;

-- Verify the upgrade
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'manageditem' 
ORDER BY ordinal_position;
