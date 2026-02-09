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

-- Step 8: Add instanceid column for credential table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'credential' AND column_name = 'instanceid') THEN
        ALTER TABLE credential ADD COLUMN instanceid TEXT NOT NULL DEFAULT '';
        RAISE NOTICE 'Added instanceid column to credential table';
    END IF;
END $$;

-- Step 9: Create index on credential.instanceid for query performance
CREATE INDEX IF NOT EXISTS idx_credential_instanceid ON credential(instanceid);

-- Verify the upgrade
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'manageditem' 
ORDER BY ordinal_position;
