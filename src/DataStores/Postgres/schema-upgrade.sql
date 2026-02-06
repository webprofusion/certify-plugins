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

-- Verify the upgrade
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'manageditem' 
ORDER BY ordinal_position;
