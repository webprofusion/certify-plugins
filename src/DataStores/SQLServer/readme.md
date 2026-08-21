SQL Server Data Store Provider
--------------------

Recommended only if you are familiar with Microsoft SQL Server and require database scaling beyond the default SQLite database.
- Compatible with current versions of SQL Express and higher, Azure SQL Server etc.

# Getting started

- create a `certify` database
- create a login e.g. `certify_app` in SQL Server, specifically for reading/writing the `certify` database
- add a data store connection in the app, then use **Test** and **Apply Migrations** to create the schema

The schema is created and upgraded by the app, so there is no need to run any DDL by hand. See
[Applying the schema](#applying-the-schema) below if the account the service runs as is not allowed to modify
the schema, and [Manual schema setup](#manual-schema-setup) if you would rather your DBA ran the scripts.

# Applying the schema

The database user the service runs as only needs to read and write data - it does not need permission to
create or alter tables:

```
USE [certify]
CREATE USER [certify_app] FOR LOGIN [certify_app]
GO
ALTER ROLE [db_datareader] ADD MEMBER [certify_app]
GO
ALTER ROLE [db_datawriter] ADD MEMBER [certify_app]
GO
```

Schema changes are applied as a separate, explicit operation:

- **Test** on a data store connection reports whether the schema is up to date, needs creating, or needs
  migrating, and whether the credentials on that connection are able to make the change.
- **Apply Migrations** lists the pending changes and applies them. It creates the tables from scratch if the
  database is empty, and upgrades an existing schema otherwise. It is safe to run repeatedly - already applied
  steps are skipped.

If the runtime user has schema modification rights, required migrations are also applied automatically when the
service connects. If it does not, the service reports the outstanding migrations rather than failing, and you
apply them one of two ways:

1. **Using a temporary admin data store connection.** Add a second data store connection pointing at the same
   database, using credentials which can modify the schema (e.g. a `db_owner` login). Run Apply Migrations on
   that connection, then remove it. The runtime connection continues to use the restricted login.
2. **Using the scripts.** Hand `schema-upgrade.sql` to your DBA - it performs the same migrations.

## Upgrading an existing installation

**An existing database is never restructured behind your back.** Migrations are split into two kinds:

- **Required** steps - adding a column or an index, moving rows out of the legacy `credential` table. These are
  additive, and the service applies them on connect when it has the rights to (as previous versions did).
- **Optional** steps - structural changes to an existing table, currently just the composite primary key below.
  These are *never* applied on connect. Test reports them, and they are applied only when you choose Apply
  Migrations or run the script yourself.

So upgrading the application does not require a database upgrade: an existing store keeps working exactly as it
did, and Test reports "Connection OK" plus a note that an optional upgrade is available.

To stop the service applying even the required migrations - leaving every schema change to you - set the
environment variable `CERTIFY_DISABLE_AUTO_SCHEMA_MIGRATION=true`. Outstanding migrations are then logged and
reported in the UI instead of being applied.

# Multiple instances sharing one database

Several Certify instances can share a single database. Every row in `manageditem` is scoped by `instanceid`
(taken from the instance's generated `InstanceId` app setting), so the logical key of a row is
`(id, itemtype, instanceid)` and each instance only ever reads, writes and deletes its own rows.

This means the same item id can legitimately exist for more than one instance - which is why a shared database
needs the primary key to cover all three columns. A database created with the older `PRIMARY KEY (id)` fails
with a duplicate key error as soon as a second instance stores an item with an id already present, or the same
id is used for two different item types.

This is the optional `composite-primary-key` migration. Apply it if you are sharing one database between
instances; a single instance database does not need it and keeps working without it. Applying it rebuilds the
table's clustered index and briefly locks the table, so prefer a maintenance window on a large table.

Rows with an empty `instanceid` are legacy rows from before the column existed - the first instance to start
against the database claims them.

# Manual schema setup

Managed certificates, stored credentials and other configuration items all share the `manageditem` table,
identified by `itemtype`.

```
CREATE TABLE dbo.manageditem
(
    id NVARCHAR(255) NOT NULL,
    itemtype NVARCHAR(100) NOT NULL DEFAULT 'managedcertificate',
    instanceid NVARCHAR(64) NOT NULL DEFAULT '',
    config NVARCHAR(MAX) NOT NULL,
    itemvalue NVARCHAR(MAX) NULL,
    CONSTRAINT PK_manageditem PRIMARY KEY (id, itemtype, instanceid)
)

CREATE INDEX idx_manageditem_itemtype ON dbo.manageditem(itemtype)
CREATE INDEX idx_manageditem_instanceid ON dbo.manageditem(instanceid)
```

To upgrade a database created by an earlier version, run `schema-upgrade.sql`. It is idempotent and can be run
repeatedly.

## Legacy credential table

Older versions kept stored credentials in a separate `credential` table. If that table exists its rows are
moved into `manageditem` as part of the migration and the table is renamed to `credential_legacy`; nothing
needs to be created by hand.

```
CREATE TABLE dbo.credential
(
    id NVARCHAR(255) NOT NULL,
    config NVARCHAR(MAX) NOT NULL,
    protectedvalue NVARCHAR(max) NOT NULL,
    PRIMARY KEY (id)
)
```
