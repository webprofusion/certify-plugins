﻿SQL Server Data Store Provider
--------------------

Recommended only if you are familiar with Microsoft SQL Server and require database scaling beyond the default SQLite database.
- Compatible with current versions of SQL Express and higher, Auze SQL Server etc.

# Getting started

- - create `certify` database
- create a new user e.g. `certify_app` in SQL Server, specifically for reading/writing the `certify` database

Run script to create table
```
CREATE TABLE dbo.manageditem
(
    id NVARCHAR(255) NOT NULL,
    config NVARCHAR(MAX),
    primary_subject NVARCHAR(500),
    date_expiry datetime,
    PRIMARY KEY (id)
)

```

Grant user permission to work with the database tables:
```
ALTER ROLE [db_datareader] ADD MEMBER [certify_app]
ALTER ROLE [db_datawriter] ADD MEMBER [certify_app]
```