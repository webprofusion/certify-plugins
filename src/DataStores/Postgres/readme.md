Postgres Data Store Provider
--------------------

Recommended only if you are familiar with postgres and require database scaling beyond the default SQLite database.
- Compatible with latest versions of PostgreSQL and Postgres compatible databases such as Google AlloyDB

# Getting started

- create a new user e.g. `certify_app` in postgres specifically for reading/writing the Certify database
- create `certify` database

Run script to create table:

```
CREATE TABLE IF NOT EXISTS public.manageditem
(
    id text NOT NULL,
    config jsonb NOT NULL,
    CONSTRAINT manageditem_pkey PRIMARY KEY (id)
);

```

Grant user permission to work with the `manageditem` table:
```
GRANT ALL ON TABLE public.manageditem TO certify_app;
```

Full example:
```
CREATE USER certify_app WITH encrypted password 'certify_app_user_pwd';
            
CREATE DATABASE certify

-- create managed items table
CREATE TABLE IF NOT EXISTS manageditem
(
	id text NOT NULL,
	config jsonb NOT NULL,
	CONSTRAINT manageditem_pkey PRIMARY KEY (id)
);

-- Grant user permission to work with the `manageditem` table:
GRANT ALL ON TABLE manageditem TO certify_app;
```