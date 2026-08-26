#!/bin/bash
# Creates one database per service on first start of the Postgres container.
# Each service owns its schema outright — there is no shared table between them.
set -euo pipefail

for database in $(echo "$POSTGRES_MULTIPLE_DATABASES" | tr ',' ' '); do
  echo "Creating database '$database'"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
    CREATE DATABASE $database;
    GRANT ALL PRIVILEGES ON DATABASE $database TO $POSTGRES_USER;
SQL
done
