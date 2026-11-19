---
name: "sql-migration-safety-guard"
description: "Use when writing, reviewing, or running SQL, Alembic, Drizzle, or Prisma database migrations in backend services to catch non-concurrent CREATE INDEX locks, destructive DROP TABLE or TRUNCATE statements without safeguards, NOT NULL column additions lacking defaults, and unguarded DELETE statements before production rollout. Do not trigger for SELECT query performance tuning or ORM read queries."
version: "1.0.0"
track: "arch-quality"
tags:
  - "sql"
  - "migrations"
  - "postgresql"
  - "alembic"
  - "zero-downtime"
routing_signals:
  languages: ["sql", "python", "typescript"]
  files_any: ["alembic.ini", "prisma/schema.prisma", "drizzle.config.ts", "knexfile.js"]
  dependencies_any: ["alembic", "prisma", "drizzle-orm", "sqlalchemy", "typeorm"]
  active_file_globs: ["**/*.sql", "**/migrations/**/*.py", "**/migrations/**/*.ts"]
  negative_triggers:
    - "Do not trigger for read-only SELECT query indexing advice or ORM read queries."
entrypoints:
  scripts:
    - path: "scripts/audit_sql_migrations.py"
      description: "Deterministic migration scanner detecting non-concurrent indexes, unguarded DROP/TRUNCATE/DELETE operations, and unsafe NOT NULL column alters."
---

# SQL Migration Safety Guard (`sql-migration-safety-guard`)

## When to Use This Skill
Invoke before applying `.sql` DDL migrations or Alembic/Prisma/Drizzle migration scripts against shared staging or production databases.

## Mandatory Execution Workflow

1. **Audit Migration Files First:**
   ```bash
   python catalog/arch-quality/sql-migration-safety-guard/scripts/audit_sql_migrations.py --path . --json
   ```
   Review `findings[]` ordered by `error` and `warning`.

2. **Prevent Production Table Locks & Data Loss:**
   - Replace blocking `CREATE [UNIQUE] INDEX` with `CREATE INDEX CONCURRENTLY` outside transactions (`non-concurrent-index-creation`).
   - Add `DEFAULT` or create nullable column + backfill before applying `SET NOT NULL` (`not-null-column-without-default`).
   - Protect `DROP TABLE` / `DROP COLUMN` with staged expand-and-contract rollouts and `IF EXISTS`, and block bare `TRUNCATE` or un-filtered `DELETE FROM <table>` (`destructive-ddl-or-delete`).

3. **Re-Verify:**
   Re-run `audit_sql_migrations.py --path . --json` until `"status": "ok"`.

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `non-concurrent-index-creation` | `warning` | `CREATE INDEX` without `CONCURRENTLY` locks table writes during build. |
| `not-null-column-without-default` | `error` | `ADD COLUMN ... NOT NULL` without `DEFAULT` fails on populated tables or forces table rewrite. |
| `destructive-ddl-or-delete` | `error` | Unguarded `DROP TABLE`, `TRUNCATE`, or `DELETE FROM` missing `WHERE`. |
