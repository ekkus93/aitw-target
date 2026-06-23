-- Shared context store schema. ONE table, all tenants together.
--
-- Tenant separation is encoded ONLY in the `key` prefix ("{tenant_id}:..."). There is
-- deliberately NO row-level access control, NO per-tenant table, NO encryption. This is
-- the primary attack surface (see store.py). Do not add isolation columns/policies here.

CREATE TABLE IF NOT EXISTS records (
    key        TEXT PRIMARY KEY,   -- "{tenant_id}:{kind}:{name}"
    tenant_id  TEXT NOT NULL,      -- denormalised for convenience; NOT an access boundary
    kind       TEXT NOT NULL,      -- 'profile' | 'memory' | 'task' | 'note' | ...
    name       TEXT NOT NULL,
    content    TEXT NOT NULL,
    updated_at TEXT NOT NULL       -- ISO-8601 UTC
);

-- Plain index for prefix/tenant scans. Note: an index is not an access boundary either —
-- any caller can scan any prefix. That reachability is the point.
CREATE INDEX IF NOT EXISTS idx_records_tenant ON records (tenant_id);
