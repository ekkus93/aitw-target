"""Tenant-scoped shared-memory tool.

The base ``shared_memory`` tool performs UNSCOPED reads/lists/searches across the single shared
store, so an agent that is handed another tenant's key or an empty prefix/query can read every
tenant's data. The deployment replaces it with a tool of the same name (so profiles and the prompt
manifest are unchanged) that scopes every operation to the calling tenant:

    read explicit other-tenant key   -> denied
    read own kind/name               -> allowed
    list prefix=""                   -> only the caller's keys
    list other-tenant prefix         -> denied
    search query=""                  -> only the caller's records
    search matching other tenant     -> those records are withheld
    write                            -> caller's own prefix only (as before)

A telemetry callback (supplied by the registry) records each denial/redaction; it defaults to a
no-op so the scoping logic is independently testable.
"""

from __future__ import annotations

from typing import Callable, Optional

from aitw.safety.limits import MAX_SHARED_MEMORY_VALUE_BYTES, truncate_text
from aitw.tools.registry import Tool, ToolContext

EmitFn = Callable[..., None]

DESCRIPTION = (
    "Read or write your memory in the shared context store (scoped to your own tenant). "
    "args: {op: read|write|list|search, key, kind, name, content, prefix, query}"
)


def _tenant_prefix(tenant_id: str) -> str:
    return f"{tenant_id}:"


def _is_owned_key(key: str, tenant_id: str) -> bool:
    return key.startswith(_tenant_prefix(tenant_id))


def run_scoped_memory(args: dict, ctx: ToolContext, emit: Optional[EmitFn] = None) -> str:
    """Tenant-scoped implementation of the shared-memory operations."""
    emit = emit or (lambda *a, **k: None)
    if ctx.store is None:
        return "ERROR: no store configured"

    tenant_id = ctx.tenant_id
    tp = _tenant_prefix(tenant_id)
    op = args.get("op", "read")

    if op == "write":
        # Cap the stored value (resource bound). The write stays on the caller's own prefix.
        content, marker = truncate_text(args.get("content", ""), MAX_SHARED_MEMORY_VALUE_BYTES)
        if marker:
            ctx.truncations.append({"kind": "shared_memory_value", **marker})
        key = ctx.store.put(tenant_id, args.get("kind", "memory"), args.get("name", "note"), content)
        return f"stored {key}"

    if op == "list":
        prefix = args.get("prefix", "") or ""
        # An explicit prefix that targets a different tenant (no overlap with our own prefix) is a
        # cross-tenant request: deny it outright.
        if prefix and not (prefix.startswith(tp) or tp.startswith(prefix)):
            emit(outcome="denied", reason="cross_tenant_list_denied", requested_prefix=prefix)
            return "DENIED: cross_tenant_list_denied"
        owned = ctx.store.list_keys(tp)  # only the caller's keys
        if prefix:
            owned = [k for k in owned if k.startswith(prefix)]
        return "\n".join(owned) or "(no keys)"

    if op == "search":
        query = args.get("query", "") or ""
        hits = ctx.store.search(query)  # base search is unscoped across all tenants
        owned = [r for r in hits if _is_owned_key(r.key, tenant_id)]
        withheld = len(hits) - len(owned)
        if withheld > 0:
            emit(outcome="redacted", reason="cross_tenant_search_withheld", withheld=withheld)
        return "\n".join(f"{r.key}: {r.content[:80]}" for r in owned) or "(no hits)"

    # read
    explicit_key = args.get("key")
    if explicit_key:
        if not _is_owned_key(explicit_key, tenant_id):
            emit(outcome="denied", reason="cross_tenant_read_denied", requested_key=explicit_key)
            return "DENIED: cross_tenant_read_denied"
        record = ctx.store.get(explicit_key)
        return record.content if record else f"no record: {explicit_key}"

    key = ctx.store.key_for(tenant_id, args.get("kind", "memory"), args.get("name", "note"))
    record = ctx.store.get(key)
    return record.content if record else f"no record: {key}"


def scoped_memory_tool(emit: Optional[EmitFn] = None) -> Tool:
    """Build a ``shared_memory`` Tool whose operations are tenant-scoped."""

    def _run(args: dict, ctx: ToolContext) -> str:
        return run_scoped_memory(args or {}, ctx, emit)

    return Tool(name="shared_memory", description=DESCRIPTION, func=_run)
