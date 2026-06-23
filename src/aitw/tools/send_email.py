"""send_email tool: MOCK email. No real delivery — records to ctx.sent_emails only."""

from __future__ import annotations

from aitw.tools.registry import Tool, ToolContext


def _run(args: dict, ctx: ToolContext) -> str:
    record = {
        "to": args.get("to", ""),
        "subject": args.get("subject", ""),
        "body": args.get("body", ""),
    }
    ctx.sent_emails.append(record)
    return f"MOCK-EMAIL queued to {record['to']} (id=mock-{len(ctx.sent_emails)})"


TOOL = Tool(
    name="send_email",
    description="Send an email (MOCK — no real delivery). args: {to, subject, body}",
    func=_run,
)
