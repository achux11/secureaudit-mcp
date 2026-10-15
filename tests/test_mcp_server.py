"""End-to-end test: start the MCP server over stdio and call its tools like an AI client would."""

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED_TOOLS = {
    "audit_duplicate_invoices",
    "audit_rbac_anomalies",
    "scrub_text_preview",
    "send_compliance_alert",
    "read_local_dataset_preview",
}


async def _run():
    params = StdioServerParameters(command=sys.executable, args=["-m", "secureaudit"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            dups = await session.call_tool("audit_duplicate_invoices", {})
            preview = await session.call_tool(
                "read_local_dataset_preview", {"file_name": "legacy_billing_q3.csv", "max_lines": 3}
            )
            return tools, json.loads(dups.content[0].text), json.loads(preview.content[0].text)


def test_mcp_tools_end_to_end():
    tools, dups, preview = asyncio.run(_run())
    assert tools == EXPECTED_TOOLS
    assert dups["cross_file_duplicate_groups"] == 2
    assert "[REDACTED_EMAIL]" in preview["preview_scrubbed"]
    assert "@" not in preview["preview_scrubbed"]
