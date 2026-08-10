#!/usr/bin/env python3
"""Minimal NDJSON MCP upstream for mayrun mcp-proxy e2e tests."""

from __future__ import annotations

import json
import sys


def write(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            write(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock-upstream", "version": "0.0.0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            write(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "tools": [
                            {
                                "name": "read_file",
                                "description": "benign read",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                },
                            },
                            {
                                "name": "delete_file",
                                "description": "dangerous delete",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                },
                            },
                            {
                                "name": "run_terminal",
                                "description": "shell",
                                "inputSchema": {"type": "object"},
                            },
                        ]
                    },
                }
            )
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name", "")
            write(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({"ok": True, "tool": name, "upstream": True}),
                            }
                        ]
                    },
                }
            )
        else:
            if mid is not None:
                write(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32601, "message": f"unknown method {method}"},
                    }
                )


if __name__ == "__main__":
    main()
