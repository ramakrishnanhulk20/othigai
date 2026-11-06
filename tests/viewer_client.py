#!/usr/bin/env python3
"""Attaches to the gateway the way a person's chat client does, types a slash command, then a turn.

Runs under the Python environment Hermes itself uses, so it is started by the end-to-end test
and never imported. Every approval prompt is answered with --answer, as a person would.
"""

import argparse
import asyncio
import json
import sys
import time
import uuid
from pathlib import Path

QUIET_KINDS = ("message.delta", "thinking.delta", "reasoning.delta", "status.update")


async def run(args: argparse.Namespace) -> int:
    from hermes_cli.gateway_client import connect_gateway

    events = []
    deadline = time.monotonic() + args.timeout
    async with connect_gateway() as client:
        snapshot = await client.rpc("session.create", request_id=uuid.uuid4().hex, source="cli", cwd=args.cwd)
        session_id = snapshot["stored_session_id"]
        events.append({"event": "session", "session_id": session_id})
        reply = await client.rpc("slash.exec", session_id=session_id, command=args.slash, _timeout=60)
        events.append({"event": "slash_reply", "reply": str(reply)[:600]})
        await client.rpc("prompt.submit", session_id=session_id, input_id=uuid.uuid4().hex, text=args.text)
        while time.monotonic() < deadline:
            frame = await asyncio.wait_for(client.events.get(), timeout=deadline - time.monotonic())
            params = frame.get("params", {}) if isinstance(frame, dict) else {}
            kind, payload = params.get("type"), params.get("payload", {})
            if kind in QUIET_KINDS:
                continue
            events.append({"event": "frame", "kind": kind, "payload": str(payload)[:400]})
            if kind == "approval.request":
                answer = await client.rpc("approval.respond", session_id=session_id, choice=args.answer,
                                          execution_generation=payload.get("execution_generation"),
                                          prompt_id=payload.get("prompt_id"))
                events.append({"event": "answered", "choice": args.answer, "reply": str(answer)[:200]})
            if kind == "message.complete" and params.get("session_id") == session_id:
                break
    args.out.write_text(json.dumps(events, indent=1), encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--slash", required=True)
    parser.add_argument("--text", required=True)
    parser.add_argument("--answer", default="deny")
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--out", type=Path, required=True)
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
