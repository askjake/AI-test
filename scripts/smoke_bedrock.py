#!/usr/bin/env python3
"""Phase 1 exit gate (CRITICAL): prove Claude can drive a computer tool over Bedrock.

Sends a tiny system+user message plus a blank screenshot and asserts the model returns a
``tool_use`` block (e.g. a ``screenshot`` action). The computer tool is declared per
``computer_tool_mode``: ``beta`` (native ``computer_20251124``), ``custom`` (plain custom
tool, no beta header), or ``auto`` (try beta, fall back to custom on rejection). The script
reports which mode satisfied the gate.

The gate is satisfied if a ``tool_use`` comes back in EITHER mode. Only if both ``beta``
and ``custom`` fail is computer driving truly unavailable — stop and resolve provisioning.

Usage::

    export BEDROCK_MODEL_ID="<inference-profile ARN>"
    export AWS_REGION="us-west-2"
    PYTHONPATH=src python scripts/smoke_bedrock.py

AWS credentials come from the standard credential chain (env / role / profile).
"""

from __future__ import annotations

import base64
import io
import sys

# Ensure `src/` is importable when run as `python scripts/smoke_bedrock.py`.
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from orchestrator.bedrock_client import (  # noqa: E402
    BedrockClient,
    BetaRejectedError,
)
from orchestrator.config import settings  # noqa: E402


def _blank_png_b64() -> str:
    """Return a base64-encoded blank PNG sized to the model display."""
    try:
        from PIL import Image
    except ImportError:
        # 1x1 transparent PNG fallback if Pillow is unavailable.
        raw = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )
        return base64.b64encode(raw).decode("ascii")
    buf = io.BytesIO()
    Image.new("RGB", (settings.model_w, settings.model_h), color=(0, 0, 0)).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def main() -> int:
    client = BedrockClient()
    print(f"[smoke] region={client.region} model={client.model_id}")
    print(f"[smoke] anthropic_version={client.anthropic_version} beta={client.computer_use_beta}")
    print(f"[smoke] computer_tool_mode={client.computer_tool_mode}")

    system = (
        "You are operating a computer via screenshots. To begin, take a screenshot of the "
        "current screen using the computer tool."
    )
    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "Take a screenshot so you can see the current state of the screen.",
                },
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": _blank_png_b64(),
                    },
                },
            ],
        }
    ]

    try:
        result, resolved_mode = client.invoke_computer_use(
            messages=messages, system=system, max_tokens=512
        )
    except BetaRejectedError as exc:
        # Only reachable when mode is forced to 'beta' (auto/custom never raise this here).
        print("\n[FAIL] Computer-use beta/tool REJECTED by Bedrock (mode=beta).")
        print(f"       {exc}")
        print("       => Try computer_tool_mode=auto or =custom, or resolve provisioning.")
        return 2
    except Exception as exc:  # noqa: BLE001 - smoke script surfaces any failure clearly
        print(f"\n[FAIL] Bedrock invoke failed: {exc!r}")
        return 1

    print(f"\n[smoke] resolved_mode={resolved_mode}")
    print(f"[smoke] stop_reason={result.stop_reason} usage={result.usage}")
    for block in result.content:
        if block.type == "text":
            print(f"  text: {block.text!r}")
        elif block.type == "tool_use":
            print(f"  tool_use: name={block.name!r} input={block.input!r}")

    tool_use = result.first_tool_use()
    if tool_use is None:
        print("\n[FAIL] No tool_use block returned — gate NOT satisfied.")
        return 1

    print(f"\n[PASS] Received tool_use '{tool_use.name}' via mode={resolved_mode} — Phase 1 gate satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
