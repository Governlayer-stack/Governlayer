"""Working example: governed Anthropic client.

Run with::

    export ANTHROPIC_API_KEY=sk-ant-...
    export GOVERNLAYER_API_KEY=gl_...
    python examples/anthropic_example.py
"""
import os
import sys

from governlayer import GovernLayerBlocked
from governlayer.anthropic_wrapper import Anthropic


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: set ANTHROPIC_API_KEY", file=sys.stderr)
        return 1
    if not os.environ.get("GOVERNLAYER_API_KEY"):
        print("ERROR: set GOVERNLAYER_API_KEY", file=sys.stderr)
        return 1

    client = Anthropic(
        api_key=os.environ["ANTHROPIC_API_KEY"],
        system_name="claims-bot",
        use_case="insurance_claims",
    )

    try:
        resp = client.messages.create(
            model="claude-3-5-sonnet-latest",
            max_tokens=512,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Claim 7781 — auto collision, $4,200, policyholder has 7 yrs "
                        "no-claims. Should we approve? Respond with your reasoning."
                    ),
                }
            ],
        )
        text = "".join(block.text for block in resp.content if hasattr(block, "text"))
        print("LLM response:")
        print(text)
    except GovernLayerBlocked as exc:
        print("Blocked by GovernLayer:")
        print(" reason:", exc.governance.get("reason", "<n/a>"))
        print(" verdict:", exc.governance)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
