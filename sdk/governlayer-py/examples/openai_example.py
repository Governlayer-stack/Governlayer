"""Working example: governed OpenAI client.

Run with::

    export OPENAI_API_KEY=sk-...
    export GOVERNLAYER_API_KEY=gl_...
    python examples/openai_example.py
"""
import os
import sys

from governlayer import GovernLayerBlocked
from governlayer.openai_wrapper import OpenAI


def main() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: set OPENAI_API_KEY", file=sys.stderr)
        return 1
    if not os.environ.get("GOVERNLAYER_API_KEY"):
        print("ERROR: set GOVERNLAYER_API_KEY", file=sys.stderr)
        return 1

    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY"],
        # governlayer_api_key picked up from env automatically
        system_name="fraud-detector",
        use_case="transaction_review",
    )

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a transaction fraud analyst."},
                {
                    "role": "user",
                    "content": (
                        "Transaction 9af2: $420 charge on a 2-day-old account from a "
                        "new device. Should we approve? Respond with your reasoning."
                    ),
                },
            ],
        )
        print("LLM response:")
        print(resp.choices[0].message.content)
    except GovernLayerBlocked as exc:
        print("Blocked by GovernLayer:")
        print(" reason:", exc.governance.get("reason", "<n/a>"))
        print(" verdict:", exc.governance)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
