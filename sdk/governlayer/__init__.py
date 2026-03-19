"""GovernLayer Python SDK — The Governance Layer for Agentic AI.

Usage::

    from governlayer import GovernLayer

    gl = GovernLayer(api_key="gl_your_key", base_url="https://api.governlayer.ai")

    # Run governance on an AI system
    decision = gl.govern(
        system_name="loan-scorer",
        reasoning_trace="Approved loan for user 42 based on credit score 720",
    )
    print(decision.governance_action)  # "APPROVE"
"""

__version__ = "0.1.0"

from governlayer.client import GovernLayer
from governlayer.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    GovernLayerError,
    NotFoundError,
    RateLimitError,
    ServerError,
    TimeoutError,
    ValidationError,
)

__all__ = [
    "GovernLayer",
    "GovernLayerError",
    "AuthenticationError",
    "AuthorizationError",
    "ConnectionError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "TimeoutError",
    "ValidationError",
    "__version__",
]
