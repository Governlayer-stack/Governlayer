"""governlayer-langchain: Governance middleware for LangChain/LangGraph.

Automatically governs every LLM call in a LangChain pipeline --
drift detection, risk scoring, and immutable audit logging happen
transparently via the GovernLayer API.

Quick start
-----------
::

    from governlayer import GovernLayerCallback

    callback = GovernLayerCallback(api_key="gl_xxx", system_name="my-bot")
    llm = ChatGroq(callbacks=[callback])
    llm.invoke("Summarise this contract")
"""

from .callback import GovernanceBlockedError, GovernLayerCallback
from .client import GovernLayerClient
from .decorators import audit_trail, govern, risk_gate
from .decorators import GovernanceViolationError
from .middleware import GovernanceEvent, GovernLayerMiddleware
from .types import GovernanceAction, GovernanceResult, RiskProfile, ScanResult

__all__ = [
    # Callback
    "GovernLayerCallback",
    "GovernanceBlockedError",
    # Middleware
    "GovernLayerMiddleware",
    "GovernanceEvent",
    # Decorators
    "govern",
    "audit_trail",
    "risk_gate",
    "GovernanceViolationError",
    # Client
    "GovernLayerClient",
    # Types
    "GovernanceAction",
    "GovernanceResult",
    "ScanResult",
    "RiskProfile",
]

__version__ = "0.1.0"
