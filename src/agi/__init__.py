"""AGI-era governance components.

Four modules for governing autonomous and self-improving AI systems:

- rsim: Recursive Self-Improvement Monitor — fingerprint and verify model weights
- ccv: Causal Chain Validator — build causal graphs and project consequences
- dad: Deceptive Alignment Detector — multi-layer alignment verification
- macm: Multi-Agent Coordination Monitor — detect and disrupt harmful coordination
"""

from src.agi.rsim import ModelFingerprint, register_model, check_integrity
from src.agi.ccv import CausalNode, CausalGraph, validate_causal_chain, project_consequences
from src.agi.dad import AlignmentResult, check_alignment
from src.agi.macm import CoordinationReport, monitor_coordination, detect_covert_channels, disrupt_harmful_coordination

__all__ = [
    "ModelFingerprint", "register_model", "check_integrity",
    "CausalNode", "CausalGraph", "validate_causal_chain", "project_consequences",
    "AlignmentResult", "check_alignment",
    "CoordinationReport", "monitor_coordination", "detect_covert_channels", "disrupt_harmful_coordination",
]
