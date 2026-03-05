"""Achonye — The Leader of the GovernLayer Agentic Ecosystem.

Named after the Igbo word meaning "one who leads/governs", Achonye is the supreme
orchestrator that understands the full ecosystem and delegates to the right
intelligence at the right time.

Architecture:
    ACHONYE (Leader) — Claude Opus 4.6
        Understands intent, decomposes tasks, makes final decisions
        |
    THE BOARD — Strategic advisors
        Claude Sonnet (governance), Gemini Pro (facts), GPT-4o (verification)
        Consulted on complex/critical decisions
        |
    THE VALIDATOR — Consensus layer
        Multi-LLM voting, Chain-of-Verification, Adversarial Debate
        Activated on critical governance decisions
        |
    THE OPERATORS — Specialized workers
        Local (Ollama): Llama, Mistral, DeepSeek-R1, Phi — simple tasks, privacy
        Cloud: Groq (fast), Devstral (code), Grok (search), Kimi (multimodal)
        Each operator handles what they're best at

Token Economics:
    - Trivial tasks -> LOCAL (zero cost)
    - Simple tasks -> LOCAL or Groq (near-zero)
    - Moderate tasks -> Standard cloud via OpenRouter
    - Complex tasks -> Premium cloud
    - Critical tasks -> Premium + consensus validation
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from enum import Enum

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm.providers import (
    ModelCapability,
    ModelTier,
    get_model,
    get_profile,
    list_models,
    MODEL_REGISTRY,
)
from src.llm.router import (
    TaskComplexity,
    RoutingDecision,
    route_task,
)
from src.llm.consensus import (
    ConsensusStrategy,
    ConsensusResult,
    run_consensus,
)

logger = logging.getLogger(__name__)


ACHONYE_SYSTEM = """You are Achonye — the supreme AI governance orchestrator for the GovernLayer ecosystem.

Your name means "one who leads/governs" in Igbo. You are the Leader.

Your ecosystem:
- THE BOARD: Claude Sonnet (governance), Gemini Pro (facts), GPT-4o (verification)
- THE VALIDATOR: Multi-LLM consensus for critical decisions
- THE OPERATORS: Local models (Llama, Mistral, DeepSeek) for simple/private tasks,
  Cloud specialists (Groq, Devstral, Grok, Kimi) for heavy lifting

Your responsibilities:
1. UNDERSTAND the full intent behind every request
2. DECOMPOSE complex tasks into subtasks matched to the right intelligence
3. DELEGATE to the optimal model (local for simple, cloud for complex)
4. VALIDATE critical outputs through multi-LLM consensus
5. SYNTHESIZE final answers from your ecosystem's collective intelligence
6. RECORD all decisions to the immutable audit ledger

You ALWAYS think about token economics:
- Can a local model handle this? Send it there (zero cost).
- Does this need search grounding? Route to Gemini.
- Is this a security/compliance decision? Use consensus validation.
- Is this simple formatting? Use Phi-3 locally.

You lead with wisdom. You delegate with precision. You verify with rigor.
"""


class AchonyeAction(str, Enum):
    """Actions Achonye can take."""
    DIRECT_ANSWER = "direct"           # Answer immediately (trivial)
    DELEGATE_LOCAL = "delegate_local"  # Send to local operator
    DELEGATE_CLOUD = "delegate_cloud"  # Send to cloud specialist
    CONSULT_BOARD = "consult_board"    # Ask board for strategic input
    VALIDATE = "validate"              # Run consensus validation
    DECOMPOSE = "decompose"            # Break into subtasks
    ESCALATE_HUMAN = "escalate_human"  # Requires human decision


@dataclass
class AchonyeDecision:
    """A record of Achonye's orchestration decision."""
    task: str
    action: AchonyeAction
    routing: RoutingDecision
    models_used: list[str] = field(default_factory=list)
    result: str = ""
    consensus: Optional[ConsensusResult] = None
    subtask_results: list[dict] = field(default_factory=list)
    tokens_saved_estimate: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_trail: list[str] = field(default_factory=list)


class Achonye:
    """The Leader — supreme orchestrator of the GovernLayer ecosystem.

    Usage:
        achonye = Achonye()
        result = await achonye.process("Audit this AI system for EU AI Act compliance")
    """

    def __init__(
        self,
        prefer_local: bool = True,
        consensus_on_critical: bool = True,
        leader_model: str = "claude-opus",
        board_models: list[str] | None = None,
    ):
        self.prefer_local = prefer_local
        self.consensus_on_critical = consensus_on_critical
        self.leader_model = leader_model
        self.board_models = board_models or ["claude-sonnet", "gemini-pro", "gpt4o"]
        self._history: list[AchonyeDecision] = []

    async def process(
        self,
        task: str,
        force_model: Optional[str] = None,
        force_strategy: Optional[ConsensusStrategy] = None,
        context: Optional[dict] = None,
    ) -> AchonyeDecision:
        """Process a task through the Achonye hierarchy.

        This is the main entry point. Achonye will:
        1. Analyze the task
        2. Route to the optimal model(s)
        3. Execute with appropriate validation
        4. Return a full decision record
        """
        # Step 1: Route
        routing = route_task(
            task,
            force_model=force_model,
            prefer_local=self.prefer_local,
        )

        decision = AchonyeDecision(
            task=task,
            action=self._determine_action(routing),
            routing=routing,
        )
        decision.audit_trail.append(
            f"ROUTED: {routing.reason}"
        )

        # Step 2: Execute based on action
        if decision.action == AchonyeAction.DIRECT_ANSWER:
            decision = await self._handle_direct(decision)

        elif decision.action == AchonyeAction.DELEGATE_LOCAL:
            decision = await self._handle_delegate(decision)

        elif decision.action == AchonyeAction.DELEGATE_CLOUD:
            decision = await self._handle_delegate(decision)

        elif decision.action == AchonyeAction.CONSULT_BOARD:
            decision = await self._handle_board_consultation(decision)

        elif decision.action == AchonyeAction.VALIDATE:
            strategy = force_strategy or ConsensusStrategy.ADVERSARIAL_DEBATE
            decision = await self._handle_validation(decision, strategy)

        elif decision.action == AchonyeAction.DECOMPOSE:
            decision = await self._handle_decompose(decision, context)

        elif decision.action == AchonyeAction.ESCALATE_HUMAN:
            decision.result = (
                f"HUMAN REVIEW REQUIRED: This task has been flagged as critical "
                f"governance matter requiring human oversight.\n"
                f"Task: {task}\n"
                f"Routing: {routing.reason}"
            )
            decision.audit_trail.append("ESCALATED to human review")

        # Record
        self._history.append(decision)
        return decision

    def _determine_action(self, routing: RoutingDecision) -> AchonyeAction:
        """Determine the right action based on routing analysis."""
        if routing.task_complexity == TaskComplexity.TRIVIAL:
            return AchonyeAction.DIRECT_ANSWER

        if routing.task_complexity == TaskComplexity.SIMPLE:
            profile = get_profile(routing.primary_model)
            if profile.tier == ModelTier.LOCAL:
                return AchonyeAction.DELEGATE_LOCAL
            return AchonyeAction.DELEGATE_CLOUD

        if routing.task_complexity == TaskComplexity.MODERATE:
            return AchonyeAction.DELEGATE_CLOUD

        if routing.task_complexity == TaskComplexity.COMPLEX:
            return AchonyeAction.CONSULT_BOARD

        if routing.task_complexity == TaskComplexity.CRITICAL:
            if self.consensus_on_critical and routing.requires_consensus:
                return AchonyeAction.VALIDATE
            return AchonyeAction.CONSULT_BOARD

        return AchonyeAction.DELEGATE_CLOUD

    async def _handle_direct(self, decision: AchonyeDecision) -> AchonyeDecision:
        """Handle trivial tasks — single model, no validation."""
        model_name = decision.routing.primary_model
        model = get_model(model_name)
        decision.models_used.append(model_name)

        response = await model.ainvoke([HumanMessage(content=decision.task)])
        decision.result = response.content
        decision.tokens_saved_estimate = self._estimate_savings(model_name)
        decision.audit_trail.append(f"DIRECT: {model_name} responded")
        return decision

    async def _handle_delegate(self, decision: AchonyeDecision) -> AchonyeDecision:
        """Delegate to a specialist operator."""
        model_name = decision.routing.primary_model
        model = get_model(model_name)
        decision.models_used.append(model_name)

        profile = get_profile(model_name)
        system = (
            f"You are a specialist operator in the GovernLayer ecosystem. "
            f"Your strength: {profile.description}. "
            f"Be precise, concise, and actionable."
        )
        response = await model.ainvoke([
            SystemMessage(content=system),
            HumanMessage(content=decision.task),
        ])
        decision.result = response.content
        decision.tokens_saved_estimate = self._estimate_savings(model_name)
        decision.audit_trail.append(f"DELEGATED: {model_name} ({profile.tier.value})")
        return decision

    async def _handle_board_consultation(self, decision: AchonyeDecision) -> AchonyeDecision:
        """Consult the Board — multiple senior models provide strategic input."""
        # Get input from board members in parallel
        board_tasks = []
        for board_model in self.board_models:
            try:
                model = get_model(board_model)
                profile = get_profile(board_model)
                system = (
                    f"You are a Board member of the GovernLayer AI governance ecosystem. "
                    f"Your specialty: {profile.description}. "
                    f"Provide your expert perspective on this matter. Be specific and actionable."
                )
                board_tasks.append(
                    model.ainvoke([
                        SystemMessage(content=system),
                        HumanMessage(content=decision.task),
                    ])
                )
                decision.models_used.append(board_model)
            except Exception as e:
                logger.warning(f"Board member {board_model} unavailable: {e}")

        if not board_tasks:
            # Fallback: leader handles it alone
            return await self._handle_delegate(decision)

        board_responses = await asyncio.gather(*board_tasks, return_exceptions=True)
        board_input = []
        for model_name, resp in zip(decision.models_used, board_responses):
            if isinstance(resp, Exception):
                logger.warning(f"Board member {model_name} failed: {resp}")
            else:
                board_input.append(f"[{model_name}]: {resp.content}")

        # Achonye synthesizes board input
        leader = get_model(self.leader_model)
        decision.models_used.append(self.leader_model)
        synthesis_prompt = (
            f"You are Achonye, the Leader. Your Board has provided their perspectives "
            f"on this task:\n\n"
            f"TASK: {decision.task}\n\n"
            f"BOARD INPUT:\n" + "\n\n".join(board_input) + "\n\n"
            f"Synthesize the Board's input into a single, authoritative response. "
            f"Resolve any disagreements. Cite which Board member's perspective you're "
            f"drawing from when relevant."
        )
        response = await leader.ainvoke([
            SystemMessage(content=ACHONYE_SYSTEM),
            HumanMessage(content=synthesis_prompt),
        ])
        decision.result = response.content
        decision.audit_trail.append(
            f"BOARD CONSULTED: {len(board_input)} members responded, Leader synthesized"
        )
        return decision

    async def _handle_validation(
        self,
        decision: AchonyeDecision,
        strategy: ConsensusStrategy,
    ) -> AchonyeDecision:
        """Run consensus validation for critical decisions."""
        models = decision.routing.consensus_models or ["llama-groq", "gemini-pro", "deepseek-v3"]
        decision.models_used.extend(models)

        consensus = await run_consensus(
            decision.task,
            strategy=strategy,
            models=models,
        )
        decision.consensus = consensus
        decision.result = consensus.final_answer

        if consensus.confidence < 0.5:
            decision.audit_trail.append(
                f"VALIDATED ({strategy.value}): LOW confidence ({consensus.confidence:.0%}) — "
                f"flagging for human review"
            )
            decision.action = AchonyeAction.ESCALATE_HUMAN
            decision.result = (
                f"CONSENSUS FAILED (confidence: {consensus.confidence:.0%})\n"
                f"Strategy: {strategy.value}\n"
                f"Dissent: {consensus.dissenting_views}\n\n"
                f"Best answer available:\n{consensus.final_answer}"
            )
        else:
            decision.audit_trail.append(
                f"VALIDATED ({strategy.value}): confidence={consensus.confidence:.0%}, "
                f"agreement={consensus.agreement_ratio:.0%}"
            )

        return decision

    async def _handle_decompose(
        self,
        decision: AchonyeDecision,
        context: Optional[dict],
    ) -> AchonyeDecision:
        """Decompose a complex task into subtasks and delegate each."""
        leader = get_model(self.leader_model)
        decision.models_used.append(self.leader_model)

        decompose_prompt = (
            f"Decompose this task into 2-5 independent subtasks that can be "
            f"executed in parallel by specialist AI models:\n\n{decision.task}\n\n"
            f"For each subtask, specify:\n"
            f"1. The subtask description\n"
            f"2. What type of capability it needs (reasoning/code/search/verification/math)\n\n"
            f"Format as numbered list with CAPABILITY: tag on each."
        )
        decomposition = await leader.ainvoke([
            SystemMessage(content=ACHONYE_SYSTEM),
            HumanMessage(content=decompose_prompt),
        ])

        # For now, return the decomposition as the result
        # In a full implementation, we'd parse and delegate each subtask
        decision.result = decomposition.content
        decision.audit_trail.append("DECOMPOSED: Task broken into subtasks by Leader")
        return decision

    def _estimate_savings(self, model_name: str) -> int:
        """Estimate tokens saved by not using a premium model."""
        profile = get_profile(model_name)
        if profile.tier == ModelTier.LOCAL:
            return 2000  # Rough estimate: saved ~2k tokens of cloud cost
        if profile.tier == ModelTier.FAST_CLOUD:
            return 500
        return 0

    @property
    def history(self) -> list[AchonyeDecision]:
        return self._history

    def get_token_savings_report(self) -> dict:
        """Report on estimated token savings from intelligent routing."""
        total_tasks = len(self._history)
        local_tasks = sum(
            1 for d in self._history
            if d.action in (AchonyeAction.DIRECT_ANSWER, AchonyeAction.DELEGATE_LOCAL)
        )
        total_saved = sum(d.tokens_saved_estimate for d in self._history)
        models_used: dict[str, int] = {}
        for d in self._history:
            for m in d.models_used:
                models_used[m] = models_used.get(m, 0) + 1

        return {
            "total_tasks": total_tasks,
            "local_tasks": local_tasks,
            "cloud_tasks": total_tasks - local_tasks,
            "local_ratio": local_tasks / max(total_tasks, 1),
            "estimated_tokens_saved": total_saved,
            "models_usage": models_used,
        }

    def get_ecosystem_status(self) -> dict:
        """Return the current state of the Achonye ecosystem."""
        local_models = list_models(tier=ModelTier.LOCAL)
        cloud_models = list_models(tier=ModelTier.STANDARD_CLOUD)
        premium_models = list_models(tier=ModelTier.PREMIUM_CLOUD)

        return {
            "leader": self.leader_model,
            "board": self.board_models,
            "operators": {
                "local": [m.name for m in local_models],
                "cloud": [m.name for m in cloud_models],
                "premium": [m.name for m in premium_models],
            },
            "total_models": len(MODEL_REGISTRY),
            "prefer_local": self.prefer_local,
            "consensus_enabled": self.consensus_on_critical,
            "tasks_processed": len(self._history),
        }


# --- Singleton ---
_achonye: Optional[Achonye] = None


def get_achonye(**kwargs) -> Achonye:
    """Get or create the singleton Achonye instance."""
    global _achonye
    if _achonye is None:
        _achonye = Achonye(**kwargs)
    return _achonye
