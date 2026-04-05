"""Multi-LLM consensus engine — hallucination resistance through disagreement.

Implements three strategies from the PDF:
1. Consensus Voting — 3 models vote, majority wins
2. Chain-of-Verification (CoVe) — generate -> question -> verify -> synthesize
3. Adversarial Debate — claim -> critique -> judge

These run only on CRITICAL tasks. Simple tasks go straight to a single model.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import StrEnum

from langchain_core.messages import HumanMessage, SystemMessage

from src.llm.providers import get_model

logger = logging.getLogger(__name__)


class ConsensusStrategy(StrEnum):
    VOTING = "voting"
    CHAIN_OF_VERIFICATION = "cove"
    ADVERSARIAL_DEBATE = "debate"


@dataclass
class ConsensusResult:
    """Output of a consensus process."""
    strategy: ConsensusStrategy
    final_answer: str
    confidence: float               # 0.0 - 1.0
    agreement_ratio: float          # How many models agreed
    individual_responses: list[dict] # Each model's response
    dissenting_views: list[str]     # Any disagreements flagged


async def _invoke_model(model_name: str, prompt: str, system: str = "") -> str:
    """Invoke a model and return its text response."""
    model = get_model(model_name)
    messages = []
    if system:
        messages.append(SystemMessage(content=system))
    messages.append(HumanMessage(content=prompt))
    response = await model.ainvoke(messages)
    return response.content


# =============================================================================
# Strategy 1: Consensus Voting
# =============================================================================

async def consensus_vote(
    prompt: str,
    models: list[str],
    system: str = "",
) -> ConsensusResult:
    """Run the same prompt through multiple models and find agreement.

    If all models agree -> high confidence.
    If they disagree -> flag for human review with dissenting views.
    """
    tasks = [_invoke_model(m, prompt, system) for m in models]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    individual = []
    valid_responses = []
    for model_name, resp in zip(models, responses):
        if isinstance(resp, Exception):
            logger.warning(f"Model {model_name} failed in consensus: {resp}")
            individual.append({"model": model_name, "response": f"ERROR: {resp}", "status": "failed"})
        else:
            individual.append({"model": model_name, "response": resp, "status": "ok"})
            valid_responses.append(resp)

    if not valid_responses:
        return ConsensusResult(
            strategy=ConsensusStrategy.VOTING,
            final_answer="ALL MODELS FAILED — cannot reach consensus",
            confidence=0.0,
            agreement_ratio=0.0,
            individual_responses=individual,
            dissenting_views=["All models returned errors"],
        )

    # Use the last model as synthesizer so the judge didn't generate the
    # first response (avoids anchoring bias from the first responder)
    synthesizer = models[-1]
    judge_prompt = (
        "You are a consensus judge. Below are responses from multiple AI models "
        "to the same question. Determine:\n"
        "1. Do they substantially agree? (yes/partially/no)\n"
        "2. What is the consensus answer?\n"
        "3. What points of disagreement exist?\n\n"
        f"Original question: {prompt}\n\n"
    )
    for i, resp in enumerate(valid_responses):
        judge_prompt += f"Model {i+1} response:\n{resp}\n\n"

    judge_prompt += (
        "Respond in this exact format:\n"
        "AGREEMENT: [yes/partially/no]\n"
        "CONSENSUS: [the agreed-upon answer]\n"
        "DISSENT: [any disagreements, or 'none']"
    )

    try:
        judgment = await _invoke_model(synthesizer, judge_prompt)
    except Exception:
        judgment = f"AGREEMENT: unknown\nCONSENSUS: {valid_responses[0]}\nDISSENT: Could not synthesize"

    # Parse agreement level
    agreement_map = {"yes": 1.0, "partially": 0.6, "no": 0.3}
    agreement = 0.5
    for key, val in agreement_map.items():
        if f"AGREEMENT: {key}" in judgment.lower():
            agreement = val
            break

    # Extract consensus answer
    final = valid_responses[0]  # fallback
    if "CONSENSUS:" in judgment:
        final = judgment.split("CONSENSUS:")[1].split("DISSENT:")[0].strip()

    dissent = []
    if "DISSENT:" in judgment:
        d = judgment.split("DISSENT:")[1].strip()
        if d.lower() != "none":
            dissent.append(d)

    return ConsensusResult(
        strategy=ConsensusStrategy.VOTING,
        final_answer=final,
        confidence=agreement,
        agreement_ratio=agreement,
        individual_responses=individual,
        dissenting_views=dissent,
    )


# =============================================================================
# Strategy 2: Chain-of-Verification (CoVe)
# =============================================================================

async def chain_of_verification(
    prompt: str,
    generator: str = "llama-groq",
    questioner: str = "gpt4o",
    verifier: str = "deepseek-v3",
    synthesizer: str = "claude-sonnet",
) -> ConsensusResult:
    """Four-step verification pipeline:

    1. Generator produces initial response
    2. Questioner generates fact-check questions about the response
    3. Verifier answers those questions independently
    4. Synthesizer produces final verified output
    """
    individual = []

    # Step 1: Generate
    initial = await _invoke_model(generator, prompt)
    individual.append({"model": generator, "role": "generator", "response": initial})

    # Step 2: Question
    q_prompt = (
        f"An AI generated this response to the question '{prompt}':\n\n"
        f"{initial}\n\n"
        "Generate 3-5 specific fact-check questions that would verify the accuracy "
        "of the key claims in this response. List them numbered."
    )
    questions = await _invoke_model(questioner, q_prompt)
    individual.append({"model": questioner, "role": "questioner", "response": questions})

    # Step 3: Verify
    v_prompt = (
        f"Answer each of these fact-check questions independently, based on your "
        f"own knowledge. Be precise and cite specifics where possible:\n\n{questions}"
    )
    verification = await _invoke_model(verifier, v_prompt)
    individual.append({"model": verifier, "role": "verifier", "response": verification})

    # Step 4: Synthesize
    s_prompt = (
        f"Original question: {prompt}\n\n"
        f"Initial response:\n{initial}\n\n"
        f"Fact-check questions:\n{questions}\n\n"
        f"Independent verification:\n{verification}\n\n"
        "Based on the verification, produce a FINAL VERIFIED response. "
        "Correct any inaccuracies found. Mark confidence as HIGH/MEDIUM/LOW."
    )
    final = await _invoke_model(synthesizer, s_prompt)
    individual.append({"model": synthesizer, "role": "synthesizer", "response": final})

    confidence = 0.85 if "HIGH" in final else 0.6 if "MEDIUM" in final else 0.4

    return ConsensusResult(
        strategy=ConsensusStrategy.CHAIN_OF_VERIFICATION,
        final_answer=final,
        confidence=confidence,
        agreement_ratio=confidence,
        individual_responses=individual,
        dissenting_views=[],
    )


# =============================================================================
# Strategy 3: Adversarial Debate
# =============================================================================

async def adversarial_debate(
    prompt: str,
    claimant: str = "claude-sonnet",
    critic: str = "gpt4o",
    judge: str = "deepseek-r1-local",
) -> ConsensusResult:
    """Three-way adversarial debate:

    1. Claimant makes a reasoned claim
    2. Critic finds flaws and counterarguments
    3. Judge evaluates with chain-of-thought reasoning

    Only claims that survive scrutiny make it through.
    """
    individual = []

    # Step 1: Claim
    claim = await _invoke_model(
        claimant, prompt,
        system="Provide a thorough, well-reasoned response. Support your claims with specifics."
    )
    individual.append({"model": claimant, "role": "claimant", "response": claim})

    # Step 2: Critique
    c_prompt = (
        f"Question: {prompt}\n\n"
        f"Another AI provided this response:\n{claim}\n\n"
        "Your job is to find flaws, inaccuracies, logical gaps, unsupported claims, "
        "and potential hallucinations. Be thorough and adversarial. "
        "For each issue found, explain WHY it's problematic."
    )
    critique = await _invoke_model(critic, c_prompt)
    individual.append({"model": critic, "role": "critic", "response": critique})

    # Step 3: Judge
    j_prompt = (
        f"Original question: {prompt}\n\n"
        f"CLAIM:\n{claim}\n\n"
        f"CRITIQUE:\n{critique}\n\n"
        "You are the final judge. Using chain-of-thought reasoning:\n"
        "1. Evaluate each point in the critique — is it valid?\n"
        "2. Determine which parts of the original claim survive scrutiny\n"
        "3. Produce a FINAL RULING that keeps only verified claims\n"
        "4. Rate overall confidence: HIGH / MEDIUM / LOW\n\n"
        "Think step by step."
    )
    judgment = await _invoke_model(judge, j_prompt)
    individual.append({"model": judge, "role": "judge", "response": judgment})

    confidence = 0.9 if "HIGH" in judgment else 0.6 if "MEDIUM" in judgment else 0.35

    dissent = []
    if "valid" in critique.lower() or "flaw" in critique.lower():
        dissent.append(f"Critic ({critic}) raised concerns — see individual responses")

    return ConsensusResult(
        strategy=ConsensusStrategy.ADVERSARIAL_DEBATE,
        final_answer=judgment,
        confidence=confidence,
        agreement_ratio=confidence,
        individual_responses=individual,
        dissenting_views=dissent,
    )


# =============================================================================
# Unified entry point
# =============================================================================

async def run_consensus(
    prompt: str,
    strategy: ConsensusStrategy = ConsensusStrategy.VOTING,
    models: list[str] | None = None,
    **kwargs,
) -> ConsensusResult:
    """Run a consensus strategy on a prompt.

    Args:
        prompt: The question/task
        strategy: Which consensus method to use
        models: For VOTING, the list of models to query
        **kwargs: Strategy-specific overrides (generator, critic, etc.)
    """
    if strategy == ConsensusStrategy.VOTING:
        if not models:
            models = ["llama-groq", "gemini-pro", "deepseek-v3"]
        return await consensus_vote(prompt, models)

    elif strategy == ConsensusStrategy.CHAIN_OF_VERIFICATION:
        return await chain_of_verification(prompt, **kwargs)

    elif strategy == ConsensusStrategy.ADVERSARIAL_DEBATE:
        return await adversarial_debate(prompt, **kwargs)

    raise ValueError(f"Unknown strategy: {strategy}")
