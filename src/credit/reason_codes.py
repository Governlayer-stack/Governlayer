"""ECOA / Regulation B adverse-action reason-code generator.

Under 15 U.S.C. 1691(d) (ECOA) and Regulation B (12 CFR 1002.9), a creditor
that takes adverse action on a credit application must give the applicant a
statement of specific reasons — either from the sample codes in Appendix C of
Regulation B, or reasons at least equivalent in specificity.

This module:
  1. Enumerates the Appendix C sample reason set (extended with common
     modern underwriting attributions banks map to).
  2. Maps feature-attribution keys produced by a decisioning model (SHAP-style
     "feature: importance" pairs) onto those reason codes.
  3. Emits an audit-ready adverse-action statement suitable for Reg B and
     FCRA compliance.

Reg B requires that the reasons be specific and relate to the *principal*
factors in the decision. We surface the top-k contributions and refuse to
generate a statement without at least one mappable factor — silent failure
here becomes a compliance violation for the customer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ReasonCode:
    """A single Reg B adverse-action reason code."""
    code: str            # short stable identifier used in the audit ledger
    statement: str       # exact language given to the applicant
    source: str          # "reg_b_appendix_c" or "extended"


# ---------------------------------------------------------------------------
# Reason-code catalog
#
# The Appendix C set below is the sample statutory list. Extended codes cover
# modern underwriting features (thin-file, cash-flow, income-verification,
# alt-data) that lenders commonly map onto the statutory categories.
# ---------------------------------------------------------------------------

_APPENDIX_C: dict[str, ReasonCode] = {
    "CREDIT_APPLICATION_INCOMPLETE": ReasonCode(
        "CREDIT_APPLICATION_INCOMPLETE",
        "Credit application incomplete",
        "reg_b_appendix_c",
    ),
    "INSUFFICIENT_CREDIT_REFERENCES": ReasonCode(
        "INSUFFICIENT_CREDIT_REFERENCES",
        "Insufficient number of credit references provided",
        "reg_b_appendix_c",
    ),
    "UNACCEPTABLE_CREDIT_REFERENCES": ReasonCode(
        "UNACCEPTABLE_CREDIT_REFERENCES",
        "Unacceptable type of credit references provided",
        "reg_b_appendix_c",
    ),
    "TEMPORARY_RESIDENCE": ReasonCode(
        "TEMPORARY_RESIDENCE",
        "Temporary or irregular residence",
        "reg_b_appendix_c",
    ),
    "SHORT_RESIDENCE": ReasonCode(
        "SHORT_RESIDENCE",
        "Length of residence too short",
        "reg_b_appendix_c",
    ),
    "TEMPORARY_EMPLOYMENT": ReasonCode(
        "TEMPORARY_EMPLOYMENT",
        "Temporary employment",
        "reg_b_appendix_c",
    ),
    "SHORT_EMPLOYMENT": ReasonCode(
        "SHORT_EMPLOYMENT",
        "Length of employment too short",
        "reg_b_appendix_c",
    ),
    "INSUFFICIENT_INCOME": ReasonCode(
        "INSUFFICIENT_INCOME",
        "Income insufficient for amount of credit requested",
        "reg_b_appendix_c",
    ),
    "EXCESSIVE_OBLIGATIONS": ReasonCode(
        "EXCESSIVE_OBLIGATIONS",
        "Excessive obligations in relation to income",
        "reg_b_appendix_c",
    ),
    "UNABLE_TO_VERIFY_INCOME": ReasonCode(
        "UNABLE_TO_VERIFY_INCOME",
        "Unable to verify income",
        "reg_b_appendix_c",
    ),
    "UNABLE_TO_VERIFY_EMPLOYMENT": ReasonCode(
        "UNABLE_TO_VERIFY_EMPLOYMENT",
        "Unable to verify employment",
        "reg_b_appendix_c",
    ),
    "UNABLE_TO_VERIFY_RESIDENCE": ReasonCode(
        "UNABLE_TO_VERIFY_RESIDENCE",
        "Unable to verify residence",
        "reg_b_appendix_c",
    ),
    "INSUFFICIENT_CREDIT_FILE": ReasonCode(
        "INSUFFICIENT_CREDIT_FILE",
        "Insufficient credit file",
        "reg_b_appendix_c",
    ),
    "DELINQUENT_CREDIT_OBLIGATIONS": ReasonCode(
        "DELINQUENT_CREDIT_OBLIGATIONS",
        "Delinquent past or present credit obligations with others",
        "reg_b_appendix_c",
    ),
    "GARNISHMENT_ATTACHMENT_FORECLOSURE_REPOSSESSION_SUIT_JUDGMENT": ReasonCode(
        "GARNISHMENT_ATTACHMENT_FORECLOSURE_REPOSSESSION_SUIT_JUDGMENT",
        "Garnishment, attachment, foreclosure, repossession, collection action, or judgment",
        "reg_b_appendix_c",
    ),
    "BANKRUPTCY": ReasonCode(
        "BANKRUPTCY",
        "Bankruptcy",
        "reg_b_appendix_c",
    ),
    "NUMBER_RECENT_INQUIRIES": ReasonCode(
        "NUMBER_RECENT_INQUIRIES",
        "Number of recent inquiries on credit bureau report",
        "reg_b_appendix_c",
    ),
    "VALUE_OR_TYPE_OF_COLLATERAL": ReasonCode(
        "VALUE_OR_TYPE_OF_COLLATERAL",
        "Value or type of collateral not sufficient",
        "reg_b_appendix_c",
    ),
    "OTHER_LATE_PAYMENT_HISTORY": ReasonCode(
        "OTHER_LATE_PAYMENT_HISTORY",
        "Poor credit performance with us",
        "reg_b_appendix_c",
    ),
    "NO_CREDIT_FILE": ReasonCode(
        "NO_CREDIT_FILE",
        "No credit file",
        "reg_b_appendix_c",
    ),
    "LIMITED_CREDIT_EXPERIENCE": ReasonCode(
        "LIMITED_CREDIT_EXPERIENCE",
        "Limited credit experience",
        "reg_b_appendix_c",
    ),
    "CREDIT_APPLICATION_WITHDRAWN": ReasonCode(
        "CREDIT_APPLICATION_WITHDRAWN",
        "Credit application withdrawn",
        "reg_b_appendix_c",
    ),
    "OTHER": ReasonCode(
        "OTHER",
        "Other, specify",
        "reg_b_appendix_c",
    ),
}

_EXTENDED: dict[str, ReasonCode] = {
    "HIGH_DEBT_TO_INCOME_RATIO": ReasonCode(
        "HIGH_DEBT_TO_INCOME_RATIO",
        "Debt-to-income ratio too high in relation to income",
        "extended",
    ),
    "HIGH_LOAN_TO_VALUE_RATIO": ReasonCode(
        "HIGH_LOAN_TO_VALUE_RATIO",
        "Loan-to-value ratio too high for requested amount",
        "extended",
    ),
    "INSUFFICIENT_CASH_FLOW": ReasonCode(
        "INSUFFICIENT_CASH_FLOW",
        "Insufficient bank-account cash flow to support requested credit",
        "extended",
    ),
    "OVERDRAFT_HISTORY": ReasonCode(
        "OVERDRAFT_HISTORY",
        "Recent overdraft history on deposit accounts",
        "extended",
    ),
    "SCORE_BELOW_CUTOFF": ReasonCode(
        "SCORE_BELOW_CUTOFF",
        "Credit score below the minimum required for this product",
        "extended",
    ),
}

# Full catalog for lookups
_CATALOG: dict[str, ReasonCode] = {**_APPENDIX_C, **_EXTENDED}


# ---------------------------------------------------------------------------
# Feature -> reason-code mapping
#
# Keys are lowercase snake_case tokens found in feature-importance dicts.
# Each key maps to the reason code that best describes the underlying finding.
# Contributions are compared in absolute value; direction (positive = adverse)
# is inferred separately below.
# ---------------------------------------------------------------------------

_FEATURE_MAP: dict[str, str] = {
    # Income / employment
    "income": "INSUFFICIENT_INCOME",
    "annual_income": "INSUFFICIENT_INCOME",
    "monthly_income": "INSUFFICIENT_INCOME",
    "employment_length": "SHORT_EMPLOYMENT",
    "employment_status": "TEMPORARY_EMPLOYMENT",
    "employment_verification": "UNABLE_TO_VERIFY_EMPLOYMENT",
    "income_verification": "UNABLE_TO_VERIFY_INCOME",
    # Obligations / DTI
    "debt_to_income": "HIGH_DEBT_TO_INCOME_RATIO",
    "dti_ratio": "HIGH_DEBT_TO_INCOME_RATIO",
    "monthly_obligations": "EXCESSIVE_OBLIGATIONS",
    "total_debt": "EXCESSIVE_OBLIGATIONS",
    # Credit file / history
    "credit_score": "SCORE_BELOW_CUTOFF",
    "fico_score": "SCORE_BELOW_CUTOFF",
    "credit_history_length": "LIMITED_CREDIT_EXPERIENCE",
    "credit_file_thickness": "INSUFFICIENT_CREDIT_FILE",
    "num_tradelines": "INSUFFICIENT_CREDIT_FILE",
    "no_credit_file": "NO_CREDIT_FILE",
    "delinquencies_24m": "DELINQUENT_CREDIT_OBLIGATIONS",
    "past_due_accounts": "DELINQUENT_CREDIT_OBLIGATIONS",
    "recent_late_payments": "OTHER_LATE_PAYMENT_HISTORY",
    "collections_count": "GARNISHMENT_ATTACHMENT_FORECLOSURE_REPOSSESSION_SUIT_JUDGMENT",
    "public_records": "GARNISHMENT_ATTACHMENT_FORECLOSURE_REPOSSESSION_SUIT_JUDGMENT",
    "bankruptcy_flag": "BANKRUPTCY",
    "num_hard_inquiries_6m": "NUMBER_RECENT_INQUIRIES",
    "recent_inquiries": "NUMBER_RECENT_INQUIRIES",
    # Residence
    "residence_length": "SHORT_RESIDENCE",
    "residence_verification": "UNABLE_TO_VERIFY_RESIDENCE",
    # Collateral / LTV
    "loan_to_value": "HIGH_LOAN_TO_VALUE_RATIO",
    "ltv_ratio": "HIGH_LOAN_TO_VALUE_RATIO",
    "collateral_value": "VALUE_OR_TYPE_OF_COLLATERAL",
    # Application completeness
    "application_completeness": "CREDIT_APPLICATION_INCOMPLETE",
    "missing_fields": "CREDIT_APPLICATION_INCOMPLETE",
    # Cash-flow / deposit signals
    "cash_flow_score": "INSUFFICIENT_CASH_FLOW",
    "avg_daily_balance": "INSUFFICIENT_CASH_FLOW",
    "overdraft_count_12m": "OVERDRAFT_HISTORY",
    "nsf_count_12m": "OVERDRAFT_HISTORY",
}


# ---------------------------------------------------------------------------
# Protected-class proxy features
#
# ECOA prohibits using these as decisioning factors. If we see them driving the
# denial, we surface a *compliance flag* rather than a reason code, so the
# audit trail records the fair-lending exposure explicitly.
# ---------------------------------------------------------------------------

_PROTECTED_PROXIES: set[str] = {
    "race", "ethnicity", "national_origin", "color",
    "sex", "gender", "sexual_orientation", "gender_identity",
    "religion", "marital_status", "age",
    "receipt_of_public_assistance", "public_assistance",
    "disability", "familial_status",
    # Common proxies
    "zip_code", "zip", "postal_code",
    "surname", "first_name",
    "language_preference", "primary_language",
    "school_attended", "college_attended",
    "census_tract",
}


@dataclass
class AdverseActionResult:
    """Output of reason-code generation for a single denial."""
    reason_codes: list[ReasonCode] = field(default_factory=list)
    unmatched_features: list[str] = field(default_factory=list)
    protected_class_flags: list[str] = field(default_factory=list)
    statement: str = ""
    ecoa_compliant: bool = False
    warnings: list[str] = field(default_factory=list)


def _normalise_feature(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def pick_reason_codes(
    feature_attributions: dict[str, float],
    *,
    top_k: int = 4,
    creditor_name: Optional[str] = None,
) -> AdverseActionResult:
    """Map model feature attributions to ECOA reason codes.

    Args:
        feature_attributions: {feature_name: contribution}. Positive values
            indicate the feature pushed the decision toward denial. Sign is
            respected — features that supported the applicant are ignored.
        top_k: Maximum number of reasons to include (Reg B typically caps at 4).
        creditor_name: Optional creditor name for the statement header.

    Returns:
        AdverseActionResult with reason codes, unmatched features (a
        compliance risk), protected-class proxy flags, and an audit-ready
        applicant statement.
    """
    result = AdverseActionResult()

    if not feature_attributions:
        result.warnings.append(
            "No feature attributions supplied; cannot produce specific reasons. "
            "Reg B requires specific reasons — do not send this decision to the applicant."
        )
        return result

    # Rank features by absolute contribution, keeping only those that push toward denial
    ranked = sorted(
        feature_attributions.items(),
        key=lambda kv: abs(kv[1]),
        reverse=True,
    )

    seen_codes: set[str] = set()
    for raw_name, contribution in ranked:
        name = _normalise_feature(raw_name)

        # Protected-class proxies never become reason codes — they become fair-lending flags
        if name in _PROTECTED_PROXIES:
            if name not in result.protected_class_flags:
                result.protected_class_flags.append(name)
            continue

        # Skip features that helped the applicant (negative contribution toward denial)
        if contribution <= 0:
            continue

        code_id = _FEATURE_MAP.get(name)
        if code_id is None:
            result.unmatched_features.append(raw_name)
            continue

        if code_id in seen_codes:
            continue

        result.reason_codes.append(_CATALOG[code_id])
        seen_codes.add(code_id)
        if len(result.reason_codes) >= top_k:
            break

    if result.protected_class_flags:
        result.warnings.append(
            "Protected-class or proxy attributes contributed to the decision. "
            "Fair-lending review required before this denial can proceed: "
            + ", ".join(result.protected_class_flags)
        )

    if result.unmatched_features:
        result.warnings.append(
            "Some driving features have no reason-code mapping: "
            + ", ".join(result.unmatched_features)
            + ". Add them to _FEATURE_MAP or provide a Reg B 'OTHER' explanation."
        )

    # ECOA compliance gate: must have at least one specific reason and no unresolved proxies
    result.ecoa_compliant = bool(result.reason_codes) and not result.protected_class_flags

    result.statement = _format_statement(result, creditor_name)
    return result


def _format_statement(result: AdverseActionResult, creditor_name: Optional[str]) -> str:
    """Render an applicant-facing adverse-action statement per Reg B 1002.9(b)(2)."""
    if not result.reason_codes:
        return ""

    header = (
        f"Notice of Action Taken\n"
        f"Creditor: {creditor_name or '[Creditor name required]'}\n"
        "\n"
        "We regret that we are unable to grant your request for credit.\n"
        "The principal reason(s) for this decision, as required by the Equal Credit\n"
        "Opportunity Act (15 U.S.C. 1691) and Regulation B (12 CFR 1002.9), are:\n"
    )
    bullets = "\n".join(f"  - {rc.statement}" for rc in result.reason_codes)

    ecoa_notice = (
        "\n\nThe federal Equal Credit Opportunity Act prohibits creditors from\n"
        "discriminating against credit applicants on the basis of race, color, religion,\n"
        "national origin, sex, marital status, age (provided the applicant has the\n"
        "capacity to enter into a binding contract); because all or part of the\n"
        "applicant's income derives from any public assistance program; or because the\n"
        "applicant has in good faith exercised any right under the Consumer Credit\n"
        "Protection Act. The federal agency that administers compliance with this law\n"
        "concerning this creditor is the applicable prudential regulator."
    )
    return f"{header}{bullets}{ecoa_notice}"


def catalog() -> list[ReasonCode]:
    """Return the full published catalog of reason codes (Appendix C + extended)."""
    return list(_CATALOG.values())
