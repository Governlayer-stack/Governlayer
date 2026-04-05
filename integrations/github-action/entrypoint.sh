#!/usr/bin/env bash
set -euo pipefail

# GovernLayer AI Governance Check — GitHub Actions Entrypoint
# Runs drift detection + risk scoring via the GovernLayer API,
# posts results as a PR comment, and fails if risk exceeds threshold.

###############################################################################
# Helpers
###############################################################################

log() { echo "::group::$1"; }
endlog() { echo "::endgroup::"; }

fail() {
  echo "::error::$1"
  exit 1
}

to_json_bool() {
  case "${1,,}" in
    true|1|yes) echo "true" ;;
    *)          echo "false" ;;
  esac
}

###############################################################################
# Validate inputs
###############################################################################

API_URL="${INPUT_API_URL:?API URL is required}"
API_KEY="${INPUT_API_KEY:?API key is required}"
SYSTEM_NAME="${INPUT_SYSTEM_NAME:?System name is required}"
REASONING_TRACE="${INPUT_REASONING_TRACE:-Automated CI/CD governance scan triggered by pull request}"
USE_CASE="${INPUT_USE_CASE:-general}"

HANDLES_PERSONAL_DATA=$(to_json_bool "${INPUT_HANDLES_PERSONAL_DATA:-false}")
MAKES_AUTONOMOUS_DECISIONS=$(to_json_bool "${INPUT_MAKES_AUTONOMOUS_DECISIONS:-false}")
USED_IN_CRITICAL_INFRASTRUCTURE=$(to_json_bool "${INPUT_USED_IN_CRITICAL_INFRASTRUCTURE:-false}")
HAS_HUMAN_OVERSIGHT=$(to_json_bool "${INPUT_HAS_HUMAN_OVERSIGHT:-true}")
IS_EXPLAINABLE=$(to_json_bool "${INPUT_IS_EXPLAINABLE:-true}")
HAS_BIAS_TESTING=$(to_json_bool "${INPUT_HAS_BIAS_TESTING:-false}")

FAIL_ON_HIGH_RISK=$(to_json_bool "${INPUT_FAIL_ON_HIGH_RISK:-true}")
RISK_THRESHOLD="${INPUT_RISK_THRESHOLD:-50}"
POST_COMMENT=$(to_json_bool "${INPUT_POST_COMMENT:-true}")

# Strip trailing slash from API URL
API_URL="${API_URL%/}"

###############################################################################
# Step 1 — Run governance scan (/v1/scan)
###############################################################################

log "GovernLayer: Running governance scan"

SCAN_BODY=$(cat <<ENDJSON
{
  "system_name": "${SYSTEM_NAME}",
  "reasoning_trace": "${REASONING_TRACE}",
  "use_case": "${USE_CASE}",
  "handles_personal_data": ${HANDLES_PERSONAL_DATA},
  "makes_autonomous_decisions": ${MAKES_AUTONOMOUS_DECISIONS},
  "used_in_critical_infrastructure": ${USED_IN_CRITICAL_INFRASTRUCTURE},
  "has_human_oversight": ${HAS_HUMAN_OVERSIGHT},
  "is_explainable": ${IS_EXPLAINABLE},
  "has_bias_testing": ${HAS_BIAS_TESTING}
}
ENDJSON
)

SCAN_HTTP_CODE=$(curl -s -o /tmp/gl_scan_response.json -w "%{http_code}" \
  -X POST "${API_URL}/v1/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d "${SCAN_BODY}" \
  --connect-timeout 30 \
  --max-time 60)

SCAN_RESPONSE=$(cat /tmp/gl_scan_response.json)

if [ "${SCAN_HTTP_CODE}" -lt 200 ] || [ "${SCAN_HTTP_CODE}" -ge 300 ]; then
  echo "Scan API returned HTTP ${SCAN_HTTP_CODE}"
  echo "Response: ${SCAN_RESPONSE}"
  fail "GovernLayer scan failed with HTTP ${SCAN_HTTP_CODE}"
fi

echo "Scan response: ${SCAN_RESPONSE}"
endlog

###############################################################################
# Step 2 — Run risk scoring (/v1/risk)
###############################################################################

log "GovernLayer: Running risk scoring"

RISK_BODY=$(cat <<ENDJSON
{
  "system_name": "${SYSTEM_NAME}",
  "handles_personal_data": ${HANDLES_PERSONAL_DATA},
  "makes_autonomous_decisions": ${MAKES_AUTONOMOUS_DECISIONS},
  "used_in_critical_infrastructure": ${USED_IN_CRITICAL_INFRASTRUCTURE},
  "has_human_oversight": ${HAS_HUMAN_OVERSIGHT},
  "is_explainable": ${IS_EXPLAINABLE},
  "has_bias_testing": ${HAS_BIAS_TESTING}
}
ENDJSON
)

RISK_HTTP_CODE=$(curl -s -o /tmp/gl_risk_response.json -w "%{http_code}" \
  -X POST "${API_URL}/v1/risk" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d "${RISK_BODY}" \
  --connect-timeout 30 \
  --max-time 60)

RISK_RESPONSE=$(cat /tmp/gl_risk_response.json)

if [ "${RISK_HTTP_CODE}" -lt 200 ] || [ "${RISK_HTTP_CODE}" -ge 300 ]; then
  echo "Risk API returned HTTP ${RISK_HTTP_CODE}"
  echo "Response: ${RISK_RESPONSE}"
  fail "GovernLayer risk scoring failed with HTTP ${RISK_HTTP_CODE}"
fi

echo "Risk response: ${RISK_RESPONSE}"
endlog

###############################################################################
# Step 3 — Parse results
###############################################################################

log "GovernLayer: Parsing results"

# Parse scan response
SCAN_ACTION=$(echo "${SCAN_RESPONSE}" | jq -r '.action // "UNKNOWN"')
SCAN_RISK_SCORE=$(echo "${SCAN_RESPONSE}" | jq -r '.risk_score // 0')
SCAN_DRIFT_COEFF=$(echo "${SCAN_RESPONSE}" | jq -r '.drift_coefficient // 0')
SCAN_VETOED=$(echo "${SCAN_RESPONSE}" | jq -r '.vetoed // false')

# Parse risk response
RISK_SCORE=$(echo "${RISK_RESPONSE}" | jq -r '.score // 0')
RISK_LEVEL=$(echo "${RISK_RESPONSE}" | jq -r '.level // "UNKNOWN"')
DIM_PRIVACY=$(echo "${RISK_RESPONSE}" | jq -r '.dimensions.privacy // 0')
DIM_AUTONOMY=$(echo "${RISK_RESPONSE}" | jq -r '.dimensions.autonomy // 0')
DIM_INFRASTRUCTURE=$(echo "${RISK_RESPONSE}" | jq -r '.dimensions.infrastructure // 0')
DIM_OVERSIGHT=$(echo "${RISK_RESPONSE}" | jq -r '.dimensions.oversight // 0')
DIM_TRANSPARENCY=$(echo "${RISK_RESPONSE}" | jq -r '.dimensions.transparency // 0')
DIM_FAIRNESS=$(echo "${RISK_RESPONSE}" | jq -r '.dimensions.fairness // 0')

echo "Action: ${SCAN_ACTION}"
echo "Risk Score: ${RISK_SCORE}/100 (${RISK_LEVEL})"
echo "Drift Coefficient: ${SCAN_DRIFT_COEFF}"
echo "Vetoed: ${SCAN_VETOED}"

endlog

###############################################################################
# Step 4 — Set outputs
###############################################################################

echo "action=${SCAN_ACTION}" >> "${GITHUB_OUTPUT}"
echo "risk_score=${RISK_SCORE}" >> "${GITHUB_OUTPUT}"
echo "risk_level=${RISK_LEVEL}" >> "${GITHUB_OUTPUT}"
echo "drift_coefficient=${SCAN_DRIFT_COEFF}" >> "${GITHUB_OUTPUT}"
echo "vetoed=${SCAN_VETOED}" >> "${GITHUB_OUTPUT}"

###############################################################################
# Step 5 — Determine status icon and pass/fail
###############################################################################

if [ "${SCAN_ACTION}" = "APPROVE" ]; then
  STATUS_ICON="white_check_mark"
  STATUS_TEXT="APPROVED"
elif [ "${SCAN_ACTION}" = "ESCALATE_HUMAN" ]; then
  STATUS_ICON="warning"
  STATUS_TEXT="NEEDS REVIEW"
else
  STATUS_ICON="x"
  STATUS_TEXT="BLOCKED"
fi

# Risk bar visualization (each block = 10 points)
FILLED=$(( RISK_SCORE / 10 ))
EMPTY=$(( 10 - FILLED ))
RISK_BAR=""
for ((i=0; i<FILLED; i++)); do RISK_BAR="${RISK_BAR}="; done
for ((i=0; i<EMPTY; i++)); do RISK_BAR="${RISK_BAR}-"; done

###############################################################################
# Step 6 — Post PR comment
###############################################################################

if [ "${POST_COMMENT}" = "true" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  # Only post comments on pull requests
  if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] || [ "${GITHUB_EVENT_NAME:-}" = "pull_request_target" ]; then

    log "GovernLayer: Posting PR comment"

    # Extract PR number from event
    if [ -f "${GITHUB_EVENT_PATH:-/dev/null}" ]; then
      PR_NUMBER=$(jq -r '.pull_request.number // .number // empty' "${GITHUB_EVENT_PATH}" 2>/dev/null || true)
    fi

    if [ -n "${PR_NUMBER:-}" ]; then
      COMMENT_BODY=$(cat <<ENDMARKDOWN
## :${STATUS_ICON}: GovernLayer Governance Check -- ${STATUS_TEXT}

**System:** \`${SYSTEM_NAME}\`
**Decision:** \`${SCAN_ACTION}\`
**Risk Score:** ${RISK_SCORE}/100 (\`${RISK_LEVEL}\`)

### Risk Dimensions

| Dimension | Score | Status |
|-----------|-------|--------|
| Privacy | ${DIM_PRIVACY}/100 | $([ "${DIM_PRIVACY}" -ge 80 ] && echo "Pass" || ([ "${DIM_PRIVACY}" -ge 50 ] && echo "Warning" || echo "Fail")) |
| Autonomy | ${DIM_AUTONOMY}/100 | $([ "${DIM_AUTONOMY}" -ge 80 ] && echo "Pass" || ([ "${DIM_AUTONOMY}" -ge 50 ] && echo "Warning" || echo "Fail")) |
| Infrastructure | ${DIM_INFRASTRUCTURE}/100 | $([ "${DIM_INFRASTRUCTURE}" -ge 80 ] && echo "Pass" || ([ "${DIM_INFRASTRUCTURE}" -ge 50 ] && echo "Warning" || echo "Fail")) |
| Oversight | ${DIM_OVERSIGHT}/100 | $([ "${DIM_OVERSIGHT}" -ge 80 ] && echo "Pass" || ([ "${DIM_OVERSIGHT}" -ge 50 ] && echo "Warning" || echo "Fail")) |
| Transparency | ${DIM_TRANSPARENCY}/100 | $([ "${DIM_TRANSPARENCY}" -ge 80 ] && echo "Pass" || ([ "${DIM_TRANSPARENCY}" -ge 50 ] && echo "Warning" || echo "Fail")) |
| Fairness | ${DIM_FAIRNESS}/100 | $([ "${DIM_FAIRNESS}" -ge 80 ] && echo "Pass" || ([ "${DIM_FAIRNESS}" -ge 50 ] && echo "Warning" || echo "Fail")) |

### Behavioral Drift

| Metric | Value |
|--------|-------|
| Drift Coefficient | ${SCAN_DRIFT_COEFF} |
| Safety Veto | ${SCAN_VETOED} |

### Risk Gauge

\`\`\`
[${RISK_BAR}] ${RISK_SCORE}/100
 0          50         100
 HIGH       MEDIUM     LOW
\`\`\`

<details>
<summary>Configuration</summary>

- **Threshold:** ${RISK_THRESHOLD} (scores below this fail the check)
- **Fail on high risk:** ${FAIL_ON_HIGH_RISK}
- **Use case:** ${USE_CASE}
- **Commit:** \`${GITHUB_SHA:-unknown}\`

</details>

---
*Powered by [GovernLayer](https://governlayer.ai) -- AI Governance Platform*
ENDMARKDOWN
)

      # Escape the body for JSON
      ESCAPED_BODY=$(echo "${COMMENT_BODY}" | jq -Rsa .)

      COMMENT_HTTP_CODE=$(curl -s -o /tmp/gl_comment_response.json -w "%{http_code}" \
        -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        -d "{\"body\": ${ESCAPED_BODY}}" \
        --connect-timeout 15 \
        --max-time 30)

      if [ "${COMMENT_HTTP_CODE}" -ge 200 ] && [ "${COMMENT_HTTP_CODE}" -lt 300 ]; then
        echo "PR comment posted successfully"
      else
        echo "::warning::Failed to post PR comment (HTTP ${COMMENT_HTTP_CODE})"
        cat /tmp/gl_comment_response.json 2>/dev/null || true
      fi
    else
      echo "::warning::Could not determine PR number; skipping comment"
    fi

    endlog
  else
    echo "Not a pull request event (${GITHUB_EVENT_NAME:-unknown}); skipping PR comment"
  fi
fi

###############################################################################
# Step 7 — Job summary (always written)
###############################################################################

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat >> "${GITHUB_STEP_SUMMARY}" <<ENDSUMMARY
## GovernLayer Governance Check

| Metric | Value |
|--------|-------|
| **System** | \`${SYSTEM_NAME}\` |
| **Decision** | \`${SCAN_ACTION}\` |
| **Risk Score** | ${RISK_SCORE}/100 (${RISK_LEVEL}) |
| **Drift Coefficient** | ${SCAN_DRIFT_COEFF} |
| **Safety Veto** | ${SCAN_VETOED} |
| **Threshold** | ${RISK_THRESHOLD} |
ENDSUMMARY
fi

###############################################################################
# Step 8 — Enforce threshold
###############################################################################

if [ "${FAIL_ON_HIGH_RISK}" = "true" ]; then
  if [ "${RISK_SCORE}" -lt "${RISK_THRESHOLD}" ]; then
    fail "Risk score ${RISK_SCORE} is below threshold ${RISK_THRESHOLD}. Governance check FAILED."
  fi

  if [ "${SCAN_VETOED}" = "true" ]; then
    fail "System was VETOED due to behavioral drift. Governance check FAILED."
  fi
fi

echo "GovernLayer governance check passed. Action: ${SCAN_ACTION}, Risk: ${RISK_SCORE}/100 (${RISK_LEVEL})"
