"""AWS Evidence Connector — collects compliance evidence via AWS APIs.

Uses AWS Signature V4 for authentication. Collects:
- CloudTrail events (recent API activity)
- IAM policies (access control posture)
- Security groups (network boundary controls)
"""

import datetime
import hashlib
import hmac
import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional

from src.evidence.connectors import BaseConnector, ConnectorError, EvidenceResult

logger = logging.getLogger("governlayer.evidence.aws")


class AWSConnector(BaseConnector):
    """Connector for Amazon Web Services using Signature V4 auth."""

    connector_type = "aws"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.access_key = config.get("aws_access_key", "")
        self.secret_key = config.get("aws_secret_key", "")
        self.region = config.get("aws_region", "us-east-1")
        self.session_token = config.get("aws_session_token", "")

    # ------------------------------------------------------------------
    # AWS Signature V4
    # ------------------------------------------------------------------

    def _sign(self, key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _get_signature_key(self, date_stamp: str, service: str) -> bytes:
        k_date = self._sign(("AWS4" + self.secret_key).encode("utf-8"), date_stamp)
        k_region = self._sign(k_date, self.region)
        k_service = self._sign(k_region, service)
        k_signing = self._sign(k_service, "aws4_request")
        return k_signing

    def _aws_request(
        self,
        service: str,
        action: str,
        params: Optional[Dict[str, str]] = None,
        body: str = "",
        target_header: Optional[str] = None,
        content_type: str = "application/x-amz-json-1.1",
    ) -> Dict[str, Any]:
        """Make a signed AWS API request.

        Supports both query-string APIs (like IAM, EC2) and JSON body APIs
        (like CloudTrail).
        """
        if not self.access_key or not self.secret_key:
            raise ConnectorError(
                "AWS credentials not configured",
                connector_type=self.connector_type,
            )

        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        host = f"{service}.{self.region}.amazonaws.com"
        # IAM is global
        if service == "iam":
            host = "iam.amazonaws.com"
        endpoint = f"https://{host}/"

        method = "POST"
        canonical_uri = "/"

        # Build headers
        headers: Dict[str, str] = {
            "Host": host,
            "X-Amz-Date": amz_date,
        }
        if self.session_token:
            headers["X-Amz-Security-Token"] = self.session_token
        if target_header:
            headers["X-Amz-Target"] = target_header
            headers["Content-Type"] = content_type

        # Build canonical query string or body
        if params:
            canonical_querystring = urllib.parse.urlencode(sorted(params.items()))
        else:
            canonical_querystring = ""

        payload = body.encode("utf-8") if body else b""
        payload_hash = hashlib.sha256(payload).hexdigest()

        # Canonical headers
        signed_header_keys = sorted(headers.keys(), key=str.lower)
        canonical_headers = ""
        for k in signed_header_keys:
            canonical_headers += f"{k.lower()}:{headers[k].strip()}\n"
        signed_headers = ";".join(k.lower() for k in signed_header_keys)

        canonical_request = "\n".join([
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ])

        credential_scope = f"{date_stamp}/{self.region}/{service}/aws4_request"
        if service == "iam":
            credential_scope = f"{date_stamp}/us-east-1/iam/aws4_request"

        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ])

        region_for_signing = "us-east-1" if service == "iam" else self.region
        signing_key = self._get_signature_key(date_stamp, service)
        if service == "iam":
            # Re-derive with us-east-1 for IAM
            k_date = self._sign(("AWS4" + self.secret_key).encode("utf-8"), date_stamp)
            k_region = self._sign(k_date, "us-east-1")
            k_service = self._sign(k_region, "iam")
            signing_key = self._sign(k_service, "aws4_request")

        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        auth_header = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers["Authorization"] = auth_header

        url = endpoint
        if canonical_querystring:
            url += "?" + canonical_querystring

        return self._http_request(url, method="POST", headers=headers, body=payload)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def test_connection(self) -> Dict[str, Any]:
        """Verify AWS credentials by calling STS GetCallerIdentity."""
        try:
            resp = self._aws_request(
                service="sts",
                action="GetCallerIdentity",
                params={
                    "Action": "GetCallerIdentity",
                    "Version": "2011-06-15",
                },
            )
            body = resp.get("body", {})
            return {
                "ok": True,
                "message": "AWS credentials validated via STS",
                "details": {
                    "account": body.get("GetCallerIdentityResponse", {})
                    .get("GetCallerIdentityResult", {})
                    .get("Account", "unknown"),
                    "arn": body.get("GetCallerIdentityResponse", {})
                    .get("GetCallerIdentityResult", {})
                    .get("Arn", "unknown"),
                },
            }
        except ConnectorError as exc:
            return {"ok": False, "message": str(exc), "details": exc.details}
        except Exception as exc:
            return {"ok": False, "message": f"Unexpected error: {exc}", "details": {}}

    def collect_evidence(self) -> List[EvidenceResult]:
        """Collect evidence from AWS APIs."""
        results: List[EvidenceResult] = []

        # Collect from each source, continuing on individual failures
        for collector in [
            self._collect_cloudtrail_events,
            self._collect_iam_policies,
            self._collect_security_groups,
        ]:
            try:
                results.extend(collector())
            except ConnectorError as exc:
                logger.warning("AWS evidence collection partial failure: %s", exc)
                results.append(
                    EvidenceResult(
                        evidence_type="collection_error",
                        title=f"Failed to collect: {collector.__name__}",
                        description=str(exc),
                        raw_data={"error": str(exc), "details": exc.details},
                        mapped_controls=[],
                        source="aws:error",
                    )
                )
            except Exception as exc:
                logger.warning("AWS evidence collection unexpected error: %s", exc)

        return results

    def _collect_cloudtrail_events(self) -> List[EvidenceResult]:
        """List recent CloudTrail events."""
        resp = self._aws_request(
            service="cloudtrail",
            action="LookupEvents",
            target_header="com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents",
            body=json.dumps({"MaxResults": 50}),
        )
        body = resp.get("body", {})
        events = body.get("Events", [])

        # Summarize events by type
        event_counts: Dict[str, int] = {}
        for evt in events:
            name = evt.get("EventName", "Unknown")
            event_counts[name] = event_counts.get(name, 0) + 1

        return [
            EvidenceResult(
                evidence_type="cloudtrail_events",
                title=f"CloudTrail: {len(events)} recent API events",
                description=f"Collected {len(events)} recent CloudTrail events across {len(event_counts)} unique API actions",
                raw_data={
                    "total_events": len(events),
                    "event_summary": event_counts,
                    "sample_events": events[:5],
                },
                mapped_controls=["SOC2-CC7.2", "ISO27001-A.12.4", "NIST-AU-2", "HIPAA-164.312(b)"],
                source="aws:cloudtrail",
                framework="SOC2,ISO27001,NIST,HIPAA",
            )
        ]

    def _collect_iam_policies(self) -> List[EvidenceResult]:
        """List IAM policies and summarize access posture."""
        resp = self._aws_request(
            service="iam",
            action="ListPolicies",
            params={
                "Action": "ListPolicies",
                "Version": "2010-05-08",
                "Scope": "Local",
                "MaxItems": "100",
            },
        )
        body = resp.get("body", {})
        # IAM returns XML-like structure; handle both XML-parsed dict and raw
        policies_result = body.get("ListPoliciesResponse", {}).get("ListPoliciesResult", {})
        policies = policies_result.get("Policies", {}).get("member", [])
        if isinstance(policies, dict):
            policies = [policies]

        policy_names = [p.get("PolicyName", "unknown") for p in policies]
        # Check for overly permissive policies
        admin_policies = [
            n for n in policy_names
            if "admin" in n.lower() or "fullaccess" in n.lower()
        ]

        return [
            EvidenceResult(
                evidence_type="iam_policies",
                title=f"IAM: {len(policies)} custom policies",
                description=(
                    f"Found {len(policies)} custom IAM policies. "
                    f"{len(admin_policies)} have broad admin/full-access naming patterns."
                ),
                raw_data={
                    "total_policies": len(policies),
                    "policy_names": policy_names[:50],
                    "admin_pattern_policies": admin_policies,
                    "policies_detail": policies[:10],
                },
                mapped_controls=["SOC2-CC6.1", "SOC2-CC6.3", "ISO27001-A.9.2", "NIST-AC-6", "NIST-IA-5"],
                source="aws:iam",
                framework="SOC2,ISO27001,NIST",
            )
        ]

    def _collect_security_groups(self) -> List[EvidenceResult]:
        """List EC2 security groups and flag overly permissive rules."""
        resp = self._aws_request(
            service="ec2",
            action="DescribeSecurityGroups",
            params={
                "Action": "DescribeSecurityGroups",
                "Version": "2016-11-15",
            },
        )
        body = resp.get("body", {})
        sg_set = (
            body.get("DescribeSecurityGroupsResponse", {})
            .get("securityGroupInfo", {})
            .get("item", [])
        )
        if isinstance(sg_set, dict):
            sg_set = [sg_set]

        # Check for 0.0.0.0/0 ingress rules
        open_to_world = []
        for sg in sg_set:
            sg_id = sg.get("groupId", "unknown")
            sg_name = sg.get("groupName", "unknown")
            ip_perms = sg.get("ipPermissions", {}).get("item", [])
            if isinstance(ip_perms, dict):
                ip_perms = [ip_perms]
            for perm in ip_perms:
                ip_ranges = perm.get("ipRanges", {}).get("item", [])
                if isinstance(ip_ranges, dict):
                    ip_ranges = [ip_ranges]
                for r in ip_ranges:
                    if r.get("cidrIp") == "0.0.0.0/0":
                        open_to_world.append({
                            "sg_id": sg_id,
                            "sg_name": sg_name,
                            "port": perm.get("fromPort", "all"),
                            "protocol": perm.get("ipProtocol", "all"),
                        })

        return [
            EvidenceResult(
                evidence_type="security_groups",
                title=f"EC2: {len(sg_set)} security groups, {len(open_to_world)} open to world",
                description=(
                    f"Found {len(sg_set)} security groups. "
                    f"{len(open_to_world)} ingress rules allow traffic from 0.0.0.0/0."
                ),
                raw_data={
                    "total_security_groups": len(sg_set),
                    "open_to_world_rules": open_to_world,
                    "security_groups_summary": [
                        {"id": sg.get("groupId"), "name": sg.get("groupName")}
                        for sg in sg_set[:20]
                    ],
                },
                mapped_controls=["SOC2-CC6.6", "ISO27001-A.13.1", "NIST-SC-7"],
                source="aws:ec2",
                framework="SOC2,ISO27001,NIST",
            )
        ]
