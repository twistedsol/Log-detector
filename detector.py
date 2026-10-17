#!/usr/bin/env python3
"""Realone Log Detector

Reads AWS CloudTrail-style audit logs (JSON, or gzipped JSON) and flags
suspicious activity using a small set of readable rules.

Usage:
    python3 detector.py sample_logs.json
    python3 detector.py sample_logs.json --format json
    python3 detector.py sample_logs.json --min-severity high
    python3 detector.py logs/*.json.gz --threshold 5 --window-minutes 5

Exit code is 1 when any finding is at or above --fail-on (default: high),
so the detector can gate a script or CI job. Otherwise it is 0.

Standard library only. No cloud account needed.
"""

import argparse
import gzip
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str
    time: str          # ISO 8601, UTC
    actor: str
    ip: str
    event_name: str
    summary: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_time(value):
    """Parse CloudTrail's '2026-10-16T10:05:00Z' into an aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def dig(obj, *keys, default=None):
    """Safely read nested dict keys: dig(e, 'userIdentity', 'type')."""
    for key in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key)
        if obj is None:
            return default
    return obj


def actor_of(event):
    ident = event.get("userIdentity") or {}
    if ident.get("type") == "Root":
        return "root"
    return ident.get("userName") or ident.get("arn") or ident.get("type") or "unknown"


def make_finding(event, rule, severity, summary):
    return Finding(
        rule=rule,
        severity=severity,
        time=event.get("eventTime", ""),
        actor=actor_of(event),
        ip=event.get("sourceIPAddress", "unknown"),
        event_name=event.get("eventName", ""),
        summary=summary,
    )


def is_console_login(event):
    return event.get("eventName") == "ConsoleLogin"


def login_succeeded(event):
    return dig(event, "responseElements", "ConsoleLogin") == "Success"


# ---------------------------------------------------------------------------
# Single-event rules: each takes one event and returns a list of findings
# ---------------------------------------------------------------------------

def rule_root_login(event):
    """Root should almost never be used. Any root console login is worth a look."""
    if not is_console_login(event) or dig(event, "userIdentity", "type") != "Root":
        return []
    if login_succeeded(event):
        return [make_finding(event, "ROOT_LOGIN", "high",
                             "Root account signed in to the console")]
    return [make_finding(event, "ROOT_LOGIN", "medium",
                         "Failed root console login attempt")]


def rule_no_mfa_login(event):
    """Successful console login without MFA.

    Limited to IAM users: federated and SSO logins don't report MFAUsed the
    same way, so including them would create false alarms. Root has its own rule.
    """
    if not is_console_login(event) or not login_succeeded(event):
        return []
    if dig(event, "userIdentity", "type") != "IAMUser":
        return []
    if dig(event, "additionalEventData", "MFAUsed") != "No":
        return []
    return [make_finding(event, "NO_MFA_LOGIN", "medium",
                         "Console login succeeded without MFA")]


ATTACH_POLICY_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
OTHER_IAM_CHANGE_EVENTS = {
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicyVersion",
    "CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile",
}


def rule_iam_privilege_change(event):
    """IAM changes that create access or widen permissions."""
    if event.get("eventSource") != "iam.amazonaws.com":
        return []
    name = event.get("eventName")
    if name in ATTACH_POLICY_EVENTS:
        policy_arn = dig(event, "requestParameters", "policyArn", default="")
        target = (dig(event, "requestParameters", "userName")
                  or dig(event, "requestParameters", "roleName")
                  or dig(event, "requestParameters", "groupName")
                  or "unknown")
        if policy_arn.endswith("/AdministratorAccess"):
            return [make_finding(event, "IAM_PRIVILEGE_CHANGE", "high",
                                 f"AdministratorAccess attached to {target}")]
        return [make_finding(event, "IAM_PRIVILEGE_CHANGE", "medium",
                             f"Policy {policy_arn.split('/')[-1] or 'unknown'} attached to {target}")]
    if name in OTHER_IAM_CHANGE_EVENTS:
        target = dig(event, "requestParameters", "userName", default="")
        suffix = f" for {target}" if target else ""
        return [make_finding(event, "IAM_PRIVILEGE_CHANGE", "medium",
                             f"{name}{suffix}")]
    return []


def _policy_statements(event):
    """Return the statements of a bucket policy, which may be a dict or a JSON string."""
    policy = dig(event, "requestParameters", "bucketPolicy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return []
    statements = dig(policy, "Statement", default=[])
    if isinstance(statements, dict):
        statements = [statements]
    return statements


def _is_wildcard_principal(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        value = principal.get("AWS")
        return value == "*" or (isinstance(value, list) and "*" in value)
    return False


def rule_public_bucket(event):
    """S3 changes that can expose a bucket to the whole internet."""
    if event.get("eventSource") != "s3.amazonaws.com":
        return []
    name = event.get("eventName")
    bucket = dig(event, "requestParameters", "bucketName", default="unknown")

    if name == "PutBucketPolicy":
        for stmt in _policy_statements(event):
            # A wildcard principal with a Condition (e.g. a VPC endpoint) is
            # usually restricted, so only flag the unconditional case.
            if (stmt.get("Effect") == "Allow"
                    and _is_wildcard_principal(stmt.get("Principal"))
                    and not stmt.get("Condition")):
                return [make_finding(event, "PUBLIC_BUCKET", "high",
                                     f"Bucket policy on {bucket} allows everyone ('*')")]

    if name == "PutBucketAcl":
        grants = dig(event, "requestParameters", "AccessControlPolicy",
                     "AccessControlList", "Grant", default=[])
        if isinstance(grants, dict):
            grants = [grants]
        for grant in grants:
            uri = dig(grant, "Grantee", "URI", default="")
            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                return [make_finding(event, "PUBLIC_BUCKET", "high",
                                     f"ACL on {bucket} grants access to {uri.split('/')[-1]}")]

    if name == "DeleteBucketPublicAccessBlock":
        return [make_finding(event, "PUBLIC_BUCKET", "high",
                             f"Public access block removed from {bucket}")]
    return []


def rule_logging_tampered(event):
    """Anyone turning off or weakening audit logging deserves immediate attention."""
    if event.get("eventSource") != "cloudtrail.amazonaws.com":
        return []
    name = event.get("eventName")
    trail = dig(event, "requestParameters", "name", default="unknown")
    if name in {"StopLogging", "DeleteTrail"}:
        return [make_finding(event, "LOGGING_TAMPERED", "critical",
                             f"{name} on trail {trail}")]
    if name in {"UpdateTrail", "PutEventSelectors"}:
        return [make_finding(event, "LOGGING_TAMPERED", "high",
                             f"{name} on trail {trail}")]
    return []


EVENT_RULES = [
    rule_root_login,
    rule_no_mfa_login,
    rule_iam_privilege_change,
    rule_public_bucket,
    rule_logging_tampered,
]


# ---------------------------------------------------------------------------
# Correlated rule: looks across many events
# ---------------------------------------------------------------------------

def rule_brute_force(events, threshold=3, window_minutes=10):
    """Several failed console logins from one IP, then (worse) a success.

    A burst is a run of failures from one IP where each failure comes within
    window_minutes of the previous one. A burst of `threshold` or more is
    flagged. A later success from the same IP within the window after the
    burst is escalated to critical.
    """
    window = timedelta(minutes=window_minutes)
    failures_by_ip = {}
    successes_by_ip = {}

    for event in events:
        if not is_console_login(event):
            continue
        ip = event.get("sourceIPAddress", "unknown")
        if login_succeeded(event):
            successes_by_ip.setdefault(ip, []).append(event)
        elif dig(event, "responseElements", "ConsoleLogin") == "Failure":
            failures_by_ip.setdefault(ip, []).append(event)

    findings = []
    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: parse_time(e["eventTime"]))
        bursts, current = [], [failures[0]]
        for event in failures[1:]:
            gap = parse_time(event["eventTime"]) - parse_time(current[-1]["eventTime"])
            if gap <= window:
                current.append(event)
            else:
                bursts.append(current)
                current = [event]
        bursts.append(current)

        for burst in bursts:
            if len(burst) < threshold:
                continue
            users = sorted({actor_of(e) for e in burst})
            first, last = burst[0], burst[-1]
            span = parse_time(last["eventTime"]) - parse_time(first["eventTime"])
            findings.append(make_finding(
                last, "BRUTE_FORCE", "high",
                f"{len(burst)} failed logins in {int(span.total_seconds())}s "
                f"targeting: {', '.join(users)}"))

            last_failure_time = parse_time(last["eventTime"])
            for success in successes_by_ip.get(ip, []):
                delta = parse_time(success["eventTime"]) - last_failure_time
                if timedelta(0) <= delta <= window:
                    findings.append(make_finding(
                        success, "BRUTE_FORCE_SUCCESS", "critical",
                        f"Login succeeded {int(delta.total_seconds())}s after "
                        f"{len(burst)} failures from the same IP"))
    return findings


# ---------------------------------------------------------------------------
# Loading, running, reporting
# ---------------------------------------------------------------------------

def load_events(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return data.get("Records", [])
    return data


def detect(events, threshold=3, window_minutes=10):
    events = sorted(events, key=lambda e: parse_time(e["eventTime"]))
    findings = []
    for event in events:
        for rule in EVENT_RULES:
            findings.extend(rule(event))
    findings.extend(rule_brute_force(events, threshold, window_minutes))
    findings.sort(key=lambda f: (parse_time(f.time), -SEVERITY_ORDER[f.severity]))
    return findings


def format_text(findings, scanned):
    lines = ["Realone Log Detector",
             f"Scanned {scanned} events, {len(findings)} findings", ""]
    if not findings:
        lines.append("No suspicious activity found.")
        return "\n".join(lines)

    for severity in ("critical", "high", "medium", "low"):
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        lines.append(f"{severity.upper()} ({len(group)})")
        for f in group:
            stamp = parse_time(f.time).strftime("%H:%M:%S")
            lines.append(f"  [{stamp}] {f.rule}  {f.actor} @ {f.ip}")
            lines.append(f"           {f.summary}")
        lines.append("")
    return "\n".join(lines).rstrip()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Flag suspicious activity in CloudTrail-style audit logs.")
    parser.add_argument("paths", nargs="+", help="log files (.json or .json.gz)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                        help="hide findings below this severity (default: low)")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                        help="exit 1 if any finding is at or above this severity (default: high)")
    parser.add_argument("--threshold", type=int, default=3,
                        help="failed logins from one IP that count as brute force (default: 3)")
    parser.add_argument("--window-minutes", type=int, default=10,
                        help="max gap between failures in one burst (default: 10)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    events = []
    for path in args.paths:
        try:
            events.extend(load_events(path))
        except (OSError, ValueError) as err:
            print(f"error: could not read {path}: {err}", file=sys.stderr)
            return 2

    findings = detect(events, args.threshold, args.window_minutes)
    floor = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= floor]

    if args.format == "json":
        print(json.dumps({"scanned": len(events),
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(format_text(findings, len(events)))

    fail_floor = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= fail_floor for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
