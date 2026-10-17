"""Tests for the Realone log detector. Run with: python3 -m unittest -v"""

import contextlib
import io
import json
import os
import unittest

import detector

HERE = os.path.dirname(os.path.abspath(__file__))


def login(time, user, ok=True, mfa="Yes", ip="198.51.100.1", user_type="IAMUser"):
    ident = {"type": user_type, "userName": user}
    if user_type == "Root":
        ident = {"type": "Root"}
    return {
        "eventTime": time,
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": ip,
        "userIdentity": ident,
        "responseElements": {"ConsoleLogin": "Success" if ok else "Failure"},
        "additionalEventData": {"MFAUsed": mfa},
    }


def rules_of(findings):
    return [f.rule for f in findings]


class RuleTests(unittest.TestCase):
    def test_root_login_success_is_high(self):
        findings = detector.detect([login("2026-10-16T10:00:00Z", "root", user_type="Root")])
        self.assertEqual(rules_of(findings), ["ROOT_LOGIN"])
        self.assertEqual(findings[0].severity, "high")

    def test_root_login_failure_is_medium(self):
        findings = detector.detect([login("2026-10-16T10:00:00Z", "root", ok=False, user_type="Root")])
        self.assertEqual(findings[0].severity, "medium")

    def test_no_mfa_flagged_for_iam_user(self):
        findings = detector.detect([login("2026-10-16T10:00:00Z", "carol", mfa="No")])
        self.assertEqual(rules_of(findings), ["NO_MFA_LOGIN"])

    def test_mfa_login_is_clean(self):
        self.assertEqual(detector.detect([login("2026-10-16T10:00:00Z", "alice", mfa="Yes")]), [])

    def test_no_mfa_ignores_federated_users(self):
        event = login("2026-10-16T10:00:00Z", "sso-user", mfa="No", user_type="AssumedRole")
        self.assertEqual(detector.detect([event]), [])

    def test_single_failed_login_is_clean(self):
        self.assertEqual(detector.detect([login("2026-10-16T10:00:00Z", "dave", ok=False)]), [])

    def test_brute_force_needs_threshold(self):
        events = [login(f"2026-10-16T10:0{i}:00Z", "admin", ok=False) for i in range(2)]
        self.assertEqual(detector.detect(events), [])
        events.append(login("2026-10-16T10:02:00Z", "admin", ok=False))
        self.assertEqual(rules_of(detector.detect(events)), ["BRUTE_FORCE"])

    def test_failures_far_apart_are_not_a_burst(self):
        events = [login(f"2026-10-16T{10 + i}:00:00Z", "admin", ok=False) for i in range(4)]
        self.assertEqual(detector.detect(events), [])

    def test_failures_from_different_ips_are_not_combined(self):
        events = [login(f"2026-10-16T10:0{i}:00Z", "admin", ok=False, ip=f"198.51.100.{i}")
                  for i in range(4)]
        self.assertEqual(detector.detect(events), [])

    def test_success_after_burst_is_critical(self):
        events = [login(f"2026-10-16T10:0{i}:00Z", "admin", ok=False, ip="203.0.113.5")
                  for i in range(3)]
        events.append(login("2026-10-16T10:04:00Z", "admin", ok=True, mfa="Yes", ip="203.0.113.5"))
        findings = detector.detect(events)
        self.assertEqual(sorted(rules_of(findings)), ["BRUTE_FORCE", "BRUTE_FORCE_SUCCESS"])

    def test_admin_policy_is_high_and_readonly_is_medium(self):
        def attach(arn):
            return {"eventTime": "2026-10-16T10:00:00Z", "eventSource": "iam.amazonaws.com",
                    "eventName": "AttachUserPolicy", "sourceIPAddress": "198.51.100.1",
                    "userIdentity": {"type": "IAMUser", "userName": "admin"},
                    "requestParameters": {"userName": "bob", "policyArn": arn}}
        high = detector.detect([attach("arn:aws:iam::aws:policy/AdministratorAccess")])
        medium = detector.detect([attach("arn:aws:iam::aws:policy/ReadOnlyAccess")])
        self.assertEqual(high[0].severity, "high")
        self.assertEqual(medium[0].severity, "medium")

    def _bucket_policy(self, statement, as_string=False):
        policy = {"Version": "2012-10-17", "Statement": [statement]}
        return {"eventTime": "2026-10-16T10:00:00Z", "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketPolicy", "sourceIPAddress": "198.51.100.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"bucketName": "b",
                                      "bucketPolicy": json.dumps(policy) if as_string else policy}}

    def test_public_bucket_policy_flagged_for_dict_and_string(self):
        stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        self.assertEqual(rules_of(detector.detect([self._bucket_policy(stmt)])), ["PUBLIC_BUCKET"])
        self.assertEqual(rules_of(detector.detect([self._bucket_policy(stmt, True)])), ["PUBLIC_BUCKET"])

    def test_aws_star_principal_flagged(self):
        stmt = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"}
        self.assertEqual(rules_of(detector.detect([self._bucket_policy(stmt)])), ["PUBLIC_BUCKET"])

    def test_restricted_bucket_policy_is_clean(self):
        specific = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "s3:GetObject"}
        conditional = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}
        deny = {"Effect": "Deny", "Principal": "*", "Action": "s3:*"}
        for stmt in (specific, conditional, deny):
            self.assertEqual(detector.detect([self._bucket_policy(stmt)]), [])

    def test_bucket_acl_all_users_flagged(self):
        event = {"eventTime": "2026-10-16T10:00:00Z", "eventSource": "s3.amazonaws.com",
                 "eventName": "PutBucketAcl", "sourceIPAddress": "198.51.100.1",
                 "userIdentity": {"type": "IAMUser", "userName": "alice"},
                 "requestParameters": {"bucketName": "b", "AccessControlPolicy": {
                     "AccessControlList": {"Grant": [{"Grantee": {
                         "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}}}}
        self.assertEqual(rules_of(detector.detect([event])), ["PUBLIC_BUCKET"])

    def test_stop_logging_is_critical(self):
        event = {"eventTime": "2026-10-16T10:00:00Z", "eventSource": "cloudtrail.amazonaws.com",
                 "eventName": "StopLogging", "sourceIPAddress": "198.51.100.1",
                 "userIdentity": {"type": "IAMUser", "userName": "admin"},
                 "requestParameters": {"name": "t"}}
        findings = detector.detect([event])
        self.assertEqual((findings[0].rule, findings[0].severity), ("LOGGING_TAMPERED", "critical"))

    def test_unordered_input_is_handled(self):
        events = [login(f"2026-10-16T10:0{i}:00Z", "admin", ok=False) for i in (2, 0, 1)]
        self.assertEqual(rules_of(detector.detect(events)), ["BRUTE_FORCE"])


class SampleFileTests(unittest.TestCase):
    def test_sample_logs_produce_expected_findings(self):
        events = detector.load_events(os.path.join(HERE, "sample_logs.json"))
        findings = detector.detect(events)
        self.assertEqual(len(events), 18)
        self.assertEqual(sorted(rules_of(findings)), sorted([
            "NO_MFA_LOGIN", "BRUTE_FORCE", "BRUTE_FORCE_SUCCESS", "NO_MFA_LOGIN",
            "IAM_PRIVILEGE_CHANGE", "IAM_PRIVILEGE_CHANGE", "PUBLIC_BUCKET",
            "LOGGING_TAMPERED", "ROOT_LOGIN"]))

    def test_exit_code_follows_fail_on(self):
        path = os.path.join(HERE, "sample_logs.json")
        clean = os.path.join(HERE, "clean_logs_for_test.json")
        with open(clean, "w") as handle:
            json.dump({"Records": [login("2026-10-16T10:00:00Z", "alice")]}, handle)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(detector.main([path, "--format", "json"]), 1)
                self.assertEqual(detector.main([path, "--fail-on", "critical"]), 1)
                self.assertEqual(detector.main([clean]), 0)
        finally:
            os.remove(clean)


if __name__ == "__main__":
    unittest.main()
