import unittest
from iam_audit.checks.wildcard_resource import WildcardResourceCheck
from iam_audit.findings import Severity


class TestWildcardResourceCheck(unittest.TestCase):

    def setUp(self):
        self.check = WildcardResourceCheck()

    def _make_policy(self, statements):
        return {"_file": "test.json", "Statement": statements}

    def test_sensitive_actions_on_wildcard_resource_is_high(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["s3:GetObject", "secretsmanager:GetSecretValue"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].check_id, "IAM-002")

    def test_scoped_resource_produces_no_findings(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_wildcard_action_is_skipped(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_deny_statement_is_ignored(self):
        policy = self._make_policy([
            {"Effect": "Deny", "Action": ["s3:GetObject"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_non_sensitive_actions_on_wildcard_resource_produce_no_findings(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()