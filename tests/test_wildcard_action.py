import unittest
from iam_audit.checks.wildcard_action import WildcardActionCheck
from iam_audit.findings import Severity


class TestWildcardActionCheck(unittest.TestCase):

    def setUp(self):
        self.check = WildcardActionCheck()

    def _make_policy(self, statements):
        return {"_file": "test.json", "Statement": statements}

    def test_full_wildcard_is_critical(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].check_id, "IAM-001")

    def test_service_wildcard_is_high(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["s3:*", "ec2:*"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_deny_statement_is_ignored(self):
        policy = self._make_policy([
            {"Effect": "Deny", "Action": "*", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_specific_actions_produce_no_findings(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()