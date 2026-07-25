import unittest
from iam_audit.checks.trust_policy import TrustPolicyCheck
from iam_audit.findings import Severity


class TestTrustPolicyCheck(unittest.TestCase):

    def setUp(self):
        self.check = TrustPolicyCheck()

    def _make_policy(self, statements):
        return {"_file": "test.json", "Statement": statements}

    def test_wildcard_principal_no_condition_is_critical(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].check_id, "IAM-005")

    def test_wildcard_principal_aws_key_no_condition_is_critical(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_wildcard_principal_with_restricting_condition_is_medium(self):
        policy = self._make_policy([
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalOrgID": "o-exampleorgid"
                    }
                }
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_specific_principal_produces_no_findings(self):
        policy = self._make_policy([
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole"
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_deny_statement_is_ignored(self):
        policy = self._make_policy([
            {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_no_principal_produces_no_findings(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()