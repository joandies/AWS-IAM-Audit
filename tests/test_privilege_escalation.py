import unittest
from iam_audit.checks.privilege_escalation import PrivilegeEscalationCheck
from iam_audit.findings import Severity


class TestPrivilegeEscalationCheck(unittest.TestCase):

    def setUp(self):
        self.check = PrivilegeEscalationCheck()

    def _make_policy(self, statements):
        return {"_file": "test.json", "Statement": statements}

    def test_passrole_and_run_instances_is_critical(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].check_id, "IAM-004")

    def test_escalation_path_across_multiple_statements(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_create_policy_version_is_critical(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_full_wildcard_action_is_skipped(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_deny_statement_is_ignored(self):
        policy = self._make_policy([
            {"Effect": "Deny", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_safe_policy_produces_no_findings(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:DescribeInstances"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)
        
    def test_remediation_is_path_specific(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertIn("iam:CreatePolicyVersion", findings[0].remediation)
        self.assertNotIn("iam:PassRole", findings[0].remediation)

    def test_passrole_remediation_mentions_passrole(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertIn("iam:PassRole", findings[0].remediation)

if __name__ == "__main__":
    unittest.main()