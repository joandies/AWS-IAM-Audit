import unittest
from iam_audit.checks.admin_equivalent import AdminEquivalentCheck
from iam_audit.findings import Severity


class TestAdminEquivalentCheck(unittest.TestCase):

    def setUp(self):
        self.check = AdminEquivalentCheck()

    def _make_policy(self, statements, managed_policies=None):
        policy = {"_file": "test.json", "Statement": statements}
        if managed_policies:
            policy["ManagedPolicies"] = managed_policies
        return policy

    def test_action_and_resource_wildcard_is_critical(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].check_id, "IAM-003")

    def test_administrator_access_managed_policy_is_critical(self):
        policy = self._make_policy(
            statements=[],
            managed_policies=["arn:aws:iam::aws:policy/AdministratorAccess"]
        )
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].check_id, "IAM-003")

    def test_power_user_access_managed_policy_is_critical(self):
        policy = self._make_policy(
            statements=[],
            managed_policies=["arn:aws:iam::aws:policy/PowerUserAccess"]
        )
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].check_id, "IAM-003")

    def test_deny_statement_is_ignored(self):
        policy = self._make_policy([
            {"Effect": "Deny", "Action": "*", "Resource": "*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_scoped_policy_produces_no_findings(self):
        policy = self._make_policy([
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"}
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_both_vulnerabilities_detected(self):
        policy = self._make_policy(
            statements=[{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            managed_policies=["arn:aws:iam::aws:policy/AdministratorAccess"]
        )
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()