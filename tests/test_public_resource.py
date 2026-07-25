import unittest
from iam_audit.checks.public_resource import PublicResourceCheck
from iam_audit.findings import Severity


class TestPublicResourceCheck(unittest.TestCase):

    def setUp(self):
        self.check = PublicResourceCheck()

    def _make_policy(self, statements):
        return {"_file": "test.json", "Statement": statements}

    def test_wildcard_principal_no_condition_is_critical(self):
        policy = self._make_policy([
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].check_id, "IAM-006")

    def test_wildcard_principal_aws_key_no_condition_is_critical(self):
        policy = self._make_policy([
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_wildcard_principal_with_source_vpc_condition_produces_no_findings(self):
        policy = self._make_policy([
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceVpc": "vpc-0a1b2c3d4e5f"
                    }
                }
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_wildcard_principal_with_principal_org_id_produces_no_findings(self):
        policy = self._make_policy([
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalOrgID": "o-exampleorgid"
                    }
                }
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_specific_principal_produces_no_findings(self):
        policy = self._make_policy([
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)

    def test_deny_statement_is_ignored(self):
        policy = self._make_policy([
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ])
        findings = self.check.run(policy)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()