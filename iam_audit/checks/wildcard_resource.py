from iam_audit.checks.base import BaseCheck
from iam_audit.findings import Finding, Severity

SENSITIVE_ACTIONS = {
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "iam:GetUser",
    "iam:ListUsers",
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey",
    "ec2:DescribeInstances",
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "rds:DescribeDBInstances",
    "rds:DeleteDBInstance",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "sts:AssumeRole",
}


class WildcardResourceCheck(BaseCheck):

    def run(self, policy: dict) -> list[Finding]:
        findings = []
        statements = policy.get("Statement", [])

        for index, statement in enumerate(statements):
            if statement.get("Effect") == "Deny":
                continue

            resource = statement.get("Resource", "")
            if isinstance(resource, list):
                has_wildcard = "*" in resource
            else:
                has_wildcard = resource == "*"

            if not has_wildcard:
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            if "*" in actions or any(a.endswith(":*") for a in actions):
                continue

            dangerous = [a for a in actions if a in SENSITIVE_ACTIONS]
            if dangerous:
                findings.append(Finding(
                    check_id="IAM-002",
                    severity=Severity.HIGH,
                    title="Sensitive actions granted on wildcard resource",
                    file=policy["_file"],
                    statement_index=index,
                    description=f"Statement #{index} grants sensitive actions on Resource: '*': {', '.join(dangerous)}.",
                    risk="These actions are not scoped to a specific resource, meaning they apply to every matching resource in the account. This violates least privilege and widens the blast radius of a compromised identity.",
                    remediation="Replace Resource: '*' with the specific ARN of the resource the principal needs to access.",
                ))

        return findings