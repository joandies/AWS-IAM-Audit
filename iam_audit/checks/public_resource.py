from iam_audit.checks.base import BaseCheck
from iam_audit.findings import Finding, Severity

RESTRICTING_CONDITIONS = {
    "aws:PrincipalOrgID",
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:PrincipalAccount",
    "aws:SourceVpc",
    "aws:SourceVpce",
}


class PublicResourceCheck(BaseCheck):

    def run(self, policy: dict) -> list[Finding]:
        findings = []
        statements = policy.get("Statement", [])

        for index, statement in enumerate(statements):
            if statement.get("Effect") == "Deny":
                continue

            principal = statement.get("Principal")
            if principal is None:
                continue

            is_wildcard = (
                principal == "*"
                or (isinstance(principal, dict) and principal.get("AWS") == "*")
            )

            if not is_wildcard:
                continue

            conditions = statement.get("Condition", {})
            condition_keys = set()
            for operator in conditions.values():
                if isinstance(operator, dict):
                    condition_keys.update(operator.keys())

            has_restricting_condition = bool(
                condition_keys & RESTRICTING_CONDITIONS
            )

            if not has_restricting_condition:
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                findings.append(Finding(
                    check_id="IAM-006",
                    severity=Severity.CRITICAL,
                    title="Resource policy grants public access",
                    file=policy["_file"],
                    statement_index=index,
                    description=f"Statement #{index} grants {', '.join(actions)} to Principal: '*' with no restricting condition, making this resource publicly accessible.",
                    risk="Any entity on the internet can access this resource without authentication. This is a common root cause of data breaches involving exposed S3 buckets, SNS topics, and SQS queues.",
                    remediation="Replace Principal: '*' with a specific AWS account or service ARN. If public access is genuinely required, add aws:SourceVpc or aws:SourceVpce conditions to restrict access to known network origins.",
                ))

        return findings