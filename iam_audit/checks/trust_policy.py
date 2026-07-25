from iam_audit.checks.base import BaseCheck
from iam_audit.findings import Finding, Severity

RESTRICTING_CONDITIONS = {
    "aws:PrincipalOrgID",
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:PrincipalAccount",
}


class TrustPolicyCheck(BaseCheck):

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
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if "sts:AssumeRole" not in actions:
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
                findings.append(Finding(
                    check_id="IAM-005",
                    severity=Severity.CRITICAL,
                    title="Trust policy allows any principal without restriction",
                    file=policy["_file"],
                    statement_index=index,
                    description=f"Statement #{index} sets Principal to '*' with no restricting condition, allowing any entity in the world to attempt to assume this role.",
                    risk="An unrestricted wildcard principal means any AWS account or unauthenticated entity can attempt to assume this role. If the role has sensitive permissions this is a critical exposure.",
                    remediation="Replace '*' with the specific AWS account ARN or service principal that needs to assume this role. If a wildcard is required, add a condition using aws:PrincipalOrgID or aws:SourceAccount to restrict access.",
                ))
            else:
                findings.append(Finding(
                    check_id="IAM-005",
                    severity=Severity.MEDIUM,
                    title="Trust policy uses wildcard principal with conditions",
                    file=policy["_file"],
                    statement_index=index,
                    description=f"Statement #{index} sets Principal to '*' but restricts access via conditions: {', '.join(condition_keys & RESTRICTING_CONDITIONS)}.",
                    risk="Conditions reduce but do not eliminate the risk of a wildcard principal. A misconfigured or missing condition value could still expose this role to unintended principals.",
                    remediation="Replace the wildcard principal with the specific ARN of the trusted entity where possible. Rely on conditions only when a specific ARN cannot be defined.",
                ))

        return findings