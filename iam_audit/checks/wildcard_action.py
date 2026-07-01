from iam_audit.checks.base import BaseCheck
from iam_audit.findings import Finding, Severity


class WildcardActionCheck(BaseCheck):

    def run(self, policy: dict) -> list[Finding]:
        findings = []
        statements = policy.get("Statement", [])

        for index, statement in enumerate(statements):
            if statement.get("Effect") == "Deny":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            if "*" in actions:
                findings.append(Finding(
                    check_id="IAM-001",
                    severity=Severity.CRITICAL,
                    title="Wildcard action grants full AWS access",
                    file=policy["_file"],
                    statement_index=index,
                    description=f"Statement #{index} grants Action: '*', allowing every API call across all AWS services.",
                    risk="Any principal with this policy can perform any action on any AWS service, including creating users, exfiltrating data, or destroying infrastructure.",
                    remediation="Replace '*' with the specific actions the principal needs. Follow the principle of least privilege.",
                ))
                continue

            service_wildcards = [a for a in actions if a.endswith(":*")]
            if service_wildcards:
                findings.append(Finding(
                    check_id="IAM-001",
                    severity=Severity.HIGH,
                    title="Wildcard action grants full service access",
                    file=policy["_file"],
                    statement_index=index,
                    description=f"Statement #{index} grants wildcard actions: {', '.join(service_wildcards)}.",
                    risk="A service-level wildcard grants every operation in that service, including destructive and sensitive ones far beyond what the workload needs.",
                    remediation="Replace each wildcard with the specific actions required. For example, use 's3:GetObject' instead of 's3:*'.",
                ))

        return findings