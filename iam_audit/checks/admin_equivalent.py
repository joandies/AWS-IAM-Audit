from iam_audit.checks.base import BaseCheck
from iam_audit.findings import Finding, Severity

DANGEROUS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


class AdminEquivalentCheck(BaseCheck):

    def run(self, policy: dict) -> list[Finding]:
        findings = []
        statements = policy.get("Statement", [])

        for index, statement in enumerate(statements):
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resource = statement.get("Resource", "")
            if isinstance(resource, list):
                has_wildcard_resource = "*" in resource
            else:
                has_wildcard_resource = resource == "*"

            if "*" in actions and has_wildcard_resource:
                findings.append(Finding(
                    check_id="IAM-003",
                    severity=Severity.CRITICAL,
                    title="Admin-equivalent policy statement detected",
                    file=policy["_file"],
                    statement_index=index,
                    description=f"Statement #{index} grants Action: '*' on Resource: '*' with Effect: Allow, which is functionally identical to AdministratorAccess.",
                    risk="This grants unrestricted access to every AWS API and every resource in the account. A compromised identity with this policy can exfiltrate data, create backdoor users, or destroy the entire infrastructure.",
                    remediation="Remove this statement and replace it with the specific actions and resources the principal actually needs. Never use Action: '*' with Resource: '*' in production.",
                ))

        managed_policies = policy.get("ManagedPolicies", [])
        for arn in managed_policies:
            if arn in DANGEROUS_MANAGED_POLICIES:
                findings.append(Finding(
                    check_id="IAM-003",
                    severity=Severity.CRITICAL,
                    title=f"Dangerous managed policy attached: {arn}",
                    file=policy["_file"],
                    statement_index=-1,
                    description=f"The managed policy {arn} is referenced in this document.",
                    risk="AdministratorAccess and PowerUserAccess grant extremely broad permissions that violate least privilege. These policies are rarely appropriate outside of break-glass or initial setup scenarios.",
                    remediation="Replace with a custom policy scoped to the specific actions and resources the principal needs. If broad access is genuinely required, document the justification and restrict via SCPs at the organization level.",
                ))

        return findings