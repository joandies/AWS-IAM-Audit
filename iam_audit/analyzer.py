from iam_audit.findings import Finding
from iam_audit.checks.base import BaseCheck


def analyze(policy: dict, checks: list[BaseCheck]) -> list[Finding]:
    findings = []

    for check in checks:
        results = check.run(policy)
        findings.extend(results)

    return findings