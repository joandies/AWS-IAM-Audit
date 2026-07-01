from iam_audit.findings import Finding, Severity

RESET = "\033[0m"
BOLD = "\033[1m"

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[96m",
}


def print_findings(findings: list[Finding], filepath: str) -> None:
    if not findings:
        print(f"\n[OK] No issues found in {filepath}\n")
        return

    print(f"\n{BOLD}Results for: {filepath}{RESET}")
    print(f"  {len(findings)} finding(s) found\n")

    for finding in findings:
        color = SEVERITY_COLORS[finding.severity]
        severity_label = finding.severity.value.upper()

        print(f"{color}{BOLD}[{severity_label}] {finding.check_id} - {finding.title}{RESET}")
        print(f"  Statement : #{finding.statement_index}")
        print(f"  Description : {finding.description}")
        print(f"  Risk        : {finding.risk}")
        print(f"  Remediation : {finding.remediation}")
        print()