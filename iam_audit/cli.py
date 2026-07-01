import argparse
import sys

from iam_audit.loader import load_policy
from iam_audit.analyzer import analyze
from iam_audit.report import print_findings


def build_checks():
    return []


def main():
    parser = argparse.ArgumentParser(
        description="AWS IAM policy static analyzer. Detects common misconfigurations in IAM policy JSON files."
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="POLICY_FILE",
        help="One or more IAM policy JSON files to analyze."
    )

    args = parser.parse_args()
    checks = build_checks()
    exit_code = 0

    for filepath in args.files:
        try:
            policy = load_policy(filepath)
        except ValueError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            exit_code = 1
            continue

        findings = analyze(policy, checks)
        print_findings(findings, filepath)

        if findings:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()