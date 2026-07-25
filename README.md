# AWS IAM Audit

A static analyzer for AWS IAM policy documents. Detects common misconfigurations, privilege escalation paths, and overly permissive access patterns. No AWS account or credentials required.

Built as a portfolio project to demonstrate practical IAM security knowledge and Python tooling skills.

## Contents

- [What this is](#what-this-is)
- [What this is not](#what-this-is-not)
- [Known limitations](#known-limitations)
- [Installation](#installation)
- [Usage](#usage)
- [Example output](#example-output)
- [Detections](#detections)
  - [IAM-001 - Wildcard Action](#iam-001---wildcard-action)
  - [IAM-002 - Wildcard Resource with Sensitive Actions](#iam-002---wildcard-resource-with-sensitive-actions)
  - [IAM-003 - Admin-Equivalent Policy](#iam-003---admin-equivalent-policy)
  - [IAM-004 - Privilege Escalation Path](#iam-004---privilege-escalation-path)
  - [IAM-005 - Trust Policy with Broad Principal](#iam-005---trust-policy-with-broad-principal)
  - [IAM-006 - Public Resource Policy](#iam-006---public-resource-policy)
- [Architecture](#architecture)
- [Running tests](#running-tests)
- [Related tools](#related-tools)
- [Related projects](#related-projects)
- [Author](#author)
- [License](#license)

## What this is

AWS Identity and Access Management (IAM) policies are JSON documents that define who can do what in an AWS account. When misconfigured, they are one of the most common root causes of cloud security incidents: data breaches from public S3 buckets, account takeovers through privilege escalation, and lateral movement through overly permissive roles.

This tool reads IAM policy JSON files and reports misconfigurations with severity levels, explanations, and remediation guidance. It is a linter for IAM policies, in the same spirit as ESLint for JavaScript or flake8 for Python.

## What this is not

- This is not a replacement for production CSPM tools like Prowler, Wiz, Prisma Cloud, or Aikido.
- It does not connect to a live AWS account.
- It does not analyze CloudTrail logs or detect unused permissions.
- It does not fetch or enumerate policies from AWS APIs.
- It performs static analysis only: it reads the JSON you give it and nothing else.

## Known limitations

- Does not expand partial wildcards like `s3:Get*` (only `*` and `service:*` are detected).
- Does not evaluate `NotAction`, `NotResource`, or `NotPrincipal` elements.
- Does not model how Allow and Deny statements interact across multiple policies.
- Condition analysis is presence-based: the tool checks whether a restricting condition key exists, it does not validate that the condition value is correct.

## Installation

```bash
git clone https://github.com/joandies/AWS-IAM-Audit.git
cd AWS-IAM-Audit
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

The tool itself has zero runtime dependencies, it runs on the Python standard library alone. `requirements.txt` contains only pytest for running the test suite.

## Usage

Analyze a single policy file:

```bash
python -m iam_audit examples/vulnerable/01_wildcard_action.json
```

Analyze multiple files at once:

```bash
python -m iam_audit examples/vulnerable/*.json
```

Glob patterns are expanded by the tool itself, so this works on Windows as well as Linux and macOS.

Exit code is 0 if no findings are detected, 1 if any findings or errors occur. This makes the tool compatible with CI/CD pipelines.

## Example output

Running the tool against a vulnerable policy prints each finding with its severity, location, risk, and remediation. This example file deliberately contains more than one escalation path to show that the check reports each one separately:

```
$ python -m iam_audit examples/vulnerable/04_privilege_escalation.json
Results for: examples/vulnerable/04_privilege_escalation.json
  3 finding(s) found

[HIGH] IAM-002 - Sensitive actions granted on wildcard resource
  Statement : 0
  Description : Statement #0 grants sensitive actions on Resource: '*': ec2:RunInstances.
  Risk        : These actions are not scoped to a specific resource, meaning they apply to every matching resource in the account. This violates least privilege and widens the blast radius of a compromised identity.
  Remediation : Replace Resource: '*' with the specific ARN of the resource the principal needs to access.

[CRITICAL] IAM-004 - Privilege escalation path detected (ESC-001)
  Statement : N/A
  Description : The policy grants actions that form a known escalation path (ESC-001): ec2:RunInstances, iam:PassRole.
  Risk        : Can launch an EC2 instance with an admin role attached, then use that instance to make API calls as the admin role.
  Remediation : Remove either permission if not required. If iam:PassRole is needed, scope it to specific role ARNs and add an iam:PassedToService condition so roles can only be passed to the intended service.

[CRITICAL] IAM-004 - Privilege escalation path detected (ESC-002)
  Statement : N/A
  Description : The policy grants actions that form a known escalation path (ESC-002): iam:CreatePolicyVersion.
  Risk        : Can create a new version of an existing IAM policy with arbitrary permissions, effectively rewriting any policy to grant admin access.
  Remediation : Remove iam:CreatePolicyVersion unless the principal manages policies as its core function. If required, scope the Resource to specific policy ARNs rather than granting it account-wide.
```

A single file can trigger multiple checks at different severities. Here a public resource policy produces one CRITICAL finding:

```
$ python -m iam_audit examples/vulnerable/06_public_resource.json
Results for: examples/vulnerable/06_public_resource.json
  1 finding(s) found

[CRITICAL] IAM-006 - Resource policy grants public access
  Statement : 0
  Description : Statement #0 grants s3:GetObject, s3:PutObject to Principal: '*' with no restricting condition, making this resource publicly accessible.
  Risk        : Any entity on the internet can access this resource without authentication. This is a common root cause of data breaches involving exposed S3 buckets, SNS topics, and SQS queues.
  Remediation : Replace Principal: '*' with a specific AWS account or service ARN. If public access is genuinely required, add aws:SourceVpc or aws:SourceVpce conditions to restrict access to known network origins.
```

Running against the corrected version of the same policy produces no findings and exits with code 0, making the tool suitable for use in a CI/CD pipeline:

```
$ python -m iam_audit examples/fixed/04_privilege_escalation.json
[OK] No issues found in examples/fixed/04_privilege_escalation.json

$ echo "Exit code: $?"
Exit code: 0
```

## Detections

### IAM-001 - Wildcard Action

**Severity:** CRITICAL (`Action: "*"`) / HIGH (`Action: "service:*"`)

IAM actions follow the format `service:operation`, for example `s3:GetObject`. Using a wildcard grants access to every operation in a service or across all services.

`Action: "*"` grants every API call across every AWS service. A principal with this permission can create users, delete databases, exfiltrate secrets, and destroy infrastructure.

`Action: "s3:*"` grants every S3 operation, including deleting buckets, making them public, and reading every object in the account.

**Vulnerable example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

**Fixed example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::my-app-bucket/*"
    }
  ]
}
```

**Remediation:** Replace wildcards with the specific actions the principal needs. Apply the principle of least privilege: grant only what is required, nothing more.

---

### IAM-002 - Wildcard Resource with Sensitive Actions

**Severity:** HIGH

`Resource: "*"` means the action applies to every matching resource in the account. Combined with sensitive actions like `s3:GetObject` or `secretsmanager:GetSecretValue`, this grants access to every S3 bucket, every secret, or every database in the account rather than the specific resource the workload needs.

Note: some actions like `s3:ListAllMyBuckets` legitimately require `Resource: "*"` because they operate at the account level. Some actions, such as `ec2:DescribeInstances`, do not support resource-level permissions at all, so `Resource: "*"` is the only valid form. This check only flags actions that are genuinely dangerous when left unscoped, and deliberately excludes read-only and account-level actions to avoid false positives.

**Vulnerable example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "secretsmanager:GetSecretValue"],
      "Resource": "*"
    }
  ]
}
```

**Fixed example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-app-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:my-app-secret"
    }
  ]
}
```

**Remediation:** Replace `Resource: "*"` with the specific ARN of the resource the principal needs to access.

---

### IAM-003 - Admin-Equivalent Policy

**Severity:** CRITICAL

Two patterns produce effective administrator access:

1. A statement combining `Effect: Allow`, `Action: "*"`, and `Resource: "*"` is functionally identical to AWS's built-in `AdministratorAccess` managed policy.
2. Explicitly attaching `arn:aws:iam::aws:policy/AdministratorAccess` or `arn:aws:iam::aws:policy/PowerUserAccess`.

Both are flagged regardless of whether the intent was accidental or not.

**Vulnerable example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ],
  "ManagedPolicies": [
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]
}
```

Note: `ManagedPolicies` is not part of the standard IAM policy document format. It is a tool-specific extension that lets you declare attached managed policies alongside the inline policy for offline analysis, since real policy attachments live outside the policy document in AWS (retrieved via APIs like `iam:ListAttachedRolePolicies`).

**Remediation:** Replace with a scoped policy containing only the actions and resources the principal requires. If broad access is genuinely needed, document the justification and apply guardrails at the AWS Organizations level using Service Control Policies (SCPs).

---

### IAM-004 - Privilege Escalation Path

**Severity:** CRITICAL

Privilege escalation in IAM means a user can combine permissions they already have to grant themselves more permissions than originally intended, without an administrator explicitly doing so.

The classic example: a user with `iam:PassRole` and `ec2:RunInstances` can launch an EC2 instance with an admin role attached. Once that instance is running, they can use it to make API calls as that admin role. Neither permission alone looks alarming. Together they produce full admin access.

This check detects the following known escalation paths, documented originally by Spencer Gietzen:

| Path | Actions | Risk |
|---|---|---|
| ESC-001 | `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with an admin role attached |
| ESC-002 | `iam:CreatePolicyVersion` | Rewrite any existing policy to grant admin access |
| ESC-003 | `iam:AttachRolePolicy` | Attach AdministratorAccess to any role |
| ESC-004 | `iam:AttachUserPolicy` | Attach AdministratorAccess to any user |
| ESC-005 | `iam:PutUserPolicy` | Inject an inline admin policy into any user |
| ESC-006 | `iam:AddUserToGroup` | Add a user to a group with elevated permissions |

The check looks across all statements in the policy, not just within a single statement. Escalation paths can span multiple statements.

**Vulnerable example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PassRole", "ec2:RunInstances"],
      "Resource": "*"
    }
  ]
}
```

**Fixed example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:DescribeInstances",
      "Resource": "*"
    }
  ]
}
```

**Remediation:** Remove escalation-enabling permissions where they are not required. The safest fix is to eliminate the dangerous combination entirely, as shown above. If `iam:PassRole` is genuinely needed, scope it to a specific role ARN and add a condition such as `iam:PassedToService` to restrict which service the role can be passed to. Note that this tool's condition analysis is presence-based and will still flag a scoped-and-conditioned PassRole as part of an escalation path; see Known limitations.

---

### IAM-005 - Trust Policy with Broad Principal

**Severity:** CRITICAL (no condition) / MEDIUM (with restricting condition)

Trust policies control who can assume an IAM role. When `Principal` is set to `"*"`, any entity in the world can attempt to assume that role, including entities outside your AWS account.

A restricting condition like `aws:PrincipalOrgID` or `aws:SourceAccount` reduces but does not eliminate this risk. A misconfigured condition value can still expose the role to unintended principals.

**Vulnerable example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Fixed example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
```

**Remediation:** Replace `Principal: "*"` with the specific ARN of the trusted entity. If a wildcard is unavoidable, add a condition using `aws:PrincipalOrgID` or `aws:SourceAccount` to restrict access to known accounts.

---

### IAM-006 - Public Resource Policy

**Severity:** CRITICAL

Resource-based policies (S3 bucket policies, SNS topic policies, SQS queue policies) define who can access a resource directly. When `Principal` is `"*"` with no restricting condition, the resource is publicly accessible to anyone on the internet without authentication.

This is one of the most common root causes of cloud data breaches. Misconfigured S3 bucket policies have exposed customer databases, financial records, and credentials in numerous high-profile incidents.

**Vulnerable example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::my-company-data/*"
    }
  ]
}
```

**Fixed example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-company-data/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceVpc": "vpc-0a1b2c3d4e5f"
        }
      }
    }
  ]
}
```

**Remediation:** Replace `Principal: "*"` with a specific ARN. If broad access is required, restrict it with `aws:SourceVpc` or `aws:SourceVpce` to limit access to known network origins.

---

## Architecture

The tool is structured around a simple plugin interface. Every check implements a `BaseCheck` abstract class with a single `run(policy) -> list[Finding]` method. The analyzer collects all findings from all checks and passes them to the reporter. Adding a new check requires only creating a new file in `iam_audit/checks/` and registering it in `cli.py`.

```
iam_audit/
├── __main__.py     # Enables running as python -m iam_audit
├── cli.py          # Entrypoint, argument parsing, check registration
├── loader.py       # JSON loading and structural validation
├── analyzer.py     # Orchestrates checks against a loaded policy
├── findings.py     # Finding dataclass and Severity enum
├── report.py       # Terminal output formatting
└── checks/
    ├── base.py     # Abstract BaseCheck interface
    └── *.py        # One file per detection
```

## Running tests

The suite has 36 tests covering all six checks, including positive detections, severity levels, and negative cases (safe policies that should produce no findings).

```bash
python -m pytest -v
```

## Related tools

This project is intentionally small in scope. For production use, consider:

- [Prowler](https://github.com/prowler-cloud/prowler) - open source CSPM with hundreds of checks across AWS, GCP, and Azure.
- [Cloudsplaining](https://github.com/salesforce/cloudsplaining) - IAM security assessment focused on least privilege violations.
- [Aikido](https://www.aikido.dev) - developer-focused security platform with IAM analysis.
- [Wiz](https://www.wiz.io) - enterprise CSPM with graph-based risk analysis.
- [Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud) - enterprise CSPM and workload protection.

## Related projects

[JWT Security Lab Toolkit](https://github.com/joandies/jwt-lab) - a hands-on lab demonstrating five common JWT authentication vulnerabilities and their defenses, in the same educational style as this project.

## Author

Joan Díes - Security Engineer  
[LinkedIn](https://linkedin.com/in/joan-dies) · [GitHub](https://github.com/joandies)

## License

MIT