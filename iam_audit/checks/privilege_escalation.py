from iam_audit.checks.base import BaseCheck
from iam_audit.findings import Finding, Severity

ESCALATION_PATHS = [
    {
        "id": "ESC-001",
        "actions": {"iam:PassRole", "ec2:RunInstances"},
        "description": "Can launch an EC2 instance with an admin role attached, then use that instance to make API calls as the admin role.",
        "remediation": "Remove either permission if not required. If iam:PassRole is needed, scope it to specific role ARNs and add an iam:PassedToService condition so roles can only be passed to the intended service.",
    },
    {
        "id": "ESC-002",
        "actions": {"iam:CreatePolicyVersion"},
        "description": "Can create a new version of an existing IAM policy with arbitrary permissions, effectively rewriting any policy to grant admin access.",
        "remediation": "Remove iam:CreatePolicyVersion unless the principal manages policies as its core function. If required, scope the Resource to specific policy ARNs rather than granting it account-wide.",
    },
    {
        "id": "ESC-003",
        "actions": {"iam:AttachRolePolicy"},
        "description": "Can attach any managed policy (including AdministratorAccess) to any role, escalating the privileges of that role.",
        "remediation": "Remove iam:AttachRolePolicy unless the principal manages role permissions. If required, use a permissions boundary to cap what the attached policies can grant, and scope the Resource to specific role ARNs.",
    },
    {
        "id": "ESC-004",
        "actions": {"iam:AttachUserPolicy"},
        "description": "Can attach any managed policy (including AdministratorAccess) to any user, including themselves.",
        "remediation": "Remove iam:AttachUserPolicy unless the principal manages user permissions. If required, apply a permissions boundary and scope the Resource to specific user ARNs to prevent self-escalation.",
    },
    {
        "id": "ESC-005",
        "actions": {"iam:PutUserPolicy"},
        "description": "Can inject an inline policy with arbitrary permissions into any IAM user, including themselves.",
        "remediation": "Remove iam:PutUserPolicy unless the principal manages inline user policies. If required, apply a permissions boundary and scope the Resource to specific user ARNs.",
    },
    {
        "id": "ESC-006",
        "actions": {"iam:AddUserToGroup"},
        "description": "Can add any user to any IAM group, potentially inheriting that group's elevated permissions.",
        "remediation": "Remove iam:AddUserToGroup unless the principal manages group membership. If required, scope the Resource to specific non-privileged group ARNs so users cannot be added to admin groups.",
    },
]


class PrivilegeEscalationCheck(BaseCheck):

    def run(self, policy: dict) -> list[Finding]:
        findings = []
        statements = policy.get("Statement", [])

        granted_actions = set()
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            granted_actions.update(actions)

        if "*" in granted_actions:
            return []

        for path in ESCALATION_PATHS:
            if path["actions"].issubset(granted_actions):
                findings.append(Finding(
                    check_id="IAM-004",
                    severity=Severity.CRITICAL,
                    title=f"Privilege escalation path detected ({path['id']})",
                    file=policy["_file"],
                    statement_index=-1,
                    description=f"The policy grants actions that form a known escalation path ({path['id']}): {', '.join(sorted(path['actions']))}.",
                    risk=path["description"],
                    remediation=path["remediation"],
                ))

        return findings