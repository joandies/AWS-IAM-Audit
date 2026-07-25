from iam_audit.checks.base import BaseCheck
from iam_audit.findings import Finding, Severity

ESCALATION_PATHS = [
    {
        "id": "ESC-001",
        "actions": {"iam:PassRole", "ec2:RunInstances"},
        "description": "Can launch an EC2 instance with an admin role attached, then use that instance to make API calls as the admin role.",
    },
    {
        "id": "ESC-002",
        "actions": {"iam:CreatePolicyVersion"},
        "description": "Can create a new version of an existing IAM policy with arbitrary permissions, effectively rewriting any policy to grant admin access.",
    },
    {
        "id": "ESC-003",
        "actions": {"iam:AttachRolePolicy"},
        "description": "Can attach any managed policy (including AdministratorAccess) to any role, escalating the privileges of that role.",
    },
    {
        "id": "ESC-004",
        "actions": {"iam:AttachUserPolicy"},
        "description": "Can attach any managed policy (including AdministratorAccess) to any user, including themselves.",
    },
    {
        "id": "ESC-005",
        "actions": {"iam:PutUserPolicy"},
        "description": "Can inject an inline policy with arbitrary permissions into any IAM user, including themselves.",
    },
    {
        "id": "ESC-006",
        "actions": {"iam:AddUserToGroup"},
        "description": "Can add any user to any IAM group, potentially inheriting that group's elevated permissions.",
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
                    remediation="Remove the escalation-enabling permissions if they are not required. If iam:PassRole is needed, restrict it with a condition limiting which roles can be passed.",
                ))

        return findings