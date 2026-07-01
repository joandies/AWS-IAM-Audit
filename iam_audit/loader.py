import json


def load_policy(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            policy = json.load(f)
    except FileNotFoundError:
        raise ValueError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}")

    if "Statement" not in policy:
        raise ValueError(f"Missing 'Statement' key in {path}")

    if not isinstance(policy["Statement"], list):
        raise ValueError(f"'Statement' must be a list in {path}")

    policy["_file"] = path
    return policy