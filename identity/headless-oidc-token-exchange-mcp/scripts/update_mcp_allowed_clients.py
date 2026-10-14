#!/usr/bin/env python3
"""Add client IDs to an AgentKit MCP service AllowedClients list.

Authentication is resolved by volc_auth.py and supports direct AK/SK,
existing STS credentials, or optional AssumeRole.

Optional resource overrides:
  VOLC_MCP_SERVICE_ID
  VOLC_ALLOWED_CLIENTS   comma-separated client IDs
"""
import copy
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import volc_auth

VERSION = "2025-10-30"
MCP_SERVICE_ID = os.environ.get(
    "VOLC_MCP_SERVICE_ID",
    "",
)
REQUIRED_CLIENTS = [
    value.strip()
    for value in os.environ.get(
        "VOLC_ALLOWED_CLIENTS",
        "",
    ).split(",")
    if value.strip()
]


def merge_allowed_clients(value):
    current = value if isinstance(value, list) else []
    return list(dict.fromkeys(current + REQUIRED_CLIENTS))


def update_allowed_clients(node):
    """Update every AllowedClients field and return the number changed."""
    changed = 0
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "AllowedClients":
                node[key] = merge_allowed_clients(value)
                changed += 1
            else:
                changed += update_allowed_clients(value)
    elif isinstance(node, list):
        for item in node:
            changed += update_allowed_clients(item)
    return changed


def collect_allowed_clients(node):
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "AllowedClients":
                found.append(value)
            else:
                found.extend(collect_allowed_clients(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(collect_allowed_clients(item))
    return found


def main():
    missing = []
    if not MCP_SERVICE_ID:
        missing.append("VOLC_MCP_SERVICE_ID")
    if not REQUIRED_CLIENTS:
        missing.append("VOLC_ALLOWED_CLIENTS")
    if missing:
        sys.exit(
            "Missing required environment variables: %s"
            % ", ".join(missing)
        )

    credentials = volc_auth.resolve_credentials()

    status, current = volc_auth.signed_call(
        "agentkit",
        "GetMCPService",
        VERSION,
        {"MCPServiceId": MCP_SERVICE_ID},
        credentials,
    )
    print("GetMCPService: HTTP %d" % status)
    if volc_auth.has_api_error(status, current):
        print(json.dumps(current, ensure_ascii=False, indent=2))
        return 1

    service = current.get("Result", {}).get("MCPService", {})
    inbound = service.get("InboundAuthorizerConfiguration")
    if not isinstance(inbound, dict):
        print("MCP service has no inbound authorizer configuration")
        return 1

    updated_inbound = copy.deepcopy(inbound)
    changed = update_allowed_clients(updated_inbound)
    if changed == 0:
        print("No AllowedClients field found in the inbound authorizer.")
        print(json.dumps(inbound, ensure_ascii=False, indent=2))
        return 1

    print(
        "AllowedClients before: %s"
        % json.dumps(collect_allowed_clients(inbound), ensure_ascii=False)
    )
    print(
        "AllowedClients after:  %s"
        % json.dumps(
            collect_allowed_clients(updated_inbound),
            ensure_ascii=False,
        )
    )

    status, updated = volc_auth.signed_call(
        "agentkit",
        "UpdateMCPService",
        VERSION,
        {
            "MCPServiceId": MCP_SERVICE_ID,
            "InboundAuthorizerConfiguration": updated_inbound,
        },
        credentials,
    )
    print("UpdateMCPService: HTTP %d" % status)
    print(json.dumps(updated, ensure_ascii=False, indent=2))
    if volc_auth.has_api_error(status, updated):
        return 1

    for attempt in range(1, 6):
        if attempt > 1:
            time.sleep(2)
        status, verified = volc_auth.signed_call(
            "agentkit",
            "GetMCPService",
            VERSION,
            {"MCPServiceId": MCP_SERVICE_ID},
            credentials,
        )
        print(
            "GetMCPService verification %d/5: HTTP %d"
            % (attempt, status)
        )
        if volc_auth.has_api_error(status, verified):
            print(json.dumps(verified, ensure_ascii=False, indent=2))
            return 1

        verified_inbound = (
            verified.get("Result", {})
            .get("MCPService", {})
            .get("InboundAuthorizerConfiguration", {})
        )
        allowed_sets = collect_allowed_clients(verified_inbound)
        print(
            "Verified AllowedClients: %s"
            % json.dumps(allowed_sets, ensure_ascii=False)
        )
        if allowed_sets and all(
            client in allowed_sets[0] for client in REQUIRED_CLIENTS
        ):
            print("MCP AllowedClients update succeeded.")
            return 0

    print(
        "Control-plane verification is still stale after 5 attempts. "
        "Check the data-plane audience result before retrying the update."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
