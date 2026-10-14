#!/usr/bin/env python3
"""Create a UserPool external OIDC Token Exchange connection.

Required configuration:
  VOLC_USER_POOL_UID
  EXTERNAL_OIDC_ISSUER
  VOLC_TE_CONNECTION_NAME   optional

Authentication is resolved by volc_auth.py and supports direct AK/SK,
existing STS credentials, or optional AssumeRole.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import volc_auth

VERSION = "2025-10-30"
ACTION = "CreateIdentityProviderTokenExchange"


def main():
    user_pool_uid = os.environ.get("VOLC_USER_POOL_UID", "").strip()
    issuer = os.environ.get("EXTERNAL_OIDC_ISSUER", "").strip()
    if not user_pool_uid or not issuer:
        sys.exit(
            "VOLC_USER_POOL_UID and EXTERNAL_OIDC_ISSUER are required"
        )

    credentials = volc_auth.resolve_credentials()
    body = {
        "UserPoolUid": user_pool_uid,
        "Name": os.environ.get(
            "VOLC_TE_CONNECTION_NAME",
            "external-oidc-token-exchange",
        ),
        "Enabled": True,
        "ProviderType": "OIDC",
        "ExternalIdentityProviderConfiguration": {
            "OIDCIssuerUrl": issuer,
        },
    }
    status, response = volc_auth.signed_call(
        "id",
        ACTION,
        VERSION,
        body,
        credentials,
    )
    print("%s: HTTP %d" % (ACTION, status))
    print(json.dumps(response, ensure_ascii=False, indent=2))
    if volc_auth.has_api_error(status, response):
        return 1

    result = response.get("Result", {})
    connection_uid = result.get("ConnectionUid") or result.get("Uid")
    if connection_uid:
        print("ConnectionUid: %s" % connection_uid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
