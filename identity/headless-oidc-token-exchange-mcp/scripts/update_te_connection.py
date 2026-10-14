#!/usr/bin/env python3
"""Update and verify a UserPool Token Exchange connection.

Authentication is resolved by volc_auth.py and supports direct AK/SK,
existing STS credentials, or optional AssumeRole.

Optional resource overrides:
  VOLC_USER_POOL_UID
  VOLC_TE_CONNECTION_UID
  VOLC_TE_CONNECTION_NAME
  EXTERNAL_OIDC_ISSUER
  EXTERNAL_ALLOWED_AUDIENCE
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import volc_auth

ACTION = "UpdateIdentityProviderTokenExchange"
VERSION = "2025-10-30"


def build_body():
    return {
        "UserPoolUid": os.environ.get(
            "VOLC_USER_POOL_UID",
            "",
        ),
        "ConnectionUid": os.environ.get(
            "VOLC_TE_CONNECTION_UID",
            "",
        ),
        "Name": os.environ.get(
            "VOLC_TE_CONNECTION_NAME",
            "external-oidc-token-exchange",
        ),
        "Enabled": True,
        "ProviderType": "OIDC",
        "ExternalIdentityProviderConfiguration": {
            "OIDCIssuerUrl": os.environ.get(
                "EXTERNAL_OIDC_ISSUER",
                "",
            )
        },
        "AllowedAudiences": [
            os.environ.get(
                "EXTERNAL_ALLOWED_AUDIENCE",
                "",
            )
        ],
        "ProviderOptions": {
            "IsLinkingAllowed": True,
            "IsCreationAllowed": True,
            "IsAutoCreation": True,
            "IsAutoUpdate": True,
            "AutoLinking": "AUTO_LINKING_OPTION_EMAIL",
            "UserLinkingPromptEnabled": False,
        },
        "ClaimsPropagationConfig": {
            "Mode": "FULL",
        },
    }


def main():
    body = build_body()
    required = {
        "VOLC_USER_POOL_UID": body["UserPoolUid"],
        "VOLC_TE_CONNECTION_UID": body["ConnectionUid"],
        "EXTERNAL_OIDC_ISSUER": body[
            "ExternalIdentityProviderConfiguration"
        ]["OIDCIssuerUrl"],
        "EXTERNAL_ALLOWED_AUDIENCE": body["AllowedAudiences"][0],
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        sys.exit(
            "Missing required environment variables: %s"
            % ", ".join(missing)
        )

    credentials = volc_auth.resolve_credentials()

    status, updated = volc_auth.signed_call(
        "id",
        ACTION,
        VERSION,
        body,
        credentials,
    )
    print("%s: HTTP %d" % (ACTION, status))
    print(json.dumps(updated, ensure_ascii=False, indent=2))
    if volc_auth.has_api_error(status, updated):
        return 1

    status, current = volc_auth.signed_call(
        "id",
        "GetIdentityProviderTokenExchange",
        VERSION,
        {
            "UserPoolUid": body["UserPoolUid"],
            "ConnectionUid": body["ConnectionUid"],
        },
        credentials,
    )
    print("GetIdentityProviderTokenExchange: HTTP %d" % status)
    print(json.dumps(current, ensure_ascii=False, indent=2))
    if volc_auth.has_api_error(status, current):
        return 1

    expected_issuer = body[
        "ExternalIdentityProviderConfiguration"
    ]["OIDCIssuerUrl"]
    actual_issuer = current.get("Result", {}).get(
        "ExternalIdentityProviderConfiguration",
        {},
    ).get("OIDCIssuerUrl")
    expected_audience = body["AllowedAudiences"][0]
    actual_audiences = current.get("Result", {}).get(
        "AllowedAudiences",
        [],
    )

    print("Expected issuer: %r" % expected_issuer)
    print("Actual issuer:   %r" % actual_issuer)
    print("Expected audience: %s" % expected_audience)
    print(
        "Actual audiences:  %s"
        % json.dumps(actual_audiences, ensure_ascii=False)
    )
    if (
        actual_issuer == expected_issuer
        and expected_audience in actual_audiences
    ):
        print("Token Exchange connection update succeeded.")
        return 0

    print("Token Exchange connection verification failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
