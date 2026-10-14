#!/usr/bin/env python3
"""Exchange an external OIDC ID Token for a Volcengine UserPool token.

The upstream token is read from /tmp/external_id_token.txt by default. The
Volcengine client secret is read from VOLC_CLIENT_SECRET or prompted securely.
No complete token or secret is printed.
"""
import base64
import datetime
import getpass
import hashlib
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

USER_POOL_UID = os.environ.get("VOLC_USER_POOL_UID", "").strip()
VOLC_REGION = os.environ.get("VOLC_REGION", "cn-beijing").strip()
USER_POOL_BASE = os.environ.get("VOLC_USER_POOL_BASE", "").rstrip("/")
if not USER_POOL_BASE and USER_POOL_UID:
    USER_POOL_BASE = (
        "https://userpool-%s.userpool.auth.id.%s.volces.com"
        % (USER_POOL_UID, VOLC_REGION)
    )
EXCHANGE_URL = (
    USER_POOL_BASE + "/api/v1/ExternalIdentityProviderTokenExchange"
    if USER_POOL_BASE
    else ""
)
CONNECTION_UID = os.environ.get(
    "TOKEN_EXCHANGE_CONNECTION_UID",
    "",
).strip()
CLIENT_ID = os.environ.get("VOLC_CLIENT_ID", "").strip()
SUBJECT_TOKEN_FILE = os.environ.get(
    "SUBJECT_TOKEN_FILE",
    "/tmp/external_id_token.txt",
)
OUTPUT_FILE = os.environ.get(
    "VOLC_TOKEN_OUT",
    "/tmp/volc_identity_token.txt",
)
DIAGNOSTIC_LOG = os.environ.get(
    "TOKEN_EXCHANGE_LOG",
    "/tmp/token_exchange_diagnostic.log",
)


def check_client_credentials(client_secret):
    """Verify the M2M credentials independently of Token Exchange."""
    token_url = USER_POOL_BASE + "/oauth/token"

    def attempt(auth_method):
        fields = {"grant_type": "client_credentials"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if auth_method == "client_secret_basic":
            raw = ("%s:%s" % (CLIENT_ID, client_secret)).encode("utf-8")
            headers["Authorization"] = (
                "Basic " + base64.b64encode(raw).decode("ascii")
            )
        else:
            fields["client_id"] = CLIENT_ID
            fields["client_secret"] = client_secret
        request = urllib.request.Request(
            token_url,
            data=urllib.parse.urlencode(fields).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                # Consume the response without printing or persisting its token.
                response.read()
                return True, response.status, {}, auth_method
        except urllib.error.HTTPError as exc:
            raw_response = exc.read().decode("utf-8")
            try:
                result = json.loads(raw_response)
            except json.JSONDecodeError:
                result = {"error": raw_response}
            return False, exc.code, result, auth_method

    first = attempt("client_secret_basic")
    if first[0]:
        return first
    return attempt("client_secret_post")


def decode_jwt_part(value):
    encoded = value + "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded))


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("subject token is not a compact JWT")
    return decode_jwt_part(parts[0]), decode_jwt_part(parts[1])


def write_private(path, value):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with os.fdopen(fd, "w") as handle:
        handle.write(value)


def iso_utc(timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    return datetime.datetime.fromtimestamp(
        timestamp,
        datetime.timezone.utc,
    ).isoformat()


def safe_response_headers(headers):
    """Keep only response metadata useful for server-side log correlation."""
    result = {}
    for key, value in headers.items():
        normalized = key.lower()
        if (
            normalized in {"content-type", "date", "server"}
            or "request" in normalized
            or "trace" in normalized
            or "logid" in normalized
        ):
            result[key] = value
    return result


def redact_sensitive_fields(value):
    """Recursively remove credentials if an error response echoes input."""
    sensitive = {
        "accesstoken",
        "access_token",
        "clientsecret",
        "client_secret",
        "idtoken",
        "id_token",
        "refreshtoken",
        "refresh_token",
        "subjecttoken",
        "subject_token",
        "token",
    }
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if key.lower() in sensitive
                else redact_sensitive_fields(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_fields(item) for item in value]
    return value


def main():
    missing = []
    if not USER_POOL_BASE:
        missing.append("VOLC_USER_POOL_UID or VOLC_USER_POOL_BASE")
    if not CONNECTION_UID:
        missing.append("TOKEN_EXCHANGE_CONNECTION_UID")
    if not CLIENT_ID:
        missing.append("VOLC_CLIENT_ID")
    if missing:
        sys.exit(
            "Missing required environment variables: %s"
            % ", ".join(missing)
        )

    try:
        with open(SUBJECT_TOKEN_FILE, "r", encoding="utf-8") as handle:
            subject_token = handle.read().strip()
    except FileNotFoundError:
        sys.exit(
            "External ID Token not found; run device_client.py first"
        )

    try:
        jwt_header, claims = decode_jwt(subject_token)
    except (ValueError, json.JSONDecodeError) as exc:
        sys.exit("Invalid external ID Token: %s" % exc)

    remaining = int(claims.get("exp", 0)) - int(time.time())
    if remaining <= 0:
        sys.exit(
            "External ID Token has expired; run device_client.py again, "
            "then immediately rerun this script"
        )

    client_secret = os.environ.get("VOLC_CLIENT_SECRET", "")
    if not client_secret:
        if not sys.stdin.isatty():
            sys.exit(
                "A secure interactive terminal is required to enter the "
                "Volcengine Client Secret"
            )
        try:
            client_secret = getpass.getpass(
                "Volcengine Client Secret for %s: " % CLIENT_ID
            )
        except (EOFError, OSError):
            sys.exit(
                "A secure interactive terminal is required to enter the "
                "Volcengine Client Secret"
            )
    if not client_secret:
        sys.exit("Volcengine Client Secret is required")

    if os.environ.get("VOLC_PREFLIGHT_CLIENT_CREDENTIALS") == "1":
        auth_ok, auth_status, auth_result, auth_method = (
            check_client_credentials(client_secret)
        )
        if not auth_ok:
            print(
                "Client authentication preflight failed: HTTP %d"
                % auth_status
            )
            print(json.dumps(auth_result, ensure_ascii=False, indent=2))
            return 1
        print(
            "Client authentication preflight succeeded (%s)." % auth_method
        )

    payload = {
        "TokenExchangeProviderConnectionUid": CONNECTION_UID,
        "GrantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "SubjectToken": subject_token,
        "SubjectTokenType": "urn:ietf:params:oauth:token-type:id_token",
        "ClientId": CLIENT_ID,
        "ClientSecret": client_secret,
        "Scopes": ["openid"],
    }
    client_request_id = str(uuid.uuid4())
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        EXCHANGE_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Client-Request-Id": client_request_id,
        },
        method="POST",
    )

    started_at = time.time()
    response_headers = {}
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
            response_headers = safe_response_headers(response.headers)
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = safe_response_headers(exc.headers)
        raw = exc.read().decode("utf-8")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            result = {"error": raw}
    except urllib.error.URLError as exc:
        status = None
        result = {"network_error": str(exc.reason)}

    finished_at = time.time()
    token_sha256 = hashlib.sha256(
        subject_token.encode("utf-8")
    ).hexdigest()
    subject_value = str(claims.get("sub", ""))
    diagnostic = {
        "started_at_utc": iso_utc(started_at),
        "finished_at_utc": iso_utc(finished_at),
        "elapsed_ms": round((finished_at - started_at) * 1000),
        "client_request_id": client_request_id,
        "request": {
            "method": "POST",
            "url": EXCHANGE_URL,
            "user_pool_uid": USER_POOL_UID,
            "connection_uid": CONNECTION_UID,
            "client_id": CLIENT_ID,
            "grant_type": payload["GrantType"],
            "subject_token_type": payload["SubjectTokenType"],
            "scopes": payload["Scopes"],
        },
        "subject_token": {
            "sha256": token_sha256,
            "length": len(subject_token),
            "header": {
                "alg": jwt_header.get("alg"),
                "kid": jwt_header.get("kid"),
                "typ": jwt_header.get("typ"),
            },
            "claims": {
                "iss": claims.get("iss"),
                "aud": claims.get("aud"),
                "azp": claims.get("azp"),
                "iat": claims.get("iat"),
                "exp": claims.get("exp"),
                "nbf": claims.get("nbf"),
                "remaining_seconds_at_request": (
                    int(claims.get("exp", 0)) - int(started_at)
                ),
                "sub_sha256": (
                    hashlib.sha256(subject_value.encode("utf-8")).hexdigest()
                    if subject_value
                    else None
                ),
                "email_present": bool(claims.get("email")),
                "groups_count": (
                    len(claims["groups"])
                    if isinstance(claims.get("groups"), list)
                    else None
                ),
            },
        },
        "response": {
            "http_status": status,
            "headers": response_headers,
            "body": redact_sensitive_fields(result),
        },
    }
    write_private(
        DIAGNOSTIC_LOG,
        json.dumps(diagnostic, ensure_ascii=False, indent=2) + "\n",
    )
    print("Diagnostic log written to: %s" % DIAGNOSTIC_LOG)
    print("Client request ID: %s" % client_request_id)

    if status is None:
        print("Token Exchange network error: %s" % result["network_error"])
        return 1

    if status != 200:
        print("Token Exchange failed: HTTP %d" % status)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1

    # UserPool wraps successful data in Result, while some compatible
    # implementations return the token fields at the top level.
    token_result = result.get("Result", result)
    access_token = (
        token_result.get("AccessToken")
        or token_result.get("access_token")
        or token_result.get("Token")
    )
    if not access_token:
        print("Token Exchange returned HTTP 200 without an access token")
        print(
            "Response fields: %s"
            % ", ".join(sorted(token_result))
        )
        return 1

    write_private(OUTPUT_FILE, access_token)
    print("Token Exchange succeeded.")
    print("Access Token written to: %s" % OUTPUT_FILE)
    print("File mode: 0600")
    for source, label in (
        ("ExpiresIn", "Expires in"),
        ("TokenType", "Token type"),
        ("Scope", "Scope"),
    ):
        if source in token_result:
            print("%s: %s" % (label, token_result[source]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
