#!/usr/bin/env python3
"""Credential resolution and signed Volcengine OpenAPI calls.

Supported authentication modes:

1. Existing STS credentials:
   VOLC_ACCESSKEY, VOLC_SECRETKEY, VOLC_SESSIONTOKEN
2. Direct AK/SK:
   VOLC_ACCESSKEY, VOLC_SECRETKEY
3. Optional AssumeRole:
   Add VOLC_ROLE_TRN to either environment credentials or securely prompted
   base credentials.

When AK/SK are not set, an interactive terminal prompts for them without
echoing. Credentials remain in memory and are never printed or persisted.
"""
import datetime
import getpass
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

REGION = os.environ.get("VOLC_REGION", "cn-beijing")
OPENAPI_HOST = os.environ.get(
    "VOLC_OPENAPI_HOST",
    "open.volcengineapi.com",
)
STS_VERSION = "2018-01-01"
STS_HOST = "sts.%s.volcengineapi.com" % REGION


def hmac_sha256(key, message):
    return hmac.new(
        key,
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def build_headers(
    access_key,
    secret_key,
    session_token,
    body,
    service,
    action,
    version,
):
    """Build Volcengine V4 authorization headers for a JSON POST."""
    now = datetime.datetime.now(datetime.timezone.utc)
    x_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    query = "Action=%s&Version=%s" % (action, version)
    headers_to_sign = {
        "content-type": "application/json",
        "host": OPENAPI_HOST,
        "x-content-sha256": payload_hash,
        "x-date": x_date,
    }
    signed_headers = ";".join(sorted(headers_to_sign))
    canonical_headers = "".join(
        "%s:%s\n" % (name, headers_to_sign[name])
        for name in sorted(headers_to_sign)
    )
    canonical_request = "\n".join([
        "POST",
        "/",
        query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = "%s/%s/%s/request" % (date_stamp, REGION, service)
    string_to_sign = "\n".join([
        "HMAC-SHA256",
        x_date,
        scope,
        hashlib.sha256(
            canonical_request.encode("utf-8")
        ).hexdigest(),
    ])
    date_key = hmac_sha256(secret_key.encode("utf-8"), date_stamp)
    region_key = hmac_sha256(date_key, REGION)
    service_key = hmac_sha256(region_key, service)
    signing_key = hmac_sha256(service_key, "request")
    signature = hmac.new(
        signing_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    headers = dict(headers_to_sign)
    headers["authorization"] = (
        "HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
        % (access_key, scope, signed_headers, signature)
    )
    if session_token:
        headers["x-security-token"] = session_token
    return headers


def assume_role(base_credentials, role_trn):
    """Exchange base credentials for short-lived role credentials."""
    params = {
        "Action": "AssumeRole",
        "Version": STS_VERSION,
        "RoleTrn": role_trn,
        "RoleSessionName": os.environ.get(
            "VOLC_ROLE_SESSION_NAME",
            "headless-sso-admin",
        ),
        "DurationSeconds": os.environ.get(
            "VOLC_ROLE_DURATION_SECONDS",
            "900",
        ),
    }
    query = urllib.parse.urlencode(
        sorted(params.items()),
        quote_via=urllib.parse.quote,
        safe="-_.~",
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    x_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(b"").hexdigest()
    headers_to_sign = {
        "host": STS_HOST,
        "x-content-sha256": payload_hash,
        "x-date": x_date,
    }
    signed_headers = ";".join(sorted(headers_to_sign))
    canonical_headers = "".join(
        "%s:%s\n" % (name, headers_to_sign[name])
        for name in sorted(headers_to_sign)
    )
    canonical_request = "\n".join([
        "GET",
        "/",
        query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = "%s/%s/sts/request" % (date_stamp, REGION)
    string_to_sign = "\n".join([
        "HMAC-SHA256",
        x_date,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    date_key = hmac_sha256(
        base_credentials["SecretAccessKey"].encode("utf-8"),
        date_stamp,
    )
    region_key = hmac_sha256(date_key, REGION)
    service_key = hmac_sha256(region_key, "sts")
    signing_key = hmac_sha256(service_key, "request")
    signature = hmac.new(
        signing_key,
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    headers = dict(headers_to_sign)
    headers["authorization"] = (
        "HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
        % (
            base_credentials["AccessKeyId"],
            scope,
            signed_headers,
            signature,
        )
    )
    if base_credentials.get("SessionToken"):
        headers["x-security-token"] = base_credentials["SessionToken"]

    request = urllib.request.Request(
        "https://%s/?%s" % (STS_HOST, query),
        headers=headers,
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(
                response.read().decode("utf-8")
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            result = {"error": raw}
        return exc.code, result


def resolve_credentials():
    """Resolve direct, STS, or AssumeRole credentials."""
    access_key = os.environ.get("VOLC_ACCESSKEY", "").strip()
    secret_key = os.environ.get("VOLC_SECRETKEY", "").strip()
    session_token = os.environ.get("VOLC_SESSIONTOKEN", "").strip()

    if bool(access_key) != bool(secret_key):
        sys.exit(
            "VOLC_ACCESSKEY and VOLC_SECRETKEY must be provided together"
        )

    if not access_key:
        if not sys.stdin.isatty():
            sys.exit(
                "Set VOLC_ACCESSKEY and VOLC_SECRETKEY, or run from an "
                "interactive terminal"
            )
        access_key = getpass.getpass("Volcengine Access Key ID: ").strip()
        secret_key = getpass.getpass(
            "Volcengine Secret Access Key: "
        ).strip()
        if not access_key or not secret_key:
            sys.exit("Access Key ID and Secret Access Key are required")

    credentials = {
        "AccessKeyId": access_key,
        "SecretAccessKey": secret_key,
        "SessionToken": session_token,
    }
    role_trn = os.environ.get("VOLC_ROLE_TRN", "").strip()
    if not role_trn:
        mode = "STS credentials" if session_token else "direct AK/SK"
        print("Authentication mode: %s" % mode)
        return credentials

    status, response = assume_role(credentials, role_trn)
    if status != 200:
        print("AssumeRole failed: HTTP %d" % status)
        print(json.dumps(response, ensure_ascii=False, indent=2))
        raise SystemExit(1)

    temporary = response.get("Result", {}).get("Credentials")
    if not temporary:
        print("AssumeRole returned no Credentials")
        raise SystemExit(1)

    print("Authentication mode: AssumeRole")
    print("AssumeRole succeeded: %s" % role_trn)
    return temporary


def signed_call(service, action, version, body_dict, credentials):
    """Call a JSON Volcengine OpenAPI action using V4 signing."""
    body = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
    headers = build_headers(
        credentials["AccessKeyId"],
        credentials["SecretAccessKey"],
        credentials.get("SessionToken", ""),
        body,
        service,
        action,
        version,
    )
    url = "https://%s/?Action=%s&Version=%s" % (
        OPENAPI_HOST,
        action,
        version,
    )
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(
                response.read().decode("utf-8")
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            result = {"error": raw}
        return exc.code, result


def has_api_error(status, response):
    return (
        status != 200
        or bool(response.get("ResponseMetadata", {}).get("Error"))
    )
