"""Device-code grant client for the enterprise OIDC IdP.

Works with an OIDC provider that publishes ``device_authorization_endpoint``
and ``token_endpoint`` in discovery. The user completes login, MFA, and
consent in a browser, but the browser never redirects back to this client.

Configuration through environment variables:
  IDP_BASE    OIDC issuer base URL (required)
  CLIENT_ID   OAuth client with Device Authorization Grant enabled (required)
  CLIENT_SECRET
              Secret for the confidential client; sent via HTTP Basic
              authentication.
  CLIENT_SECRET_REQUIRED
              Set to 1 to prompt securely when CLIENT_SECRET is not set.
  SCOPE       defaults to "openid profile"
  OUT         defaults to /tmp/external_id_token.txt

The complete ID Token is written to OUT with mode 0600 and is never printed.
"""
import base64
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

IDP_BASE = os.environ.get("IDP_BASE", "").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
CLIENT_SECRET_REQUIRED = (
    os.environ.get("CLIENT_SECRET_REQUIRED", "0") == "1"
)
SCOPE = os.environ.get("SCOPE", "openid profile")
OUT = os.environ.get("OUT", "/tmp/external_id_token.txt")


def auth_headers():
    """HTTP Basic auth headers for a confidential client (client_secret_basic)."""
    if not CLIENT_SECRET:
        # The local mock accepts a public client; Enterprise uses a confidential
        # client and therefore requires CLIENT_SECRET.
        return {}
    raw = (CLIENT_ID + ":" + CLIENT_SECRET).encode("utf-8")
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


def http_get_json(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode())


def http_post_form(url, fields, headers=None):
    data = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(url, data=data, headers=headers or {},
                                     method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, {"__raw": raw}


def main():
    global CLIENT_SECRET
    if not IDP_BASE or not CLIENT_ID:
        sys.exit("IDP_BASE and CLIENT_ID are required")

    if CLIENT_SECRET_REQUIRED and not CLIENT_SECRET:
        CLIENT_SECRET = getpass.getpass("OIDC Client Secret: ")
        if not CLIENT_SECRET:
            sys.exit("CLIENT_SECRET is required for this OIDC client")

    # Resolve endpoints from OIDC discovery instead of hard-coding paths. This
    # keeps the client compatible with standards-compliant OIDC providers.
    discovery = http_get_json(
        IDP_BASE + "/.well-known/openid-configuration"
    )
    device_endpoint = discovery.get("device_authorization_endpoint")
    token_endpoint = discovery.get("token_endpoint")
    if not device_endpoint or not token_endpoint:
        sys.exit("discovery lacks device/token endpoints")

    # Start RFC 8628 Device Authorization Grant. The response contains a
    # short-lived device_code for polling and a user_code for browser consent.
    code, dauth = http_post_form(device_endpoint, {
        "client_id": CLIENT_ID,
        "scope": SCOPE,
    }, headers=auth_headers())
    if code != 200:
        sys.exit("device authorization failed: %s" % dauth)

    user_code = dauth["user_code"]
    verification_uri = dauth["verification_uri"]
    complete = dauth.get("verification_uri_complete")
    interval = int(dauth.get("interval", 30))
    expires_in = int(dauth.get("expires_in", 600))

    print("请在另一台设备上完成企业登录：")
    if complete:
        print("  打开: %s" % complete)
        print("  确认用户码: %s" % user_code)
    else:
        print("  打开: %s" % verification_uri)
        print("  输入码: %s" % user_code)

    # Poll only at the server-provided interval and stop when the device code
    # expires. Polling faster can trigger "slow_down".
    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        code, tok = http_post_form(token_endpoint, {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_ID,
            "device_code": dauth["device_code"],
        }, headers=auth_headers())
        # Only the OAuth token endpoint's id_token is valid as the subject token
        # for Volcengine. A browser-page user_token is a different credential.
        if code == 200 and "id_token" in tok:
            id_token = tok["id_token"]
            print("\n已取得企业 ID Token。")
            if OUT:
                # OUT should point to a temporary, access-controlled location.
                fd = os.open(
                    OUT,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600,
                )
                with os.fdopen(fd, "w") as fh:
                    fh.write(id_token)
                print("已写入: %s" % OUT)
            return

        err = tok.get("error") or tok.get("__type") or tok
        if err == "authorization_pending":
            print("  等待授权中...")
            continue
        if err == "slow_down":
            # RFC 8628 requires increasing the interval after this response.
            interval += 5
            continue
        sys.exit("device flow failed: %s %s" % (err, tok.get("message", "")))

    sys.exit("device code expired before authorization")


if __name__ == "__main__":
    main()
