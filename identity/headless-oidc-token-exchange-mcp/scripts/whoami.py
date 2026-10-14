#!/usr/bin/env python3
"""Print the identity represented by the configured Volcengine credentials."""
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
import volc_auth

ACTION = "GetCallerIdentity"
VERSION = "2018-01-01"


def main():
    credentials = volc_auth.resolve_credentials()
    body = b""
    headers = volc_auth.build_headers(
        credentials["AccessKeyId"],
        credentials["SecretAccessKey"],
        credentials.get("SessionToken", ""),
        body,
        "sts",
        ACTION,
        VERSION,
    )
    url = "https://%s/?Action=%s&Version=%s" % (
        volc_auth.OPENAPI_HOST,
        ACTION,
        VERSION,
    )
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            print(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
