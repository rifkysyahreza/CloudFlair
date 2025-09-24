import sys
import requests

BASE_URL = "https://search.censys.io/api/v2"
USER_AGENT = "CloudFlair (+https://github.com/christophetd/CloudFlair)"

INVALID_CREDS = "[-] Your Censys credentials look invalid.\n"
RATE_LIMIT = "[-] Looks like you exceeded your Censys account limits rate. Exiting\n"


def _post(endpoint: str, api_key: str, json: dict) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
    }
    resp = requests.post(f"{BASE_URL}{endpoint}", headers=headers, json=json)
    return resp


def get_certificates(domain, api_key, pages=2) -> set:
    certificate_query = (
        f"names: {domain} and parsed.signature.valid: true and not names: cloudflaressl.com"
    )
    fingerprints = set()
    cursor = None
    for _ in range(pages):
        payload = {"q": certificate_query, "per_page": 100}
        if cursor:
            payload["cursor"] = cursor

        resp = _post("/certificates/search", api_key, payload)

        if resp.status_code == 401:
            sys.stderr.write(INVALID_CREDS)
            exit(1)
        if resp.status_code == 429:
            sys.stderr.write(RATE_LIMIT)
            exit(1)
        if not resp.ok:
            sys.stderr.write(f"[-] Censys API error: {resp.status_code}\n")
            exit(1)

        data = resp.json()
        hits = data.get("result", {}).get("hits", [])
        for cert in hits:
            # Accept common keys across versions
            fp = cert.get("fingerprint_sha256") or cert.get("fingerprint")
            if fp:
                fingerprints.add(fp)

        cursor = data.get("result", {}).get("links", {}).get("next")
        if not cursor:
            break

    return fingerprints


def get_hosts(cert_fingerprints, api_key):
    # Match any host presenting any of the given certificate fingerprints
    # Field name may vary; try both fingerprint and fingerprint_sha256
    query = (
        f"services.tls.certificates.leaf_data.fingerprint: {{{','.join(cert_fingerprints)}}}"
    )
    payload = {"q": query, "per_page": 100}
    resp = _post("/hosts/search", api_key, payload)

    if resp.status_code == 401:
        sys.stderr.write(INVALID_CREDS)
        exit(1)
    if resp.status_code == 429:
        sys.stderr.write(RATE_LIMIT)
        exit(1)
    if not resp.ok:
        sys.stderr.write(f"[-] Censys API error: {resp.status_code}\n")
        exit(1)

    data = resp.json()
    hits = data.get("result", {}).get("hits", [])
    return set([r.get("ip") for r in hits if r.get("ip")])
