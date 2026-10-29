#!/usr/bin/env python3
"""
n2s_scan.py - RedSide Security Node2Shell scanner (CVE-2026-111497).

Detects web servers exposed to the Brotli decoder out-of-bounds write
("Node2Shell" / "HTTP2Shell" / "Broccoli2Shell", CVE-2026-111497) that ships
inside Node.js, Bun, Envoy, .NET and Python's Brotli bindings.

DETECTION ONLY. This tool never sends the malformed stream that triggers the
bug. It does two safe things:

  1. Fingerprints the platform and, when the version is visible (response
     headers or a health/version endpoint), decides patched vs. vulnerable.
  2. With --probe, sends two tiny, VALID requests - one with a correct Brotli
     body ("{}" => 6 bytes) and one with a made-up Content-Encoding - to learn
     whether the server decompresses Brotli request bodies at all. That is the
     reachable attack surface; it is not an exploit.

No code is ever executed on the target. Scan only systems you are authorized
to test.

Usage:
    python3 n2s_scan.py -u https://api.example.com/v1/orders --probe
    python3 n2s_scan.py -l targets.txt -o results.csv
    python3 n2s_scan.py -u https://example.com --json

Python 3.8+, standard library only.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

__version__ = "1.0.0"
UA = f"RedSide-Node2Shell-Scanner/{__version__} (+authorized testing)"

# ---------------------------------------------------------------------------
# Vulnerability data (CVE-2026-111497) - first fixed release per branch.
# ---------------------------------------------------------------------------
FIXED = {
    "Node.js": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"},
    "Bun": {"1": "1.4.4"},
    "Envoy": {"1.37": "1.37.8", "1.38": "1.38.6", "1.39": "1.39.3", "1.40": "1.40.0"},
}
# Node.js lines with no fix at all (end of life): anything not 22/24/26.
NODE_EOL_VULNERABLE = True

FIXED_TABLE = [
    ("Node.js", "22.23.4, 24.22.1, 26.12.1  (older lines are EOL - no fix)"),
    ("Bun", "1.4.4"),
    ("Envoy / Istio", "1.37.8, 1.38.6, 1.39.3, 1.40.0"),
    ("Python Brotli / brotlicffi", "1.2.1 / 1.2.1.0"),
    (".NET", "Microsoft out-of-band update (Oct 2026) - see advisory"),
    ("Brotli library (libbrotlidec)", "1.0.10, 1.1.1, 1.2.1"),
]

# A complete, valid Brotli stream encoding the 2 bytes "{}". Harmless.
BROTLI_JSON = b"\x8b\x00\x80{}\x03"
UNKNOWN_ENCODING = "x-redside-n2s-probe"

# Platform / framework fingerprints: (name, where, regex[, version group]).
# A capture group, where present, is the product version.
FINGERPRINTS = [
    ("Node.js", "header", r"^x-powered-by:[^\n]*\bnode(?:\.?js)?(?:/v?(\d+\.\d+\.\d+))?\b"),
    ("Node.js", "header", r"^server:[^\n]*\bnode(?:\.?js)?/v?(\d+\.\d+\.\d+)\b"),
    ("Express", "header", r"^x-powered-by:\s*express\b"),
    ("Express", "cookie", r"\bconnect\.sid="),
    ("Next.js", "header", r"^x-powered-by:\s*next\.js"),
    ("Next.js", "header", r"^x-nextjs-(?:cache|prerender|matched-path|stale-time):"),
    ("Nuxt", "header", r"^x-powered-by:\s*nuxt\b"),
    ("Koa", "header", r"^x-powered-by:\s*koa\b"),
    ("SvelteKit", "header", r"^x-sveltekit-page:"),
    ("Bun", "header", r"^server:\s*bun\b"),
    ("Bun", "header", r"^x-powered-by:[^\n]*\b(?:bun|elysia|hono)\b"),
    ("ASP.NET Core", "header", r"^server:\s*kestrel\b"),
    ("ASP.NET Core", "cookie", r"\.aspnetcore\."),
    (".NET", "header", r"^x-aspnet-version:\s*(\d[\d.]*)"),
    ("Envoy", "header", r"^server:\s*envoy\b"),
    ("Envoy", "header", r"^x-envoy-[a-z-]+:"),
    ("Istio", "header", r"^server:\s*istio-envoy\b"),
    ("Python", "header", r"^server:[^\n]*\bpython/(\d+\.\d+(?:\.\d+)?)"),
    ("aiohttp", "header", r"^server:[^\n]*\baiohttp/"),
    ("Gunicorn", "header", r"^server:\s*gunicorn\b"),
    ("Uvicorn", "header", r"^server:\s*uvicorn\b"),
]

# Framework -> the runtime whose Brotli decoder is what actually matters.
PLATFORM_OF = {
    "Node.js": "Node.js", "Express": "Node.js", "Next.js": "Node.js",
    "Nuxt": "Node.js", "Koa": "Node.js", "SvelteKit": "Node.js",
    "Bun": "Bun",
    "ASP.NET Core": ".NET", ".NET": ".NET",
    "Envoy": "Envoy", "Istio": "Envoy",
    "Python": "Python", "aiohttp": "Python", "Gunicorn": "Python", "Uvicorn": "Python",
}
# Which runtimes carry the vulnerable decoder (for the "version hidden" tier).
AFFECTED_PLATFORMS = {"Node.js", "Bun", ".NET", "Envoy", "Python"}

# Health / version-disclosure endpoints to try when the version is not in headers.
VERSION_PATHS = ["/health", "/healthz", "/api/health", "/version", "/status", "/livez", "/readyz"]
# A Node version hiding in a JSON blob, e.g. {"node":"24.22.0"} or "v24.22.0".
NODE_VER_RE = re.compile(r'(?:"node"\s*:\s*"|node[^\d]{0,4}v?)(\d+\.\d+\.\d+)', re.I)


def version_tuple(v):
    return [int(x) for x in re.findall(r"\d+", v)]


def is_prerelease(v):
    return bool(re.search(r"[-+]|\b(?:rc|alpha|beta|nightly|dev|pre)\b", v, re.I))


def platform_status(platform, version):
    """'patched', 'vulnerable' or '' (unknown) for a visible version."""
    if not version or platform not in FIXED:
        return ""
    v = version_tuple(version)
    pre = is_prerelease(version)
    for branch, fixed in FIXED[platform].items():
        bt = version_tuple(branch)
        if v[:len(bt)] == bt:
            if v >= version_tuple(fixed):
                # a pre-release of the fix release can't be trusted as patched
                return "vulnerable" if pre else "patched"
            return "vulnerable"
    if platform == "Node.js" and NODE_EOL_VULNERABLE:
        return "vulnerable"      # 20, 21, 23, 25, ... : EOL, no fix
    if platform == "Envoy" and v[:2] < version_tuple("1.37"):
        return "vulnerable"
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects - used by the hosted backend to block
    redirect-based SSRF (e.g. a public site 302-ing to an internal address)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(timeout, verify_tls, follow_redirects=True):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    https = urllib.request.HTTPSHandler(context=ctx)
    handlers = [https]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = []
    return opener


def http(opener, url, timeout, method="GET", body=None, headers=None):
    """Return (status, header_lines_lower, cookies, body_text). Never raises on HTTP errors."""
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception as e:  # noqa: BLE001  - network/TLS/timeout etc.
        return None, "", "", "", str(e)
    try:
        raw = resp.read(65536)
    except Exception:
        raw = b""
    hdr_lines, cookies = [], []
    for k, v in resp.headers.items():
        line = f"{k.lower()}: {v}"
        hdr_lines.append(line)
        if k.lower() == "set-cookie":
            cookies.append(v)
    status = getattr(resp, "status", None) or getattr(resp, "code", None)
    try:
        resp.close()
    except Exception:
        pass
    return status, "\n".join(hdr_lines), "\n".join(cookies), raw.decode("utf-8", "replace"), ""


def fingerprint(hdr, cookies, body):
    """Return ({platform: version_or_''}, [evidence])."""
    found, evidence = {}, []
    hay = {"header": hdr, "cookie": cookies, "body": body}
    for entry in FINGERPRINTS:
        name, where, rx = entry[0], entry[1], entry[2]
        m = re.search(rx, hay[where], re.I | re.M)
        if not m:
            continue
        plat = PLATFORM_OF.get(name, name)
        ver = (m.group(1) if m.groups() else "") or ""
        if plat not in found or (ver and not found[plat]):
            found[plat] = ver
        evidence.append(f"{name} via {where}" + (f" ({ver})" if ver else ""))
    return found, evidence


def probe_brotli(opener, url, timeout):
    """Send valid-Brotli vs unknown-encoding POSTs. Return (result, detail)."""
    def post(encoding, data):
        s, *_ = http(opener, url, timeout, method="POST", body=data, headers={
            "Content-Type": "application/json",
            "Content-Encoding": encoding,
            "Content-Length": str(len(data)),
        })
        return s

    br = post("br", BROTLI_JSON)
    unknown = post(UNKNOWN_ENCODING, b"{}")
    if br is None or unknown is None:
        return "error", f"br={br} unknown={unknown}"
    if unknown == 415 and br != 415 and br < 500:
        return "decodes", f"br={br} unknown={unknown}"
    if br == 415 and unknown == 415:
        return "rejects", f"br={br} unknown={unknown}"
    if br == unknown:
        return "ignored", f"br={br} unknown={unknown}"
    return "differs", f"br={br} unknown={unknown}"


def find_version(opener, base, timeout, found):
    """Probe health/version endpoints for a Node version when headers hide it."""
    if found.get("Node.js"):
        return None
    if "Node.js" not in found and not (found.keys() & AFFECTED_PLATFORMS):
        return None
    root = base.split("//", 1)
    origin = (root[0] + "//" + root[1].split("/", 1)[0]) if len(root) == 2 else base
    for path in VERSION_PATHS:
        s, hdr, _c, body, _e = http(opener, origin + path, timeout)
        if s == 200 and body:
            m = NODE_VER_RE.search(body)
            if m:
                return path, m.group(1)
    return None


def scan(opener, target, timeout, do_probe):
    url = target if "://" in target else "http://" + target
    status, hdr, cookies, body, err = http(opener, url, timeout)
    info = {"target": target, "url": url, "status": status, "error": err,
            "platforms": {}, "evidence": [], "probe": None, "version_source": "headers"}
    if status is None:
        info["verdict"] = "ERROR"
        info["evidence"].append(err)
        return info

    found, evidence = fingerprint(hdr, cookies, body)
    info["evidence"] = evidence

    hv = find_version(opener, url, timeout, found)
    if hv:
        path, ver = hv
        found["Node.js"] = ver
        info["version_source"] = path
        info["evidence"].append(f"Node.js {ver} via {path}")

    if do_probe:
        result, detail = probe_brotli(opener, url, timeout)
        info["probe"] = {"result": result, "detail": detail}
        info["evidence"].append(f"probe:{result} ({detail})")

    info["platforms"] = {p: {"version": v, "state": platform_status(p, v)} for p, v in found.items()}

    states = [d["state"] for d in info["platforms"].values()]
    probe_result = (info["probe"] or {}).get("result")
    # An affected platform whose version we could NOT read is an unknown, not a
    # pass: it must never let the verdict collapse to PATCHED (e.g. patched Node
    # behind a version-hidden Envoy sidecar).
    affected = [(p, d["state"]) for p, d in info["platforms"].items() if p in AFFECTED_PLATFORMS]
    if any(s == "vulnerable" for s in states):
        info["verdict"] = "VULNERABLE"
    elif affected and all(s == "patched" for _, s in affected):
        info["verdict"] = "PATCHED"
    else:
        info["verdict"] = _soft(found, probe_result)
    return info


def _soft(found, probe_result):
    affected = found.keys() & AFFECTED_PLATFORMS
    if probe_result == "decodes":
        return "LIKELY VULNERABLE"
    if affected:
        return "POTENTIALLY VULNERABLE"
    return "NOT DETECTED"


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
COLOR = {"VULNERABLE": "31", "LIKELY VULNERABLE": "31", "POTENTIALLY VULNERABLE": "33",
         "PATCHED": "32", "NOT DETECTED": "90", "ERROR": "90"}


def fmt_platforms(info):
    out = []
    for p, d in info["platforms"].items():
        v = d["version"]
        tag = {"vulnerable": "VULN", "patched": "fixed", "": "?"}[d["state"]]
        out.append(f"{p}{(' ' + v) if v else ''} [{tag}]")
    return ", ".join(out) or "-"


def print_human(info, color):
    v = info["verdict"]
    label = f"\033[1;{COLOR.get(v,'37')}m{v}\033[0m" if color else v
    print(f"[{label}] {info['target']}")
    print(f"    platforms : {fmt_platforms(info)}")
    if info.get("probe"):
        print(f"    brotli    : {info['probe']['result']} ({info['probe']['detail']})")
    if info["evidence"]:
        print(f"    evidence  : {'; '.join(info['evidence'])}")
    print()


def to_row(info):
    plats = ", ".join(f"{p} {d['version']}".strip() + f"[{d['state'] or '?'}]"
                      for p, d in info["platforms"].items())
    return [info["target"], info.get("url", ""), info.get("status", ""), info["verdict"],
            plats, (info.get("probe") or {}).get("result", ""), "; ".join(info["evidence"])]


def main():
    ap = argparse.ArgumentParser(
        description="RedSide Node2Shell scanner (CVE-2026-111497) - detection only.",
        epilog="Scan only systems you are authorized to test.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="single target URL or host")
    g.add_argument("-l", "--list", help="file with one target per line")
    ap.add_argument("-p", "--probe", action="store_true",
                    help="also send two tiny VALID requests to check if the server decodes "
                         "Brotli request bodies (best against a JSON/API route)")
    ap.add_argument("-o", "--out", help="write results to CSV")
    ap.add_argument("--json", action="store_true", help="emit JSON lines instead of text")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds (default 10)")
    ap.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.url:
        targets = [args.url]
    else:
        with open(args.list, encoding="utf-8") as fh:
            targets = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    opener = make_opener(args.timeout, verify_tls=not args.insecure)
    color = sys.stdout.isatty() and not args.no_color

    if not args.json and not args.out:
        print(f"RedSide Node2Shell scanner v{__version__}  -  CVE-2026-111497 (detection only)\n")

    results = []
    worst = 0
    rank = {"VULNERABLE": 3, "LIKELY VULNERABLE": 3, "POTENTIALLY VULNERABLE": 2,
            "PATCHED": 0, "NOT DETECTED": 0, "ERROR": 0}
    for t in targets:
        info = scan(opener, t, args.timeout, args.probe)
        results.append(info)
        worst = max(worst, rank.get(info["verdict"], 0))
        if args.json:
            print(json.dumps(info))
        elif not args.out:
            print_human(info, color)

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["target", "url", "http_status", "verdict", "platforms", "probe", "evidence"])
            for info in results:
                w.writerow(to_row(info))
        print(f"[+] wrote {len(results)} rows to {args.out}", file=sys.stderr)

    if not args.json and not args.out:
        print("Fixed versions:")
        for sw, ver in FIXED_TABLE:
            print(f"  {sw:<32} {ver}")

    # exit 2 if anything vulnerable/likely, 0 otherwise - handy for CI.
    sys.exit(2 if worst >= 3 else 0)


if __name__ == "__main__":
    main()
