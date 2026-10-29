# n2s_scan.py — Node2Shell scanner (CVE-2026-111497)

A single-file, dependency-free (`Python 3.8+`, standard library only), **detection-only** scanner.
It never sends the malformed stream that triggers the bug.

## How it decides

1. **Fingerprint** the platform from response headers, cookies and body (Node.js, Bun, .NET/Kestrel,
   Envoy/Istio, Python servers, and frameworks that imply them — Express, Next.js, Koa, …).
2. **Version** — if a version is visible (headers, or a `/health`, `/version`, `/status`… endpoint
   that discloses it), compare it to the fixed release for its branch.
3. **Behavioral probe** (`--probe`) — send two tiny, **valid** requests: one JSON body compressed with
   Brotli (`Content-Encoding: br`) and one with a made-up encoding. If the server **415s the unknown
   but accepts the Brotli**, it decompresses Brotli request bodies — the reachable attack surface.

## Usage

```bash
python3 n2s_scan.py -u https://api.example.com/v1/orders --probe
python3 n2s_scan.py -l targets.txt --probe -o results.csv
python3 n2s_scan.py -u https://example.com --json
```

| Flag | Meaning |
|---|---|
| `-u, --url` | single target (URL or host) |
| `-l, --list` | file with one target per line |
| `-p, --probe` | also run the safe Brotli body probe (best against a JSON/API route) |
| `-o, --out` | write results to CSV |
| `--json` | emit JSON lines |
| `--timeout` | per-request timeout (default 10s) |
| `--insecure` | do not verify TLS certificates |

**Exit code** `2` if anything is `VULNERABLE`/`LIKELY VULNERABLE`, else `0` — handy in CI.

## Verdicts

`VULNERABLE` · `LIKELY VULNERABLE` · `POTENTIALLY VULNERABLE` · `PATCHED` · `NOT DETECTED` · `ERROR`
— see the top-level [README](../README.md#verdicts).

> Scan only systems you are authorized to test.
