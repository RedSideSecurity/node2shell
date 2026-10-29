# lab/ — Node2Shell vulnerable lab (CVE-2026-111497)

Three realistic targets so you can see every verdict tier for real. All bind to `127.0.0.1` only.
The app is an ordinary Express 5 API (`express.json()`), so it decompresses `Content-Encoding: br`
request bodies by default — the reachable Brotli path. **Only the Node.js version differs** between
vulnerable and patched.

| Target | Port | Node | What it shows |
|---|---|---|---|
| vulnerable | 8091 | 24.22.0 | `VULNERABLE` — affected version, visible at `/health` |
| patched (control) | 8092 | 24.22.1 | `PATCHED` — the fix is in Node's bundled Brotli |
| stealth | 8093 | 24.22.0 | `LIKELY VULNERABLE` — version hidden; caught by the behavioral probe alone |

> Node keeps `process.versions.brotli == "1.2.0"` on both 24.22.0 and 24.22.1 — the patch is a source
> fix to the bundled decoder, not a version bump. So the verdict keys on the **Node** version, not the
> Brotli string. The stealth target proves why a behavioral probe matters.

## Run

```bash
./run.sh      # build + start all three
./stop.sh     # tear down
```
or from the repo root: `docker compose up vuln patched stealth`.

```bash
curl -s http://127.0.0.1:8091/health            # {"status":"ok","node":"24.22.0",...}
python3 ../scanner/n2s_scan.py -u http://127.0.0.1:8091/api/orders --probe
```

For authorized, local testing only.
