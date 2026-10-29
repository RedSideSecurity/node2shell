# Security & responsible use

## What this tool does and doesn't do

`n2s_scan.py` is **detection only**. Against a target it:

- sends a normal `GET` and reads a bounded amount of the response to fingerprint the platform/version;
- optionally (`--probe`) sends two tiny **valid** requests — a 6-byte Brotli body (`{}`) and one with
  an unknown `Content-Encoding` — to learn whether the server decompresses Brotli request bodies.

It **never** sends the malformed Brotli stream that triggers CVE-2026-111497, never attempts code
execution, and writes nothing to the target. A scan is a handful of ordinary HTTP requests.

## Authorized use only

Scan only systems you own or have explicit written permission to test. You are responsible for how
you use it. The maintainers accept no liability for misuse.

## Reporting a vulnerability

Found a security issue in this tooling? Email **info@redsidesecurity.com**. Please don't open a
public issue for security reports.

## Remediation for Node2Shell itself

Update the runtime and rebuild your images — Node.js 22.23.4 / 24.22.1 / 26.12.1, Bun 1.4.4,
Envoy 1.37.8+ for its branch, the .NET out-of-band update, and Python `Brotli` 1.2.1 / `brotlicffi`
1.2.1.0. See the [README](README.md#fixed-versions) for the full table.
