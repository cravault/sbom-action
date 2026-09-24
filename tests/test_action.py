#!/usr/bin/env python3
"""Smoke tests for the composite action, against a stub Cravault that records requests.

No network and no real backend: the point is the contract this action promises — what it
sends, what it refuses, and above all that a hostile input value stays data. The version
input defaults to github.ref_name, and git accepts a ref named `v1$(...)`, so "inputs are
data" is the property that matters most here.

  python3 tests/test_action.py
"""
import json
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": [
        {"type": "library", "name": "requests", "version": "2.31.0",
         "purl": "pkg:pypi/requests@2.31.0"}
    ],
}

requests_seen: list[dict] = []


class Stub(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)
        requests_seen.append({
            "path": self.path,
            "query": urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query),
            "authorization": self.headers.get("authorization"),
            "body": body,
        })
        payload = json.dumps({"id": "stub", "component_count": 1}).encode()
        self.send_response(201)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # keep the test output readable
        pass


def run_action(tmp: Path, **inputs) -> subprocess.CompletedProcess:
    args = [sys.executable, str(ROOT / "tests" / "run_action.py"), str(ROOT / "action.yml")]
    args += [f"{k.replace('_', '-')}={v}" for k, v in inputs.items()]
    return subprocess.run(args, capture_output=True, text=True, cwd=tmp)


FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok   {name}")
    else:
        FAILURES.append(name)
        print(f"  FAIL {name} {detail}")


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    api = f"http://127.0.0.1:{server.server_port}"

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        sbom = tmp / "sbom.cyclonedx.json"
        sbom.write_text(json.dumps(SBOM))
        canary = tmp / "INJECTED"
        base = {"token": "crv_test", "api_url": api, "sbom_path": str(sbom)}

        print("a successful upload")
        requests_seen.clear()
        r = run_action(tmp, version="v1.0.0", **base)
        check("exits 0", r.returncode == 0, r.stderr)
        check("posts once", len(requests_seen) == 1)
        if requests_seen:
            sent = requests_seen[0]
            check("carries the bearer token", sent["authorization"] == "Bearer crv_test")
            check("sends the version", sent["query"].get("version") == ["v1.0.0"])
            check("defaults kind to release", sent["query"].get("kind") == ["release"])
            check("uploads the SBOM body", b"pkg:pypi/requests@2.31.0" in sent["body"])

        print("a hostile version is data, not code")
        requests_seen.clear()
        payload = f"v1$(touch {canary})"
        r = run_action(tmp, version=payload, **base)
        check("exits 0", r.returncode == 0, r.stderr)
        check("did not execute the substitution", not canary.exists())
        check("sent it verbatim", requests_seen and requests_seen[0]["query"]["version"] == [payload])

        # The only case that exercises the generation step, so it downloads syft.
        print("a hostile scan path is data, not code")
        canary.unlink(missing_ok=True)
        hostile = f"{tmp} ; touch {canary}"
        r = run_action(tmp, version="v1", path=hostile, token="crv_test", api_url=api)
        check("did not execute the substitution", not canary.exists())
        # Without this, the check above would also pass if syft never ran at all: syft
        # reporting the whole string as one target is what proves it arrived as data.
        check("syft received it as a single literal argument",
              hostile in (r.stdout + r.stderr), r.stderr[-200:])

        print("semver build metadata survives the query string")
        requests_seen.clear()
        run_action(tmp, version="v1.0.0+build.5", **base)
        check("+ is not turned into a space",
              requests_seen and requests_seen[0]["query"]["version"] == ["v1.0.0+build.5"],
              requests_seen[0]["query"] if requests_seen else "")

        print("kind reaches the API")
        requests_seen.clear()
        run_action(tmp, version="v1", kind="snapshot", **base)
        check("snapshot is passed through",
              requests_seen and requests_seen[0]["query"]["kind"] == ["snapshot"])

        print("bad input is refused before anything is sent")
        for name, kwargs in {
            "a line break in sbom-path": {"version": "v1", "sbom_path": f"{sbom}\nPATH=/evil"},
            "an unknown kind": {"version": "v1", "kind": "whatever", "sbom_path": str(sbom)},
            "a missing sbom-path": {"version": "v1", "sbom_path": str(tmp / "nope.json")},
            "an empty version": {"version": "", "sbom_path": str(sbom)},
        }.items():
            requests_seen.clear()
            r = run_action(tmp, token="crv_test", api_url=api, **kwargs)
            check(name, r.returncode != 0 and not requests_seen, r.stdout[-200:])

        print("a server error fails the job")
        server.shutdown()
        r = run_action(tmp, version="v1", **base)
        check("non-2xx exits non-zero", r.returncode != 0)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed: {', '.join(FAILURES)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
