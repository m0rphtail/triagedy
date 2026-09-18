#!/usr/bin/env python3
"""Offline mock of TypeSafe's /v1/systemone for triagedy's jev backend.

Usage:
    python3 tools/mock_typesafe.py 8765 &
    TYPESAFE_API_KEY=dummy ./target/debug/triagedy doctor \
        --backend jev --typesafe-url http://127.0.0.1:8765/v1/systemone

Asserts path, bearer auth, model, and the question-key set (5 without context,
6 with duplicate_of_recent). Dumps the last request to /tmp/mock_last_request.json.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ANSWERS = {
    "model": "jev-latest",
    "answers": {
        "disposition": {"type": "choice", "choice": "escalate",
                        "probabilities": {"close": 0.02, "escalate": 0.85, "contain": 0.05, "investigate": 0.08},
                        "confidence": 0.83},
        "severity": {"type": "score", "score": 2.4,
                     "legend": {"0": "Informational", "1": "Low", "2": "High", "3": "Critical"},
                     "probabilities": {"0": 0.02, "1": 0.08, "2": 0.7, "3": 0.2},
                     "confidence": 0.81},
        "false_positive_probability": {"type": "noul", "noul": 0.11},
        "requires_escalation": {"type": "noul", "noul": 0.93},
        "attack_class": {"type": "choice", "choice": "execution",
                         "probabilities": {"none": 0.05, "execution": 0.8, "credential_access": 0.06,
                                           "persistence": 0.04, "lateral_movement": 0.03, "exfiltration": 0.02},
                         "confidence": 0.79},
        "duplicate_of_recent": {"type": "noul", "noul": 0.21},
    },
    "usage": {"input_tokens": 312, "output_tokens": 48},
}

BASE = {"disposition", "severity", "false_positive_probability",
        "requires_escalation", "attack_class"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(n))
            with open("/tmp/mock_last_request.json", "w") as f:
                json.dump(req, f, indent=2)
            assert self.path == "/v1/systemone", self.path
            assert self.headers.get("Authorization", "").startswith("Bearer "), "missing bearer"
            assert req.get("model") == "jev-latest", req.get("model")
            keys = set(req.get("questions", {}).keys())
            assert keys in (BASE, BASE | {"duplicate_of_recent"}), f"unexpected question keys: {keys}"
            wants_dup = "duplicate_of_recent" in keys
            answers = {k: v for k, v in ANSWERS["answers"].items() if wants_dup or k != "duplicate_of_recent"}
            body = json.dumps({"model": "jev-latest", "answers": answers,
                               "usage": ANSWERS["usage"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:  # noqa: BLE001
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            print(f"MOCK ERROR: {e!r}", file=sys.stderr)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print(f"mock listening on 127.0.0.1:{port}", file=sys.stderr, flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
