"""Phase 2 Demo Script.

Tests the role-based matrix by sending requests as every role:
  - log_analyst
  - threat_detector
  - incident_responder
  - nobody (unauthorized role)
  - no header (missing identity)

Against every endpoint:
  1. GET  /api/v1/agent-a/report
  2. GET  /api/v1/agent-b/threats
  3. POST /api/v1/agent-c/block (valid untrusted IP 203.0.113.5)
  4. POST /api/v1/agent-c/block (protected gateway IP 192.168.1.1)
  5. POST /api/v1/agent-c/isolate (normal host web-02)
  6. POST /api/v1/agent-c/isolate (protected database host db-01)

Prints an ALLOWED / DENIED(status) matrix table to verify the policy engine.
"""
import requests

BASE_URL = "http://127.0.0.1:8000"

ROLES = [
    ("log_analyst", "log_analyst"),
    ("threat_detector", "threat_detector"),
    ("incident_responder", "incident_responder"),
    ("nobody", "nobody"),
    ("no header", None),
]

ENDPOINTS = [
    {
        "name": "GET Agent-A Report",
        "method": "GET",
        "path": "/api/v1/agent-a/report",
        "payload": None,
    },
    {
        "name": "GET Agent-B Threats",
        "method": "GET",
        "path": "/api/v1/agent-b/threats",
        "payload": None,
    },
    {
        "name": "POST Block 203.0.113.5",
        "method": "POST",
        "path": "/api/v1/agent-c/block",
        "payload": {"ip": "203.0.113.5"},
    },
    {
        "name": "POST Block 192.168.1.1 (Protected)",
        "method": "POST",
        "path": "/api/v1/agent-c/block",
        "payload": {"ip": "192.168.1.1"},
    },
    {
        "name": "POST Isolate web-02",
        "method": "POST",
        "path": "/api/v1/agent-c/isolate",
        "payload": {"host": "web-02"},
    },
    {
        "name": "POST Isolate db-01 (Protected)",
        "method": "POST",
        "path": "/api/v1/agent-c/isolate",
        "payload": {"host": "db-01"},
    },
]


def test_endpoint(method: str, path: str, role_header: str | None, payload: dict | None) -> str:
    """Send an HTTP request and return formatted status outcome."""
    headers = {}
    if role_header is not None:
        headers["x-agent-role"] = role_header

    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=3.0)
        else:
            resp = requests.post(url, json=payload, headers=headers, timeout=3.0)

        if resp.status_code == 200:
            return "ALLOWED (200)"
        else:
            return f"DENIED ({resp.status_code})"
    except Exception as e:
        return f"ERROR ({e.__class__.__name__})"


def main():
    print("=" * 95)
    print(" PHASE 2 AUTHORIZATION MATRIX DEMO - AUTONOMOUS AGENT SUPERVISOR")
    print("=" * 95)
    print()

    # Table Header
    col_ep = 38
    col_role = 18
    header_line = f"{'Endpoint / Test Case':<{col_ep}}" + "".join(
        f"{role_label:^{col_role}}" for role_label, _ in ROLES
    )
    print(header_line)
    print("-" * len(header_line))

    # Run each endpoint against each role
    for ep in ENDPOINTS:
        row = f"{ep['name']:<{col_ep}}"
        for _, role_val in ROLES:
            result = test_endpoint(ep["method"], ep["path"], role_val, ep["payload"])
            row += f"{result:^{col_role}}"
        print(row)

    print("-" * len(header_line))
    print()

    # Query public SOC state
    print("Inspecting Simulated SOC Tool State (GET /api/v1/soc/blocked):")
    try:
        soc_resp = requests.get(f"{BASE_URL}/api/v1/soc/blocked", timeout=3.0)
        print(soc_resp.json())
    except Exception as e:
        print(f"Could not reach SOC state endpoint: {e}")
    print()


if __name__ == "__main__":
    main()
