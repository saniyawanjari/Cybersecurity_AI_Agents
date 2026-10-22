"""Supervisor (Phase 1): every request is checked by OPA BEFORE the agent runs."""
import os

import httpx
from fastapi import FastAPI, Header, HTTPException

import agent_a

app = FastAPI(title="SOC Agent Supervisor", version="phase-1")

# Where OPA listens. Not a secret, but configurable through an environment variable.
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181/v1/data/authz/allow")


def authorize(role: str, action: str) -> None:
    """Ask OPA if this role may do this action. Returns nothing if allowed.

    FAIL CLOSED: every problem ends in an error, never in 'allow'.
      - OPA unreachable / bad answer -> 503
      - OPA says false or gives no answer -> 403
    """
    try:
        response = httpx.post(
            OPA_URL,
            json={"input": {"role": role, "action": action}},
            timeout=2.0,
        )
        response.raise_for_status()
        # OPA replies {"result": true}. If 'allow' is undefined, 'result' is missing.
        allowed = response.json().get("result")
    except (httpx.HTTPError, ValueError):
        # HTTPError = cannot connect / timeout / non-2xx. ValueError = invalid JSON.
        raise HTTPException(status_code=503, detail="Policy engine unavailable - request denied")

    # 'is True' so that only a real true allows; null/false/anything else denies.
    if allowed is not True:
        raise HTTPException(status_code=403, detail="Denied by policy")


@app.get("/api/v1/agent-a/report")
def agent_a_report(x_agent_role: str | None = Header(default=None)):
    # TEMPORARY: the role comes from a header anyone can fake.
    # Phase 3 and 4 replace this with real identity and capability tokens.
    role = x_agent_role or ""  # missing header -> empty role -> OPA denies

    authorize(role, "read_logs")  # 1) policy check FIRST

    report = agent_a.run_analysis()  # 2) only now run the agent
    return {"agent": "log_analyst", "threshold": agent_a.THRESHOLD, "report": report}
