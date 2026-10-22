"""Supervisor (Phase 2): Autonomous Agent Authorization Framework.

Intercepts all agent requests and enforces capability-based access control.
Before any agent action is executed:
  1. Validates the agent role from the x-agent-role header (fail-closed if missing).
  2. Queries Open Policy Agent (OPA) at http://localhost:8181/v1/data/authz/allow.
  3. Denies any request if OPA is unreachable (503) or if not explicitly allowed (403).
  4. Dispatches the action to simulated SOC tools only upon approval.
"""
import ipaddress
import os
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

import agent_a
import agent_b
import soc_tools

app = FastAPI(
    title="SOC Agent Framework Supervisor",
    version="phase-2",
    description="Capability-based supervisor for autonomous cybersecurity agents."
)

# OPA URL configured via environment variable with localhost fallback
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181/v1/data/authz/allow")


class BlockRequest(BaseModel):
    ip: str


class IsolateRequest(BaseModel):
    host: str


def authorize(role: Optional[str], action: str, resource: str) -> None:
    """Evaluate authorization against OPA policy.
    
    Fail closed:
      - Missing or empty role header -> 403 Forbidden
      - OPA unreachable, connection error, or timeout (>2s) -> 503 Service Unavailable
      - OPA decision not exactly True -> 403 Forbidden
    """
    if not role or not role.strip():
        raise HTTPException(
            status_code=403,
            detail="Authorization denied: missing or empty 'x-agent-role' header"
        )

    try:
        response = httpx.post(
            OPA_URL,
            json={"input": {"role": role.strip(), "action": action, "resource": resource}},
            timeout=2.0,
        )
        response.raise_for_status()
        data = response.json()
        allowed = data.get("result")
    except (httpx.HTTPError, ValueError):
        # Network error, timeout, non-2xx status, or malformed JSON
        raise HTTPException(
            status_code=503,
            detail="Policy engine (OPA) unavailable - request denied (fail closed)"
        )

    if allowed is not True:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied by policy: role '{role}' cannot perform '{action}' on '{resource}'"
        )


@app.get("/api/v1/agent-a/report")
def get_agent_a_report(x_agent_role: Optional[str] = Header(default=None)):
    """Agent A - Log Analyst report endpoint.
    
    Requires permission: 'read_logs' on 'server_logs.txt'.
    """
    authorize(x_agent_role, "read_logs", "server_logs.txt")
    return agent_a.analyze_logs()


@app.get("/api/v1/agent-b/threats")
def get_agent_b_threats(x_agent_role: Optional[str] = Header(default=None)):
    """Agent B - Threat Detector threats endpoint.
    
    Requires BOTH permissions:
      1. 'read_logs' on 'server_logs.txt'
      2. 'report_threat' on 'threats'
    """
    authorize(x_agent_role, "read_logs", "server_logs.txt")
    authorize(x_agent_role, "report_threat", "threats")
    
    report = agent_a.analyze_logs()
    return agent_b.detect_threats(report)


@app.post("/api/v1/agent-c/block")
def post_agent_c_block(
    payload: BlockRequest,
    x_agent_role: Optional[str] = Header(default=None)
):
    """Agent C - Incident Responder: block suspicious IP.
    
    Validates IP address format (422 if invalid).
    Requires permission: 'block_ip' on the requested IP.
    """
    # 1. Validate IP format using standard ipaddress module
    try:
        ipaddress.ip_address(payload.ip)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IP address format: '{payload.ip}'"
        )

    # 2. Check policy authorization (OPA)
    authorize(x_agent_role, "block_ip", payload.ip)

    # 3. Execute action via simulated SOC tools (with second-line defense check)
    try:
        result = soc_tools.block_ip(payload.ip)
        return result
    except PermissionError as err:
        raise HTTPException(status_code=403, detail=str(err))


@app.post("/api/v1/agent-c/isolate")
def post_agent_c_isolate(
    payload: IsolateRequest,
    x_agent_role: Optional[str] = Header(default=None)
):
    """Agent C - Incident Responder: isolate compromised host.
    
    Requires permission: 'isolate_host' on the target host.
    """
    host = payload.host.strip()
    if not host:
        raise HTTPException(status_code=422, detail="Host parameter cannot be empty")

    # 1. Check policy authorization (OPA)
    authorize(x_agent_role, "isolate_host", host)

    # 2. Execute action via simulated SOC tools (with second-line defense check)
    try:
        result = soc_tools.isolate_host(host)
        return result
    except PermissionError as err:
        raise HTTPException(status_code=403, detail=str(err))


@app.get("/api/v1/soc/blocked")
def get_soc_blocked():
    """Unauthenticated public inspection endpoint to observe simulated SOC state."""
    return {
        "blocked_ips": soc_tools.list_blocked(),
        "isolated_hosts": soc_tools.list_isolated()
    }
