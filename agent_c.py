"""Agent C - Incident Responder (Phase 2).

Acts on detected threats by invoking simulated remediation tools (soc_tools).
Calls soc_tools.block_ip for every medium and high severity threat.
Catches PermissionError (second line of defense if an IP is protected)
and returns an audit list of actions taken.
"""
import soc_tools


def block_threats(threats: list[dict]) -> list[dict]:
    """Execute remediation on medium and high threats.
    
    Args:
        threats: List of threat dicts from Agent B, containing {ip, severity, ...}.
        
    Returns:
        list of dict: Actions attempted and their status (blocked or denied).
    """
    actions = []
    
    for threat in threats:
        ip = threat.get("ip")
        severity = threat.get("severity", "low")
        
        # Only take action on medium or high threats
        if severity in ("medium", "high"):
            try:
                result = soc_tools.block_ip(ip)
                actions.append({
                    "ip": ip,
                    "severity": severity,
                    "status": "blocked",
                    "details": result
                })
            except PermissionError as err:
                actions.append({
                    "ip": ip,
                    "severity": severity,
                    "status": "error",
                    "error": str(err)
                })
                
    return actions
