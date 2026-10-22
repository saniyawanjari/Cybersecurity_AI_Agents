"""Agent B - Threat Detector (Phase 2).

Takes the report from Agent A and categorizes suspicious IP addresses by threat severity:
  - 6 or more failed logins: 'high'
  - 3 to 5 failed logins: 'medium'
  - below 3: 'low'

Sorts the resulting list so high severity threats appear first.
Agent B can SUGGEST threat levels, but does NOT have authority to block IPs.
"""


def detect_threats(report: dict[str, int]) -> list[dict]:
    """Analyze the report from Agent A and assign threat levels to each IP.
    
    Args:
        report: Dictionary of {ip: failure_count}.
        
    Returns:
        list of dict: List containing {ip, severity, reason, count}, sorted high first.
    """
    threats = []
    
    for ip, count in report.items():
        if count >= 6:
            severity = "high"
        elif count >= 3:
            severity = "medium"
        else:
            severity = "low"
            
        threats.append({
            "ip": ip,
            "severity": severity,
            "reason": f"Repeated failed logins ({count} attempts)",
            "count": count
        })
        
    # Sort order: 'high' comes before 'medium', then higher counts first
    severity_order = {"high": 0, "medium": 1, "low": 2}
    threats.sort(key=lambda item: (severity_order.get(item["severity"], 3), -item["count"]))
    
    return threats
