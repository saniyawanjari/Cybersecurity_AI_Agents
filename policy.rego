# Phase 2 authorization policy for the SOC Agent Supervisor.
# Evaluated by Open Policy Agent (OPA).
package authz

import rego.v1

# Fail closed: any request not explicitly permitted is DENIED.
default allow := false

# Role-Based Permissions Matrix:
# - log_analyst: can only read logs
# - threat_detector: can read logs and generate threat reports
# - incident_responder: can perform active actions (block_ip, isolate_host)
permissions := {
	"log_analyst": {"read_logs"},
	"threat_detector": {"read_logs", "report_threat"},
	"incident_responder": {"block_ip", "isolate_host"},
}

# Protected infrastructure resources that must NEVER be modified
protected_resources := {"192.168.1.1", "db-01"}

# Allow rule:
# 1. The requested action must be in the role's allowed set of permissions.
# 2. The target resource must NOT be in the protected resources set.
allow if {
	input.action in permissions[input.role]
	not input.resource in protected_resources
}
