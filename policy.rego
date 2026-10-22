# Phase 1 policy for the Supervisor.
# OPA evaluates this file; the Supervisor asks: "is input.role allowed to do input.action?"
package authz

import rego.v1

# Fail closed: anything not explicitly allowed below is denied.
default allow := false

# The only rule in Phase 1: a log analyst may read logs.
allow if {
	input.role == "log_analyst"
	input.action == "read_logs"
}
