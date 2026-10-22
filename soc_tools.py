"""Simulated SOC Tools (Phase 2).

Provides simulated remediation tools: blocking/unblocking IP addresses
and isolating hosts. Everything runs in-memory - no real firewall, network
interface, or production system is ever touched.

Protected targets act as a "second line of defense": even if the policy
engine had a bug, these tools themselves raise PermissionError if anyone
tries to block core infrastructure like the default gateway or production DB.
"""

# Protected assets that can NEVER be blocked or isolated.
PROTECTED_IPS = {"192.168.1.1"}
PROTECTED_HOSTS = {"db-01"}

# In-memory storage for blocked IPs and isolated hosts
_blocked_ips: set[str] = set()
_isolated_hosts: set[str] = set()


def block_ip(ip: str) -> dict:
    """Simulate blocking an IP address on the firewall.
    
    Raises:
        PermissionError: if the IP belongs to PROTECTED_IPS.
    """
    if ip in PROTECTED_IPS:
        raise PermissionError(f"Cannot block protected IP: {ip}")
    _blocked_ips.add(ip)
    return {"status": "blocked", "ip": ip}


def unblock_ip(ip: str) -> dict:
    """Simulate unblocking an IP address on the firewall."""
    _blocked_ips.discard(ip)
    return {"status": "unblocked", "ip": ip}


def isolate_host(host: str) -> dict:
    """Simulate isolating an internal host from the network.
    
    Raises:
        PermissionError: if the host belongs to PROTECTED_HOSTS.
    """
    if host in PROTECTED_HOSTS:
        raise PermissionError(f"Cannot isolate protected host: {host}")
    _isolated_hosts.add(host)
    return {"status": "isolated", "host": host}


def list_blocked() -> list[str]:
    """Return a sorted list of all currently blocked IP addresses."""
    return sorted(list(_blocked_ips))


def list_isolated() -> list[str]:
    """Return a sorted list of all currently isolated hosts."""
    return sorted(list(_isolated_hosts))


def reset_tools() -> None:
    """Helper to clear in-memory state (useful for tests or demo resets)."""
    _blocked_ips.clear()
    _isolated_hosts.clear()
