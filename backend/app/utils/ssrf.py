import ipaddress
import socket
from urllib.parse import urlsplit


PROHIBITED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),    # Private RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),   # Private RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


def is_prohibited_ip(ip_str: str) -> bool:
    """
    Returns True if the IP address belongs to loopback, private, link-local,
    reserved, or multicast blocks.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PROHIBITED_NETWORKS)
    except ValueError:
        return True


def validate_target_url(url: str) -> tuple[bool, str]:
    """
    Validates a URL against SSRF vulnerabilities:
    - Only allows http and https schemes.
    - Rejects localhost, loopback, private, link-local, or multicast destinations.
    - Resolves hostname via DNS to prevent DNS rebinding or private IP access.
    """
    try:
        parsed = urlsplit(str(url).strip())
    except Exception as exc:
        return False, f"Malformed URL: {exc}"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "URL missing valid hostname."

    # Direct localhost check
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return False, f"Access to localhost/loopback address '{hostname}' is prohibited."

    # Direct IP string check
    try:
        ip = ipaddress.ip_address(hostname)
        if is_prohibited_ip(str(ip)):
            return False, f"Access to private/reserved IP address '{hostname}' is prohibited."
        return True, "URL is safe"
    except ValueError:
        # Hostname is not a raw IP, resolve via DNS
        pass

    try:
        # Resolve all IPs for the hostname
        resolved_ips = socket.getaddrinfo(hostname, None)
        for entry in resolved_ips:
            ip_str = entry[4][0]
            if is_prohibited_ip(ip_str):
                return False, f"Resolved IP address '{ip_str}' for host '{hostname}' is prohibited (SSRF protection)."
    except socket.gaierror:
        # Unresolvable domains are not SSRF targets, but still can't connect
        pass
    except Exception as exc:
        return False, f"DNS resolution check failed: {exc}"

    return True, "URL is safe"
