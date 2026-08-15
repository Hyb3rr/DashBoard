"""X4B privacy and datacenter CIDR adapters."""
from .cidr_lists import refresh_cidr_source

def refresh_vpn(conn, url=None, cache=None):
    return refresh_cidr_source(conn, "x4b_vpn", url, "vpn", cache)

def refresh_datacenter(conn, url=None, cache=None):
    return refresh_cidr_source(conn, "x4b_datacenter", url, "datacenter", cache)
