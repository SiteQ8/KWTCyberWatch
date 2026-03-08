#!/usr/bin/env python3
"""
KWTCyberWatch - DNS & WHOIS Utilities
"""

import logging
import socket
from typing import Dict, List, Optional

logger = logging.getLogger("kwtcyberwatch.utils")


def dns_resolve(domain: str) -> Dict:
    """Resolve DNS records for a domain."""
    results = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    try:
        import dns.resolver
        for rtype in results.keys():
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers):
                pass
    except ImportError:
        # Fallback to socket
        try:
            results["A"] = [socket.gethostbyname(domain)]
        except socket.gaierror:
            pass
    return results


def whois_lookup(domain: str) -> Optional[Dict]:
    """Perform WHOIS lookup on a domain."""
    try:
        import whois
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "country": getattr(w, "country", None),
        }
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        return None


def reverse_ip_lookup(ip: str) -> List[str]:
    """Find domains hosted on the same IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return [hostname]
    except (socket.herror, socket.gaierror):
        return []


def check_ssl_certificate(domain: str, port: int = 443) -> Optional[Dict]:
    """Retrieve SSL certificate details."""
    import ssl
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, port))
            cert = s.getpeercert()
            return {
                "subject": dict(x[0] for x in cert.get("subject", ())),
                "issuer": dict(x[0] for x in cert.get("issuer", ())),
                "serial_number": cert.get("serialNumber"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "san": [
                    entry[1] for entry in cert.get("subjectAltName", ())
                ],
            }
    except Exception as e:
        logger.debug(f"SSL check failed for {domain}: {e}")
        return None
