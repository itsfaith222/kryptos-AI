"""
whois_checker.py
WHOIS Domain Checker — real lookup for domain age (python-whois)
HOUR 4-6: Domain age detection
"""

from datetime import datetime, timezone


def _normalize_domain(domain: str) -> str:
    """Strip protocol, path, and www for WHOIS lookup."""
    if not domain:
        return ""
    domain = domain.strip().lower()
    for prefix in ("http://", "https://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    if "/" in domain:
        domain = domain.split("/")[0]
    return domain


def _suspicion_heuristics(domain: str, age_days: int) -> int:
    """Pattern-based suspicion (numbers, length, TLD). Add penalty for very new domains."""
    suspicion = 0
    if any(c.isdigit() for c in domain):
        suspicion += 20
    if len(domain.split(".")[0]) > 20:
        suspicion += 15
    if any(tld in domain for tld in [".tk", ".ml", ".ga", ".cf"]):
        suspicion += 30
    # Very new domain (real age from WHOIS)
    if age_days >= 0 and age_days < 30:
        suspicion += 35
    elif age_days >= 0 and age_days < 90:
        suspicion += 15
    return min(suspicion, 100)


class WHOISChecker:
    """Check domain registration info using real WHOIS lookup for age."""

    def check_domain(self, domain: str) -> dict:
        """
        Real WHOIS lookup for creation date; compute domainAgeDays and suspicionScore.
        Falls back to heuristics only if WHOIS fails or returns no creation date.
        """
        domain = _normalize_domain(domain)
        if not domain:
            return {
                "domainName": "",
                "domainAgeDays": -1,
                "registrar": "Unknown",
                "privacyProtected": False,
                "suspicionScore": 50,
            }

        age_days = -1
        registrar = "Unknown"
        creation_date = None

        try:
            import whois
            w = whois.whois(domain)
            creation_date = getattr(w, "creation_date", None)
            if creation_date is not None:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age_days = (now - creation_date).days
            if getattr(w, "registrar", None):
                registrar = str(w.registrar) if w.registrar else "Unknown"
        except ImportError:
            # python-whois not installed; use heuristics only
            age_days = -1
        except Exception:
            age_days = -1
            creation_date = None

        suspicion = _suspicion_heuristics(domain, age_days)
        return {
            "domainName": domain,
            "domainAgeDays": age_days,
            "registrar": registrar,
            "privacyProtected": suspicion > 30,
            "suspicionScore": suspicion,
        }
