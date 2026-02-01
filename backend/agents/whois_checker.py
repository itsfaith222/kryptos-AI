"""
whois_checker.py
Kryptos-AI - WHOIS Domain Checker (Hour 6-12 Enhanced)
"""

from datetime import datetime, timezone
from typing import Dict
import re


SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click']
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
    'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com', 'netflix.com',
    'linkedin.com', 'instagram.com', 'github.com', 'wikipedia.org', 'reddit.com',
]


def _normalize_domain(domain: str) -> str:
    """Clean domain for WHOIS lookup"""
    if not domain:
        return ""
    domain = domain.strip().lower()
    for prefix in ("http://", "https://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    if "/" in domain:
        domain = domain.split("/")[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


class WHOISChecker:
    """Enhanced WHOIS checker"""

    def check_domain(self, domain: str) -> Dict:
        """Check domain registration info"""
        domain = _normalize_domain(domain)
        
        if not domain:
            return self._empty_result()

        # Check trusted domains
        base_domain = '.'.join(domain.split('.')[-2:])
        if base_domain in TRUSTED_DOMAINS:
            return {
                "domainName": domain,
                "domainAgeDays": 3650,
                "registrar": "Trusted Domain",
                "privacyProtected": False,
                "suspicionScore": 5,
            }

        result = {
            "domainName": domain,
            "domainAgeDays": -1,
            "registrar": "Unknown",
            "privacyProtected": False,
            "suspicionScore": 0,
        }

        # Try real WHOIS lookup
        whois_data = self._perform_whois_lookup(domain)
        if whois_data:
            result.update(whois_data)

        # Calculate suspicion score
        result["suspicionScore"] = self._calculate_suspicion(result, domain)

        return result

    def _empty_result(self) -> Dict:
        return {
            "domainName": "",
            "domainAgeDays": -1,
            "registrar": "Unknown",
            "privacyProtected": False,
            "suspicionScore": 50,
        }

    def _perform_whois_lookup(self, domain: str) -> Dict:
        """Perform actual WHOIS lookup"""
        try:
            import whois
            w = whois.whois(domain)
            
            result = {}
            
            creation_date = getattr(w, 'creation_date', None)
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                result["domainAgeDays"] = (now - creation_date).days

            registrar = getattr(w, 'registrar', None)
            if registrar:
                result["registrar"] = str(registrar)

            # Check privacy protection
            name = str(getattr(w, 'name', '') or '').lower()
            org = str(getattr(w, 'org', '') or '').lower()
            if any(p in name or p in org for p in ['privacy', 'protect', 'proxy', 'whoisguard']):
                result["privacyProtected"] = True

            return result

        except ImportError:
            return None
        except Exception:
            return None

    def _calculate_suspicion(self, result: Dict, domain: str) -> int:
        """Calculate suspicion score"""
        suspicion = 0

        age_days = result.get('domainAgeDays', -1)
        if age_days >= 0:
            if age_days < 7:
                suspicion += 40
            elif age_days < 30:
                suspicion += 30
            elif age_days < 90:
                suspicion += 15
        else:
            suspicion += 15

        # TLD check
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                suspicion += 25
                break

        # Pattern checks
        if re.search(r'\d{3,}', domain):
            suspicion += 15
        if domain.count('-') >= 2:
            suspicion += 15

        # Brand impersonation check
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix', 'bank']
        for brand in brands:
            if brand in domain and domain != f'{brand}.com':
                if '-' in domain or any(c.isdigit() for c in domain):
                    suspicion += 30

        if result.get('privacyProtected'):
            suspicion += 10

        return max(0, min(100, suspicion))