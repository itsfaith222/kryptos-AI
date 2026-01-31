"""
whois_checker.py
WHOIS Domain Checker (Mock for hackathon)
HOUR 4-6: Domain age detection
"""


class WHOISChecker:
    """Check domain registration info"""
    
    def check_domain(self, domain: str) -> dict:
        """
        Mock WHOIS check (replace with real API in production)
        
        Returns:
            {
                "domainName": "example.com",
                "domainAgeDays": 5,
                "suspicionScore": 75
            }
        """
        suspicion = 0
        age_days = -1
        
        # Pattern-based heuristics
        if any(char.isdigit() for char in domain):
            suspicion += 20  # Numbers in domain
        
        if len(domain.split('.')[0]) > 20:
            suspicion += 15  # Very long
        
        if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
            suspicion += 30  # Suspicious TLDs
        
        # Mock age
        known_legit = ['amazon.com', 'paypal.com', 'google.com', 
                       'microsoft.com', 'netflix.com', 'apple.com']
        
        if not any(legit in domain for legit in known_legit):
            age_days = 5
            suspicion += 25
        else:
            age_days = 3650
            suspicion = 0
        
        return {
            "domainName": domain,
            "domainAgeDays": age_days,
            "registrar": "Unknown (mock)",
            "privacyProtected": suspicion > 30,
            "suspicionScore": min(suspicion, 100)
        }