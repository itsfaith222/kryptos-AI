# backend/agents/__init__.py

import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

# Handle imports for both direct script execution and package import
try:
    from .gemini_analyzer import GeminiAnalyzer
    from .mitre_mapper import MITREMapper
    from .whois_checker import WHOISChecker
except (ImportError, ValueError):
    from gemini_analyzer import GeminiAnalyzer
    from mitre_mapper import MITREMapper
    from whois_checker import WHOISChecker

class AnalystAgent:
    """The Analyst Agent - Kryptos-AI's Deep Investigator (Hour 4-6)"""
    
    def __init__(self, db=None):
        """Initialize Analyst Agent with OpenRouter-powered Gemini"""
        self.db = db
        
        # This now uses the OpenRouter API key to access Gemini models
        self.gemini = GeminiAnalyzer() 
        
        # New Hour 4-6 Modules
        self.whois = WHOISChecker()
        self.mitre_mapper = MITREMapper() # Ensure this is initialized
        
        print("[ANALYST] 🔍 Hour 4-6: Analyst with MITRE + WHOIS")
        print(f"[ANALYST] AI Engine (OpenRouter): {'✓' if self.gemini.available else '✗'}")
        print(f"[ANALYST] MongoDB: {'✓' if db else '✗ (standalone mode)'}")