try:
    from .gemini_analyzer import GeminiAnalyzer
except ImportError:
    from gemini_analyzer import GeminiAnalyzer
    
def __init__(self, db=None):
    """Initialize Analyst Agent"""
    self.db = db
    self.gemini = GeminiAnalyzer() 
    print("[ANALYST] 🔍 Hour 2-4: Analyst with Gemini AI")
    print(f"[ANALYST] Gemini: {'✓' if self.gemini.available else '✗'}")
    print(f"[ANALYST] MongoDB: {'✓' if db else '✗ (standalone mode)'}")