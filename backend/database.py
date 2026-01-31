"""
Guardian AI - MongoDB connection and scans collection
Used by Scout endpoint to persist every scan (timestamp, url, score, metadata)
"""

import os
from datetime import datetime
from typing import Dict, Any, Optional

_MONGO_CLIENT = None
_DB = None

def get_db():
    """Get MongoDB database; connect if not already connected."""
    global _MONGO_CLIENT, _DB
    if _DB is not None:
        return _DB
    uri = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI") or "mongodb://localhost:27017"
    try:
        from pymongo import MongoClient
        _MONGO_CLIENT = MongoClient(uri, serverSelectionTimeoutMS=5000)
        _MONGO_CLIENT.admin.command("ping")
        _DB = _MONGO_CLIENT.get_database("guardian_ai")
        return _DB
    except Exception as e:
        print(f"[Guardian AI] MongoDB not available: {e}. Scans will not be persisted.")
        return None


def save_scan(url: str, score: int, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Save a scan to the scans collection.
    Returns inserted document id if MongoDB is available, else None.
    """
    db = get_db()
    if db is None:
        return None
    try:
        doc = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "url": url,
            "score": score,
            "metadata": metadata or {}
        }
        result = db.scans.insert_one(doc)
        return str(result.inserted_id)
    except Exception as e:
        print(f"[Guardian AI] save_scan error: {e}")
        return None
