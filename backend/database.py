"""
Database - Person D: MongoDB schema, save/load scan results, GridFS audio for Educator
"""
import os
from pathlib import Path

# Load .env from backend folder before reading MONGODB_URI
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

MONGODB_URI = (os.getenv("MONGODB_URI", "mongodb://localhost:27017") or "").strip()
DB_NAME = os.getenv("MONGODB_DB", "guardian_ai").strip() or "guardian_ai"
COLLECTION = "scans"

_client = None
_db = None
_fs = None


def _get_db():
    global _client, _db
    if _db is not None:
        return _db
    try:
        from pymongo import MongoClient
        from pymongo.server_api import ServerApi
        _client = MongoClient(MONGODB_URI, server_api=ServerApi("1"))
        _db = _client[DB_NAME]
        return _db
    except Exception as e:
        raise RuntimeError(f"MongoDB connection failed: {e}") from e


def _get_fs():
    """Lazy-init GridFS on the same DB (for Educator audio)."""
    global _fs
    if _fs is not None:
        return _fs
    from gridfs import GridFS
    _fs = GridFS(_get_db())  # noqa: PLW0603
    return _fs


async def save_scan(scan_result: dict) -> None:
    """Save full ScanResult to MongoDB (scanId, riskScore, threatType, evidence, explanation, nextSteps, mitreAttackTechniques, etc.)."""
    db = _get_db()
    # Insert a copy so PyMongo adding _id does not mutate the caller's dict (avoids ObjectId in API response).
    doc = dict(scan_result)
    result = db[COLLECTION].insert_one(doc)
    # Terminal feedback
    print(f"\n[DB] Scan saved to MongoDB | scanId={doc.get('scanId', '?')[:8]}... | riskScore={doc.get('riskScore')} | threatType={doc.get('threatType')}\n")


async def get_recent_scans(limit: int = 10) -> list:
    """Get recent scans, newest first."""
    try:
        db = _get_db()
        cursor = db[COLLECTION].find().sort("timestamp", -1).limit(limit)
        return list(cursor)
    except Exception:
        return []


# --- GridFS audio for Educator (voice alerts) ---


def save_audio(mp3_bytes: bytes, filename: str, metadata: dict) -> str:
    """Store MP3 bytes in GridFS; returns file_id (str) for later retrieval."""
    fs = _get_fs()
    file_id = fs.put(mp3_bytes, filename=filename, metadata=metadata)
    return str(file_id)


def get_audio(file_id: str):
    """Retrieve audio file from GridFS by file_id (str). Returns GridOut (read .read() for bytes)."""
    from bson import ObjectId
    fs = _get_fs()
    return fs.get(ObjectId(file_id))
