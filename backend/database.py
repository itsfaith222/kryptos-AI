"""
Database - Person D: MongoDB schema, save/load scan results
"""
# Stub for mock milestone - real MongoDB wiring in Hour 6+
# from pymongo import MongoClient


async def save_scan(scan_result: dict) -> None:
    """Save scan result to MongoDB. No-op when not connected."""
    pass


async def get_recent_scans(limit: int = 10) -> list:
    """Get recent scans. Returns empty list for mock."""
    return []
