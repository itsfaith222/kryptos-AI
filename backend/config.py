"""
App config - change appName here to rebrand.
"""
import json
from pathlib import Path

_config_path = Path(__file__).resolve().parent.parent / "app.config.json"
_config = json.loads(_config_path.read_text()) if _config_path.exists() else {}

APP_NAME = _config.get("appName", "")
