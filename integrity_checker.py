"""
Integrity Checker Module - File Integrity Verification

Compares current file hashes against previously stored hashes
to detect unauthorized modifications.
"""

import os
import json
import hashlib
from datetime import datetime


REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
BASELINE_FILE = os.path.join(REPORTS_DIR, "baseline.json")


def _ensure_reports_dir():
    """Create the reports directory if it doesn't exist."""
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _hash_file_content(file_path: str) -> str:
    """Compute SHA-256 hash of file contents."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_baseline() -> dict:
    """Load the baseline hash store from disk."""
    if not os.path.isfile(BASELINE_FILE):
        return {}
    try:
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_baseline(data: dict):
    """Persist the baseline hash store to disk."""
    _ensure_reports_dir()
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)


def save_baseline(file_path: str) -> dict:
    """
    Compute and store a baseline hash for a file.

    Args:
        file_path: Path to the file.

    Returns:
        dict with 'success', 'message', and 'hash' keys.
    """
    if not os.path.isfile(file_path):
        return {"success": False, "message": f"File not found: {file_path}"}

    try:
        file_hash = _hash_file_content(file_path)
        abs_path = os.path.abspath(file_path)
        baseline = _load_baseline()
        baseline[abs_path] = {
            "hash": file_hash,
            "timestamp": datetime.now().isoformat(),
            "size": os.path.getsize(file_path),
        }
        _save_baseline(baseline)

        return {
            "success": True,
            "message": f"Baseline saved for {file_path}",
            "hash": file_hash,
        }
    except Exception as e:
        return {"success": False, "message": f"Failed to save baseline: {str(e)}"}


def verify_integrity(file_path: str) -> dict:
    """
    Verify a file's integrity against its stored baseline hash.

    Args:
        file_path: Path to the file.

    Returns:
        dict with 'success', 'message', 'is_intact', 'current_hash',
        'baseline_hash', and 'last_checked' keys.
    """
    if not os.path.isfile(file_path):
        return {"success": False, "message": f"File not found: {file_path}"}

    try:
        abs_path = os.path.abspath(file_path)
        baseline = _load_baseline()

        if abs_path not in baseline:
            return {
                "success": False,
                "message": "No baseline found for this file. Save a baseline first.",
                "is_intact": None,
            }

        current_hash = _hash_file_content(file_path)
        stored = baseline[abs_path]
        baseline_hash = stored["hash"]
        is_intact = current_hash == baseline_hash

        if is_intact:
            msg = "File integrity verified - NO modifications detected"
        else:
            msg = "WARNING: File has been modified since baseline was saved!"

        return {
            "success": True,
            "message": msg,
            "is_intact": is_intact,
            "current_hash": current_hash,
            "baseline_hash": baseline_hash,
            "last_checked": stored["timestamp"],
        }
    except Exception as e:
        return {"success": False, "message": f"Integrity check failed: {str(e)}"}
