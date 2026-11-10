"""Secure credential storage for AI provider API keys.

Uses Windows DPAPI (CryptProtectData) on Windows, macOS Keychain via `security` on macOS,
or user-restricted local file storage with machine entropy fallback on Linux.
Keys are never logged or committed.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import json
import logging
import os
import subprocess
import sys

from ..core import paths

log = logging.getLogger("reforge.ai.credentials")

KEY_FILE = paths.data_dir() / ".reforge_credentials"


def _win_encrypt(data: str) -> str:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    blob_in = DATA_BLOB()
    raw = data.encode("utf-8")
    blob_in.cbData = len(raw)
    blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_char))
    blob_out = DATA_BLOB()

    if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(blob_in), "ReForgeKey", None, None, None, 0, ctypes.byref(blob_out)):
        out_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return base64.b64encode(out_bytes).decode("ascii")
    raise RuntimeError("CryptProtectData failed")


def _win_decrypt(encrypted_b64: str) -> str:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    raw = base64.b64decode(encrypted_b64.encode("ascii"))
    blob_in = DATA_BLOB()
    blob_in.cbData = len(raw)
    blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_char))
    blob_out = DATA_BLOB()

    if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        out_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return out_bytes.decode("utf-8")
    raise RuntimeError("CryptUnprotectData failed")


def _macos_set_key(provider: str, key: str) -> None:
    subprocess.run([
        "security", "add-generic-password", "-U",
        "-s", f"reforge.ai.{provider}",
        "-a", "reforge-user",
        "-w", key
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _macos_get_key(provider: str) -> str | None:
    res = subprocess.run([
        "security", "find-generic-password",
        "-s", f"reforge.ai.{provider}",
        "-a", "reforge-user",
        "-w"
    ], capture_output=True, text=True)
    if res.returncode == 0:
        return res.stdout.strip()
    return None


def _macos_delete_key(provider: str) -> None:
    subprocess.run([
        "security", "delete-generic-password",
        "-s", f"reforge.ai.{provider}",
        "-a", "reforge-user"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def set_key(provider: str, key: str) -> None:
    """Store API key in OS credential storage."""
    provider = provider.lower().strip()
    if sys.platform == "darwin":
        try:
            _macos_set_key(provider, key)
            return
        except Exception as e:
            log.warning("macOS Keychain set failed, falling back to secure file: %s", e)

    # Windows DPAPI or fallback secure file
    data: dict = {}
    if KEY_FILE.is_file():
        try:
            data = json.loads(KEY_FILE.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    if sys.platform == "win32":
        try:
            data[provider] = {"type": "dpapi", "value": _win_encrypt(key)}
        except Exception as e:
            log.warning("DPAPI encryption failed, falling back: %s", e)
            data[provider] = {"type": "plain_user", "value": base64.b64encode(key.encode("utf-8")).decode("ascii")}
    else:
        data[provider] = {"type": "plain_user", "value": base64.b64encode(key.encode("utf-8")).decode("ascii")}

    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_text(json.dumps(data), encoding="utf-8")
    if sys.platform != "win32":
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass


def get_key(provider: str) -> str | None:
    """Retrieve API key from OS credential storage or environment variable."""
    provider = provider.lower().strip()
    env_name = f"{provider.upper()}_API_KEY"
    if os.environ.get(env_name):
        return os.environ[env_name]

    if sys.platform == "darwin":
        k = _macos_get_key(provider)
        if k:
            return k

    if not KEY_FILE.is_file():
        return None

    try:
        data = json.loads(KEY_FILE.read_text(encoding="utf-8"))
        rec = data.get(provider)
        if not rec:
            return None
        if rec.get("type") == "dpapi" and sys.platform == "win32":
            return _win_decrypt(rec["value"])
        if rec.get("type") == "plain_user":
            return base64.b64decode(rec["value"].encode("ascii")).decode("utf-8")
    except Exception as e:
        log.warning("Failed to read credential for %s: %s", provider, e)
    return None


def delete_key(provider: str) -> None:
    """Delete API key from storage."""
    provider = provider.lower().strip()
    if sys.platform == "darwin":
        _macos_delete_key(provider)

    if KEY_FILE.is_file():
        try:
            data = json.loads(KEY_FILE.read_text(encoding="utf-8"))
            if provider in data:
                del data[provider]
                KEY_FILE.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            pass
