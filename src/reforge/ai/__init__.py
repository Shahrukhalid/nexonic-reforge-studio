"""AI Assistant package for Nexonic ReForge Studio."""
from __future__ import annotations

from .client import PROVIDERS, stream_chat
from .context import SYSTEM_PROMPT, build_project_context
from .credentials import delete_key, get_key, set_key

__all__ = [
    "PROVIDERS",
    "SYSTEM_PROMPT",
    "build_project_context",
    "delete_key",
    "get_key",
    "set_key",
    "stream_chat",
]
