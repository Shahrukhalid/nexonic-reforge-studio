"""AI Assistant multi-provider client supporting BYOK, streaming, and cancellation."""
from __future__ import annotations

import json
import logging
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator

log = logging.getLogger("reforge.ai.client")

PROVIDERS = {
    "openrouter": {
        "name": "OpenRouter",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "default_model": "anthropic/claude-3.5-sonnet",
        "format": "openai",
    },
    "openai": {
        "name": "OpenAI",
        "url": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-4o",
        "format": "openai",
    },
    "anthropic": {
        "name": "Anthropic",
        "url": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-3-5-sonnet-20241022",
        "format": "anthropic",
    },
    "gemini": {
        "name": "Google Gemini",
        "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "default_model": "gemini-2.0-flash",
        "format": "openai",
    },
    "local": {
        "name": "Local (Ollama / LocalAI)",
        "url": "http://localhost:11434/v1/chat/completions",
        "default_model": "llama3.2",
        "format": "openai",
    },
}


def _tls_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def stream_chat(
    provider_id: str,
    api_key: str,
    model: str,
    messages: list[dict],
    custom_url: str | None = None,
    stop_event: threading.Event | None = None,
    timeout: int = 60,
) -> Iterator[str]:
    """Stream chat completion tokens from selected provider with cancellation support."""
    prov = PROVIDERS.get(provider_id, PROVIDERS["openrouter"])
    url = custom_url or prov["url"]
    fmt = prov["format"]

    headers = {"Content-Type": "application/json"}
    if api_key:
        if fmt == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = f"Bearer {api_key}"

    if provider_id == "openrouter":
        headers["HTTP-Referer"] = "https://reforge.studio"
        headers["X-Title"] = "Nexonic ReForge Studio"

    # Build payload
    if fmt == "anthropic":
        system_content = ""
        user_msgs = []
        for m in messages:
            if m["role"] == "system":
                system_content += m["content"] + "\n\n"
            else:
                user_msgs.append({"role": m["role"], "content": m["content"]})

        payload = {
            "model": model or prov["default_model"],
            "messages": user_msgs,
            "max_tokens": 4096,
            "stream": True,
        }
        if system_content:
            payload["system"] = system_content.strip()
    else:
        payload = {
            "model": model or prov["default_model"],
            "messages": messages,
            "stream": True,
        }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    ctx = _tls_context() if url.startswith("https://") else None

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            buffer = ""
            for raw_line in resp:
                if stop_event and stop_event.is_set():
                    break
                line = raw_line.decode("utf-8", errors="replace")
                buffer += line
                while "\n" in buffer:
                    chunk_line, buffer = buffer.split("\n", 1)
                    chunk_line = chunk_line.strip()
                    if not chunk_line or chunk_line.startswith(":"):
                        continue
                    if chunk_line.startswith("data: "):
                        data_str = chunk_line[6:].strip()
                        if data_str == "[DONE]":
                            return
                        try:
                            parsed = json.loads(data_str)
                            if fmt == "anthropic":
                                typ = parsed.get("type")
                                if typ == "content_block_delta":
                                    delta = parsed.get("delta", {})
                                    if delta.get("type") == "text_delta":
                                        yield delta.get("text", "")
                            else:
                                choices = parsed.get("choices", [])
                                if choices:
                                    delta = choices[0].get("delta", {})
                                    content = delta.get("content", "")
                                    if content:
                                        yield content
                        except json.JSONDecodeError:
                            continue
    except urllib.error.HTTPError as err:
        err_msg = err.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"AI API Error (HTTP {err.code}): {err_msg}") from err
    except Exception as err:
        if stop_event and stop_event.is_set():
            return
        raise RuntimeError(f"Connection failed: {err}") from err
