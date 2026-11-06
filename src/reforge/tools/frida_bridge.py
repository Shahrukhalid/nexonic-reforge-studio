"""Frida integration.

Device discovery only. Spawning or attaching runs the target, which ReForge refuses
until a verified isolated runtime exists (dynamic analysis is disabled by design).
"""
from __future__ import annotations

REASON = ("Dynamic instrumentation runs the target. ReForge only allows it inside a verified isolated "
          "runtime, which is not available yet, so Frida spawn/attach is disabled.")


class DynamicAnalysisDisabled(RuntimeError):
    pass


def info() -> dict | None:
    try:
        import frida
    except ImportError:
        return None
    return {"version": frida.__version__}


def devices() -> list[dict]:
    """List Frida devices (local, remote, USB). Nothing is executed or attached."""
    import frida
    return [{"id": d.id, "name": d.name, "type": d.type} for d in frida.enumerate_devices()]


def instrument(*_args, **_kwargs):
    raise DynamicAnalysisDisabled(REASON)
