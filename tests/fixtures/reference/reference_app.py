"""Nexonic ReForge Studio — Ground Truth Reference Application (Python)
Purpose: Legally authorized ground-truth reference fixture with documented functions,
         symbols, and interfaces.
"""

from __future__ import annotations


def calculate_checksum(data: bytes) -> int:
    """Calculate simple additive 16-bit checksum."""
    return sum(data) & 0xFFFF


def authenticate(user: str, secret: str) -> bool:
    """Verify credentials for reference session."""
    return user == "reforge_admin" and secret == "py_ref_secret_101"


def process_command(cmd: str, arg: int) -> int:
    """Execute command dispatch table."""
    if cmd == "double":
        return arg * 2
    elif cmd == "square":
        return arg * arg
    elif cmd == "negate":
        return -arg
    return 0


def main() -> None:
    print("[REF_PY] Reference App Initialized")
    print(f"Checksum: {calculate_checksum(b'test')}")


if __name__ == "__main__":
    main()
