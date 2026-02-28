"""
ethos.core.logger
=================
Structured audit logger for the EthosAI framework.
Emits JSON-style log entries with timestamps and context.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


class StructuredLogger:
    """
    Lightweight structured logger that records operations as JSON-style dicts.

    Two output modes:
      console: prints formatted log lines to stderr
      silent:  stores entries in memory only (default for framework use)

    Usage
    -----
    logger = StructuredLogger(name="vault", console=True)
    logger.log("store", token="⟨TKN_AADHAAR_A3F2B7C1⟩", session="sess_abc")
    entries = logger.get_entries()
    """

    def __init__(
        self,
        name: str = "ethos",
        console: bool = False,
        max_entries: int = 10_000,
    ):
        self.name       = name
        self.console    = console
        self.max_entries = max_entries
        self._entries: List[Dict[str, Any]] = []

    def log(
        self,
        operation: str,
        level: str = "INFO",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Record a structured log entry.

        Parameters
        ----------
        operation : str
            Short operation name (e.g. "store", "retrieve", "scan").
        level : str
            Log level: DEBUG / INFO / WARNING / ERROR / CRITICAL.
        **kwargs
            Additional key-value pairs to include in the entry.

        Returns
        -------
        dict
            The log entry that was recorded.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "logger":    self.name,
            "level":     level,
            "operation": operation,
            **kwargs,
        }

        # Trim oldest entries if cap exceeded
        if len(self._entries) >= self.max_entries:
            self._entries = self._entries[-(self.max_entries // 2):]

        self._entries.append(entry)

        if self.console:
            self._print_entry(entry)

        return entry

    def warn(self, operation: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log(operation, level="WARNING", **kwargs)

    def error(self, operation: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log(operation, level="ERROR", **kwargs)

    def critical(self, operation: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log(operation, level="CRITICAL", **kwargs)

    def get_entries(
        self,
        operation: Optional[str] = None,
        level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return stored log entries, optionally filtered.

        Parameters
        ----------
        operation : str or None
            Filter by operation name.
        level : str or None
            Filter by log level.
        """
        entries = self._entries
        if operation:
            entries = [e for e in entries if e.get("operation") == operation]
        if level:
            entries = [e for e in entries if e.get("level") == level]
        return list(entries)

    def clear(self) -> None:
        """Remove all stored log entries."""
        self._entries.clear()

    def _print_entry(self, entry: Dict[str, Any]) -> None:
        """Pretty-print a log entry to stderr."""
        ts  = entry.get("timestamp", "")[:19]
        lvl = entry.get("level", "INFO").ljust(8)
        op  = entry.get("operation", "")
        extras = {
            k: v for k, v in entry.items()
            if k not in ("timestamp", "logger", "level", "operation")
        }
        extra_str = " " + json.dumps(extras) if extras else ""
        print(
            f"[{ts}] {lvl} [{self.name}] {op}{extra_str}",
            file=sys.stderr,
            flush=True,
        )

    def __repr__(self) -> str:
        return (
            f"StructuredLogger(name={self.name!r}, "
            f"entries={len(self._entries)}, "
            f"console={self.console})"
        )
