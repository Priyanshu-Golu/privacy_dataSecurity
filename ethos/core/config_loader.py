"""
ethos.core.config_loader
========================
Reads and validates YAML configuration files or plain dicts.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Union

import yaml

from ethos.core.exceptions import ConfigError


def load_config(source: Union[str, Dict[str, Any], None]) -> Dict[str, Any]:
    """
    Load and return a config dict from various sources.

    Parameters
    ----------
    source : str, dict, or None
        - None       → returns empty dict (module uses its own defaults)
        - dict       → validated and returned as-is
        - str path   → loaded from YAML file at that path
        - preset name (no slashes) → looked up in the presets/ directory

    Returns
    -------
    dict
        Validated configuration dictionary.

    Raises
    ------
    ConfigError
        If the source is invalid or the YAML cannot be parsed.
    """
    if source is None:
        return {}

    if isinstance(source, dict):
        return source

    if isinstance(source, str):
        # Check if it's a preset name (no path separators, no .yaml extension)
        if not os.sep in source and "/" not in source and not source.endswith(".yaml"):
            resolved = _resolve_preset(source)
            if resolved is not None:
                return resolved
            # Fall through to try as a file path

        # Treat as a file path
        if not os.path.isfile(source):
            raise ConfigError(
                f"Config file not found: {source!r}",
                details={"path": source},
            )
        try:
            with open(source, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return data if data is not None else {}
        except yaml.YAMLError as exc:
            raise ConfigError(
                f"Failed to parse YAML config: {source!r}",
                details={"error": str(exc)},
            ) from exc

    raise ConfigError(
        f"Unsupported config source type: {type(source).__name__}",
        details={"source": repr(source)},
    )


def _resolve_preset(name: str) -> Dict[str, Any] | None:
    """
    Look up a named preset in the presets/ directory adjacent to this module.
    Returns None if the preset is not found (caller can try other sources).
    """
    # Locate presets relative to this file:
    # ethos/core/ → ethos/ → find ethos/privacy/config/presets/
    this_dir = os.path.dirname(os.path.abspath(__file__))
    ethos_dir = os.path.dirname(this_dir)
    preset_path = os.path.join(
        ethos_dir, "privacy", "config", "presets", f"{name}.yaml"
    )

    if not os.path.isfile(preset_path):
        return None

    try:
        with open(preset_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if data is not None else {}
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Failed to parse preset config {name!r}",
            details={"path": preset_path, "error": str(exc)},
        ) from exc
