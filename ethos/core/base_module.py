"""
ethos.core.base_module
======================
Abstract base class that all EthosAI layer modules must inherit from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from ethos.core.data_types import DataRecord, ProcessedRecord


class BaseModule(ABC):
    """
    Abstract base class for all EthosAI pipeline layer modules.

    Every layer (Privacy, Fairness, Model, Transparency, etc.) must
    inherit this class and implement the run() method.

    Usage
    -----
    class MyLayer(BaseModule):
        layer_name    = "my_layer"
        layer_version = "1.0.0"
        depends_on    = []
        provides_to   = ["other_layer"]

        def run(self, record: DataRecord) -> ProcessedRecord:
            ...
    """

    # ── Layer Manifest (must be set by subclass) ──────────────────────────────
    layer_name:    str       = "unnamed"
    layer_version: str       = "0.0.0"
    depends_on:    list[str] = []
    provides_to:   list[str] = []

    def __init__(self, config: Any = None):
        """
        Parameters
        ----------
        config : str, dict, or None
            Configuration for this module. A str is treated as a
            preset name or YAML file path. A dict is used directly.
        """
        self._config_raw = config
        self._initialized = False

    def initialize(self) -> "BaseModule":
        """
        Perform any lazy initialization (load keys, open connections, etc.).
        Called automatically by run() if not already done.
        Returns self for chaining.
        """
        self._initialized = True
        return self

    @abstractmethod
    def run(self, record: DataRecord) -> ProcessedRecord:
        """
        Process a DataRecord and return a ProcessedRecord.

        Parameters
        ----------
        record : DataRecord
            Input data wrapped in the framework's data type.

        Returns
        -------
        ProcessedRecord
            The processed result with safe_content and metadata.
        """
        ...

    def get_manifest(self) -> Dict[str, Any]:
        """Return the layer manifest as a plain dict."""
        return {
            "layer_name":    self.layer_name,
            "layer_version": self.layer_version,
            "depends_on":    self.depends_on,
            "provides_to":   self.provides_to,
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"layer={self.layer_name!r}, "
            f"version={self.layer_version!r})"
        )
