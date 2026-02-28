"""ethos.core — Foundation layer for all EthosAI modules."""

from ethos.core.data_types import (
    DataRecord,
    ProcessedRecord,
    AuditEntry,
    ScanResult,
    ProtectResult,
)
from ethos.core.exceptions import (
    VaultAccessError,
    ConfidentialDataError,
    ConfigError,
    TokenExpiredError,
    ScannerError,
)
from ethos.core.base_module import BaseModule
from ethos.core.base_pipeline import BasePipeline
from ethos.core.config_loader import load_config
from ethos.core.logger import StructuredLogger

__all__ = [
    "DataRecord",
    "ProcessedRecord",
    "AuditEntry",
    "ScanResult",
    "ProtectResult",
    "VaultAccessError",
    "ConfidentialDataError",
    "ConfigError",
    "TokenExpiredError",
    "ScannerError",
    "BaseModule",
    "BasePipeline",
    "load_config",
    "StructuredLogger",
]
