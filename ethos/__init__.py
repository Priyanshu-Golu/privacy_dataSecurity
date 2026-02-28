"""
EthosAI Framework
=================
A comprehensive ethical AI framework with privacy, fairness, transparency,
and safety layers.

Layer 2: Privacy Data Security — intercepts confidential data before AI sees it.
"""

__version__ = "1.0.0"
__author__ = "EthosAI Framework"

# Lazy import to avoid circular dependencies
def __getattr__(name):
    if name == "PrivacyDataSecurity":
        from ethos.privacy import PrivacyDataSecurity
        return PrivacyDataSecurity
    raise AttributeError(f"module 'ethos' has no attribute {name!r}")


__all__ = [
    "__version__",
]
