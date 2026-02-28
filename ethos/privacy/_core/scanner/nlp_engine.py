"""
ethos.privacy._core.scanner.nlp_engine
=======================================
Strategy E: NLP-based context-aware detection using spaCy.

Detects confidential data by UNDERSTANDING what text means, not just
what it looks like. Uses spaCy Named Entity Recognition (NER) to find:

  PERSON   → Full names (PII / HIGH)
  DATE     → Dates that could be DOB or schedules (PII / HIGH)
  GPE/LOC  → Countries, cities, addresses (PII / HIGH)
  ORG      → Company names in sensitive context (BUSINESS / HIGH)
  MONEY    → Financial amounts (FINANCIAL / HIGH)
  CARDINAL → Numeric values near financial/identity context (varies)

Why NLP instead of regex?
  Regex: "Priya Sharma" → ONLY detected if preceded by "name:" keyword
  NLP:   "call Priya Sharma tomorrow" → DETECTED as a PERSON entity

CONFIDENCE DESIGN:
  spaCy NER confidence alone would produce too many false positives
  (e.g., "Apple" as ORG in a food context).
  We apply context boosting: +0.15 if a sensitive keyword nearby,
  and family-specific base confidences to stay accurate.

FALLBACK:
  If spaCy is not installed or the model is missing, the engine
  returns an empty list (never crashes). The other 4 strategies
  continue working without NLP.
"""

from __future__ import annotations

import regex
from typing import Any, Dict, List, Optional

from ethos.core.data_types import AlertLevel, DataFamily, ScanResult


# ── NER label → (type_name, family, base_confidence, alert_level) ─────────────
_ENTITY_MAP: Dict[str, tuple] = {
    "PERSON":      ("PERSON_NAME",    DataFamily.PII,       0.78, AlertLevel.HIGH),
    "DATE":        ("DATE_ENTITY",    DataFamily.PII,       0.65, AlertLevel.HIGH),
    "GPE":         ("LOCATION",       DataFamily.PII,       0.60, AlertLevel.HIGH),
    "LOC":         ("LOCATION",       DataFamily.PII,       0.62, AlertLevel.HIGH),
    "FAC":         ("LOCATION",       DataFamily.PII,       0.58, AlertLevel.HIGH),
    "ORG":         ("ORG_NAME",       DataFamily.BUSINESS,  0.55, AlertLevel.HIGH),
    "MONEY":       ("FINANCIAL_AMNT", DataFamily.FINANCIAL, 0.72, AlertLevel.HIGH),
    "CARDINAL":    ("NUMERIC_VALUE",  DataFamily.PII,       0.50, AlertLevel.HIGH),
    "ORDINAL":     ("NUMERIC_VALUE",  DataFamily.PII,       0.45, AlertLevel.HIGH),
    "NORP":        ("NATIONALITY",    DataFamily.PII,       0.50, AlertLevel.HIGH),
    "EMAIL":       ("EMAIL",          DataFamily.PII,       0.92, AlertLevel.HIGH),
    "PHONE":       ("PHONE",          DataFamily.PII,       0.90, AlertLevel.HIGH),
}

# ── Minimum confidence to emit a ScanResult ───────────────────────────────────
_EMIT_THRESHOLD = 0.60

# ── Context keywords that boost confidence (within 120 chars of the entity) ───
_BOOST_KEYWORDS = regex.compile(
    r"\b(name|patient|customer|client|user|account|owner|contact|"
    r"dob|birth|address|email|phone|mobile|salary|payment|"
    r"amount|transfer|balance|ssn|aadhaar|pan|passport|id)\b",
    regex.IGNORECASE,
)

# ── Noise filter: skip very short generic words even if spaCy labels them ─────
_MIN_ENTITY_LENGTH = 3

# ── Labels to skip entirely (too noisy without strong context) ────────────────
_SKIP_WITHOUT_CONTEXT = {"ORG", "CARDINAL", "ORDINAL", "NORP"}


class NLPEngine:
    """
    spaCy-powered NLP context-aware scanner.

    Usage
    -----
    engine = NLPEngine()
    results = engine.scan("Please transfer ₹50,000 to Priya Sharma's account.")

    Falls back to empty results if spaCy / model is unavailable.
    """

    def __init__(
        self,
        model: str = "en_core_web_sm",
        enabled: bool = True,
        min_confidence: float = _EMIT_THRESHOLD,
        context_boost: float = 0.15,
        skip_labels: Optional[List[str]] = None,
    ):
        self.enabled        = enabled
        self.min_confidence = min_confidence
        self.context_boost  = context_boost
        self._skip_without_context = set(skip_labels or _SKIP_WITHOUT_CONTEXT)
        self._nlp           = None
        self._model_name    = model
        self._available     = False

        if enabled:
            self._load_model(model)

    def _load_model(self, model: str) -> None:
        """Attempt to load the spaCy model. Silently degrades if unavailable."""
        try:
            import spacy
            self._nlp       = spacy.load(model)
            self._available = True
        except ImportError:
            _warn("spaCy is not installed. NLP engine disabled. "
                  "Install with: pip install spacy && python -m spacy download en_core_web_sm")
        except OSError:
            _warn(f"spaCy model '{model}' not found. NLP engine disabled. "
                  f"Download with: python -m spacy download {model}")

    @property
    def available(self) -> bool:
        """True if spaCy and the model loaded successfully."""
        return self._available

    def scan(
        self,
        text: str,
        enabled_families: Optional[List[str]] = None,
        existing_spans: Optional[List[tuple]] = None,
    ) -> List[ScanResult]:
        """
        Run NER on the text and return ScanResults for detected entities.

        Parameters
        ----------
        text : str
            Raw text to scan.
        enabled_families : list[str] or None
            If provided, filter results to these families only.
        existing_spans : list of (start, end) or None
            Character spans already detected by other engines.
            NLP results overlapping these are SKIPPED (deduplication).

        Returns
        -------
        list[ScanResult]
        """
        if not self._available or not text or not text.strip():
            return []

        existing = existing_spans or []
        results: List[ScanResult] = []

        doc = self._nlp(text)

        for ent in doc.ents:
            label = ent.label_

            if label not in _ENTITY_MAP:
                continue

            value = ent.text.strip()
            if len(value) < _MIN_ENTITY_LENGTH:
                continue

            type_name, family, base_conf, alert = _ENTITY_MAP[label]

            # Filter by enabled families
            if enabled_families and family not in enabled_families:
                continue

            # Build context window (±120 chars)
            ctx_start = max(0, ent.start_char - 120)
            ctx_end   = min(len(text), ent.end_char + 120)
            context   = text[ctx_start:ctx_end]

            # Context boost for high-signal labels
            has_context = bool(_BOOST_KEYWORDS.search(context))

            # Skip noisy labels with no context confirmation
            if label in self._skip_without_context and not has_context:
                continue

            confidence = base_conf
            if has_context:
                confidence = min(1.0, confidence + self.context_boost)

            if confidence < self.min_confidence:
                continue

            # Dedup: skip if already caught by another engine
            if _overlaps(ent.start_char, ent.end_char, existing):
                continue

            snippet = context.replace("\n", " ")

            results.append(ScanResult(
                value           = value,
                type            = type_name,
                family          = family,
                position        = (ent.start_char, ent.end_char),
                confidence      = confidence,
                alert_level     = alert,
                strategy        = "NLP",
                context_snippet = snippet,
            ))

        return results

    def __repr__(self) -> str:
        status = f"model={self._model_name}" if self._available else "unavailable"
        return f"NLPEngine({status})"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _overlaps(start: int, end: int, spans: List[tuple]) -> bool:
    """Return True if (start, end) overlaps any span in spans."""
    for s, e in spans:
        if not (end <= s or start >= e):
            return True
    return False


def _warn(msg: str) -> None:
    import warnings
    warnings.warn(f"[EthosAI NLPEngine] {msg}", RuntimeWarning, stacklevel=3)
