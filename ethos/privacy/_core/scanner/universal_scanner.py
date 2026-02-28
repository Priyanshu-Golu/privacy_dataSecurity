"""
ethos.privacy._core.scanner.universal_scanner
============================================
Universal Scanner — orchestrates all five detection strategies.
Single entry point: scanner.scan(text_or_dict, config) → List[ScanResult]

Strategies:
  A: Pattern   — regex + Luhn/Verhoeff validators
  B: Entropy   — Shannon entropy for unknown secrets
  C: Context   — key=value assignments + proximity boost
  D: Structure — pasted .env / JSON / YAML blocks
  E: NLP       — spaCy Named Entity Recognition (PERSON, DATE, GPE, …)

All strategy results are merged and deduplicated before returning.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from ethos.core.data_types import DataFamily, ScanResult
from ethos.privacy._core.scanner.pattern_engine import PatternEngine
from ethos.privacy._core.scanner.entropy_engine import EntropyEngine
from ethos.privacy._core.scanner.context_engine import ContextEngine
from ethos.privacy._core.scanner.structure_engine import StructureEngine
from ethos.privacy._core.scanner.nlp_engine import NLPEngine


class UniversalScanner:
    """
    Orchestrates all detection strategies and returns a merged,
    deduplicated list of ScanResults.

    Usage
    -----
    scanner = UniversalScanner(config={"scanner": {...}})
    results = scanner.scan("My Aadhaar is 4512-8934-2301...")
    results = scanner.scan({"email": "user@example.com", "note": "..."})
    """

    def __init__(self, config: Dict[str, Any] = None):
        cfg = (config or {}).get("scanner", {})

        self.enabled_families: Optional[List[str]] = cfg.get("families")
        sensitivity = cfg.get("sensitivity", "medium")
        safe_fields: List[str] = cfg.get("safe_fields", [])

        entropy_cfg = cfg.get("entropy", {})
        entropy_enabled = entropy_cfg.get("enabled", True)

        nlp_cfg = cfg.get("nlp", {})
        nlp_enabled = nlp_cfg.get("enabled", True)
        nlp_model   = nlp_cfg.get("model", "en_core_web_sm")
        nlp_min_conf = float(nlp_cfg.get("min_confidence", 0.60))
        nlp_context_boost = float(nlp_cfg.get("context_boost", 0.15))

        # Initialise sub-engines
        self._pattern_engine = PatternEngine(
            sensitivity=sensitivity,
            enabled_families=self.enabled_families,
        )
        self._entropy_engine = EntropyEngine(
            threshold=entropy_cfg.get("threshold", 3.5),
            min_length=entropy_cfg.get("min_length", 16),
            max_length=entropy_cfg.get("max_length", 512),
            require_context_word=entropy_cfg.get("require_context_word", True),
            sensitivity=sensitivity,
        ) if entropy_enabled else None

        self._context_engine   = ContextEngine()
        self._structure_engine = StructureEngine(
            enabled_families=self.enabled_families,
        )
        self._nlp_engine = NLPEngine(
            model          = nlp_model,
            enabled        = nlp_enabled,
            min_confidence = nlp_min_conf,
            context_boost  = nlp_context_boost,
        )

        self._safe_fields = [f.lower() for f in safe_fields]


    def scan(self, content: Union[str, Dict[str, Any]]) -> List[ScanResult]:
        """
        Detect all confidential data in text or a dict.

        Parameters
        ----------
        content : str or dict
            Raw user input string, or a dict of field→value pairs.

        Returns
        -------
        list[ScanResult]
            Deduplicated, sorted scan results from all engines.
        """
        if isinstance(content, dict):
            return self._scan_dict(content)
        return self._scan_text(str(content))

    # ── Text scanning ─────────────────────────────────────────────────────────

    def _scan_text(self, text: str) -> List[ScanResult]:
        all_results: List[ScanResult] = []

        # Strategy A: Pattern engine
        pattern_results = self._pattern_engine.scan(text)
        all_results.extend(pattern_results)

        # Strategy B: Entropy engine
        if self._entropy_engine:
            entropy_results = self._entropy_engine.scan(text)
            all_results.extend(entropy_results)

        # Strategy C: Context engine — boost existing results
        all_results = self._context_engine.boost(all_results, text)

        # Strategy C: Context engine — find extra key=value matches
        context_new = self._context_engine.scan(text, self.enabled_families)
        all_results.extend(context_new)

        # Strategy D: Structure engine
        struct_results = self._structure_engine.scan(text)
        all_results.extend(struct_results)

        # Strategy E: NLP engine — entity-based context detection
        # Pass existing spans so NLP does not duplicate already-found items
        existing_spans = [
            r.position for r in all_results if r.position is not None
        ]
        nlp_results = self._nlp_engine.scan(
            text,
            enabled_families=self.enabled_families,
            existing_spans=existing_spans,
        )
        all_results.extend(nlp_results)

        return _deduplicate(all_results)

    # ── Dict scanning ─────────────────────────────────────────────────────────

    def _scan_dict(self, data: Dict[str, Any]) -> List[ScanResult]:
        all_results: List[ScanResult] = []

        for field_name, field_value in data.items():
            # Skip safe fields
            if field_name.lower() in self._safe_fields:
                continue

            if isinstance(field_value, dict):
                # Recurse into nested dicts
                for r in self._scan_dict(field_value):
                    all_results.append(r)
                continue

            value_str = str(field_value)
            field_results = self._scan_text(value_str)

            # Annotate each result with the field name
            for r in field_results:
                r.field_name = field_name
                # Adjust position to be relative to field value, not document
                # (position remains relative to value_str)

            all_results.extend(field_results)

        return _deduplicate(all_results)


# ── Deduplication ─────────────────────────────────────────────────────────────

def _deduplicate(results: List[ScanResult]) -> List[ScanResult]:
    """
    Remove duplicate and overlapping ScanResults.
    Rule: same value → keep highest confidence occurrence.
    Overlapping positions → keep highest confidence.
    """
    # Step 1: For identical values, keep highest confidence
    by_value: Dict[str, ScanResult] = {}
    for r in results:
        key = r.value
        if key not in by_value or r.confidence > by_value[key].confidence:
            by_value[key] = r

    # Step 2: Re-sort by position and remove positional overlaps
    unique = list(by_value.values())
    unique.sort(key=lambda r: (r.position[0] if r.position else 0, -r.confidence))

    kept: List[ScanResult] = []
    last_end = -1

    for r in unique:
        if r.position is None:
            kept.append(r)
            continue
        start, end = r.position
        if start >= last_end:
            kept.append(r)
            last_end = end

    return kept
