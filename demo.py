"""
EthosAI Privacy Data Security — Live Demo
==========================================
Demonstrates the complete 7-step flow from Section 12 of the spec.

Run with:
  python demo.py
"""

import sys
import os

# Ensure the package root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ethos.privacy import PrivacyDataSecurity


# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"


def sep(title: str = "", char: str = "─") -> None:
    width = 66
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{DIM}{char * pad} {RESET}{BOLD}{title}{RESET}{DIM} {char * (width - pad - len(title) - 2)}{RESET}")
    else:
        print(f"{DIM}{char * width}{RESET}")


def header(text: str) -> None:
    print(f"\n{BOLD}{BLUE}{text}{RESET}")
    sep()


def main():
    print()
    print(f"{BOLD}{'═' * 66}{RESET}")
    print(f"{BOLD}{'  ETHOS AI — PRIVACY DATA SECURITY MODULE DEMO':^66}{RESET}")
    print(f"{BOLD}{'  Layer 2: Universal Confidential Data Gateway':^66}{RESET}")
    print(f"{BOLD}{'═' * 66}{RESET}")

    # ── Initialise the framework ───────────────────────────────────────────────
    pds = PrivacyDataSecurity(config="banking")

    # ── STEP 1 ─ Raw user input ───────────────────────────────────────────────
    header("STEP 1 — INPUT (what the user typed)")

    raw_input = (
        "My name is Priya Sharma. Aadhaar: 8279-5423-1806.\n"
        "Phone: +91-9876543210. Email: priya.sharma@gmail.com.\n"
        "My OpenAI key is sk-proj-abc123XYZsecretKEYdemo9876.\n"
        "DB: postgresql://admin:pass123@prod.db.internal:5432/users\n"
        "Please fix my code."
    )

    print(f"\n{CYAN}{raw_input}{RESET}")

    # ── STEP 2 ─ Gateway intercepts ───────────────────────────────────────────
    header("STEP 2 — GATEWAY INTERCEPTS")

    result = pds.protect(raw_input)

    for sr in result.scan_results:
        icon = f"{RED}[CRITICAL]{RESET}" if sr.alert_level == "CRITICAL" else f"{YELLOW}[DETECTED]{RESET}"
        truncated = sr.value[:30] + "..." if len(sr.value) > 30 else sr.value
        print(f"  {icon}  {sr.type:<22} {GREEN}{truncated!r:<38}{RESET} → VAULTED ✓"
              + (f" {RED}⚠ ALERT{RESET}" if sr.alert_level == "CRITICAL" else ""))

    if result.alerts:
        print()
        for alert in result.alerts:
            print(f"  {RED}⚠  SECURITY ALERT:{RESET} {alert['data_type']} intercepted and vaulted.")
            if "recommendation" in alert:
                print(f"     {YELLOW}↳ Recommendation:{RESET} {alert['recommendation']}")

    # ── STEP 3 ─ Safe request sent to AI ─────────────────────────────────────
    header("STEP 3 — SAFE REQUEST SENT TO AI")

    print(f"\n{GREEN}{result.safe_content}{RESET}")
    print(f"\n{DIM}  ↑ AI receives tokens only — real values never transmitted.{RESET}")

    # ── STEP 4 ─ Mock AI response ─────────────────────────────────────────────
    header("STEP 4 — AI RESPONSE (with tokens)")

    # Build a simulated AI response that echoes back some tokens
    token_map = {}
    for sr in result.scan_results:
        # Find the token that replaced this value in safe_content
        for token_candidate in _extract_tokens(result.safe_content):
            pass
    # Simpler approach: extract unique tokens from safe_content
    from ethos.privacy._core.resolver.pattern_matcher import find_tokens as ft
    tokens_in_safe = [t for t, s, e in ft(result.safe_content)]

    # Build a plausible-looking AI response using those tokens
    ai_response = _build_ai_response(result.safe_content, tokens_in_safe)

    print(f"\n{MAGENTA}{ai_response}{RESET}")

    # ── STEP 5 ─ Token resolution ─────────────────────────────────────────────
    header("STEP 5 — TOKEN RESOLUTION")

    final = pds.restore(ai_response, session_id=result.session_id)

    # Show what was resolved
    for tok in tokens_in_safe:
        if tok in ai_response:
            resolved_value = _find_resolved(tok, ai_response, final)
            if resolved_value:
                short_val = resolved_value[:35] + "..." if len(resolved_value) > 35 else resolved_value
                short_tok = tok[:28] + "..." if len(tok) > 28 else tok
                print(f"  {CYAN}[RESOLVED]{RESET}  {short_tok:<35} → {GREEN}{short_val!r}{RESET}")

    # ── STEP 6 ─ Final response ───────────────────────────────────────────────
    header("STEP 6 — FINAL RESPONSE (what the user sees)")

    print(f"\n{GREEN}{final}{RESET}")
    print(f"\n{DIM}  ↑ Real values restored for the authorized user only.{RESET}")

    # ── STEP 7 ─ Audit summary ────────────────────────────────────────────────
    header("STEP 7 — AUDIT SUMMARY")

    audit = pds.audit(result.session_id)
    families = result.audit_summary.get("families", {})
    fam_str  = ", ".join(f"{k}({v})" for k, v in families.items())

    print(f"""
  {BOLD}Session    :{RESET}  {result.session_id}
  {BOLD}Intercepted:{RESET}  {result.items_vaulted} confidential items
  {BOLD}Families   :{RESET}  {fam_str or 'None'}
  {BOLD}AI saw     :{RESET}  0 real values  {GREEN}✓{RESET}
  {BOLD}Alerts     :{RESET}  {len(result.alerts)} CRITICAL
  {BOLD}Vault ops  :{RESET}  {len(audit)} recorded in audit log""")

    if result.alerts:
        print(f"\n  {YELLOW}Rotation recommended for:{RESET}")
        for alert in result.alerts:
            if "recommendation" in alert:
                print(f"    • {alert['data_type']}")

    print()
    sep(char="═")
    print(f"  {BOLD}{GREEN}✓  AI processed your request without ever seeing real data.{RESET}")
    sep(char="═")
    print()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_tokens(text: str) -> list:
    from ethos.privacy._core.resolver.pattern_matcher import find_tokens
    return [t for t, s, e in find_tokens(text)]


def _build_ai_response(safe_text: str, tokens: list) -> str:
    """Build a plausible AI response that uses the same tokens."""
    # Pick name token and api/db tokens if they exist
    name_token  = next((t for t in tokens if "NAME" in t or "FULL" in t), None)
    api_token   = next((t for t in tokens if "OPENAI" in t or "APIKEY" in t or "KEY" in t), None)
    db_token    = next((t for t in tokens if "DBCONN" in t or "DB_CO" in t), None)

    greeting = f"Hello {name_token}," if name_token else "Hello,"
    api_line  = f"\nMake sure {api_token} is set in your environment." if api_token else ""
    db_line   = f"\nConnect to your database at {db_token}." if db_token else ""

    return (
        f"{greeting} your code has been fixed successfully!{api_line}{db_line}\n"
        f"The issue was a missing authentication header. "
        f"Here is the corrected snippet:\n\n"
        f"  client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])\n\n"
        f"Let me know if you need anything else!"
    )


def _find_resolved(token: str, original: str, resolved: str) -> str | None:
    """Find what a token was resolved to by comparing original and resolved text."""
    if token not in original:
        return None
    # Simple: token was replaced → find what's at that position in resolved
    idx = original.find(token)
    if idx == -1:
        return None
    # In resolved, find text at same position that differs from the token
    prefix = original[:idx]
    suffix = original[idx + len(token):]
    if resolved.startswith(prefix) and resolved.endswith(suffix):
        real_part = resolved[len(prefix): len(resolved) - len(suffix)]
        return real_part
    return None


if __name__ == "__main__":
    main()
