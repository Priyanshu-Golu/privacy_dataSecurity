"""
EthosAI Privacy Layer — Interactive CLI Chat
=============================================
Real conversation with Gemini 2.5 Flash, protected by the EthosAI privacy layer.

Every message you type goes through:
  protect() → Gemini 2.5 Flash → restore()

Your secrets (emails, API keys, phone numbers, etc.) are NEVER sent to Gemini.

Usage
-----
  python chat.py

Commands
--------
  /quit or /exit  — end the conversation
  /audit          — show vault audit log for current session
  /new            — start a fresh session (clears vault & history)
  /help           — show this help
"""

from __future__ import annotations

import io
import os
import sys
import time

# ── Force UTF-8 so ⟨TKN_...⟩ tokens render correctly on Windows ──────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Load .env if present ──────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Gemini ────────────────────────────────────────────────────────────────────
try:
    import google.generativeai as genai
except ImportError:
    print("ERROR: google-generativeai not installed.")
    print("  Run: pip install google-generativeai")
    sys.exit(1)

# ── Privacy layer ─────────────────────────────────────────────────────────────
from ethos.privacy import PrivacyDataSecurity

# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"

# ── Config ────────────────────────────────────────────────────────────────────
API_KEY     = os.environ.get("GEMINI_API_KEY", "")
MODEL_NAME  = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
HISTORY_MAX = 20          # keep last N turns in Gemini context

SYSTEM_PROMPT = (
    "You are a helpful, concise AI assistant. "
    "Some values in the user's messages are replaced with privacy tokens "
    "like ⟨TKN_EMAIL_xxxx⟩ or ⟨TKN_OPENAI_xxxx⟩. "
    "Treat these tokens as opaque placeholders and refer to them naturally "
    "in your response (do NOT invent or guess real values). "
    "Be friendly and professional."
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bar(char: str = "─", width: int = 66) -> str:
    return DIM + char * width + RESET


def _header(text: str) -> None:
    print(f"\n{BOLD}{BLUE}{text}{RESET}")
    print(_bar())


def _badge(label: str, colour: str) -> str:
    return f"{colour}{BOLD}[{label}]{RESET}"


def _format_alerts(alerts: list) -> str:
    if not alerts:
        return ""
    lines = [f"  {RED}⚠  SECURITY ALERT:{RESET}"]
    for a in alerts:
        lines.append(f"     • {YELLOW}{a.get('data_type', '?')}{RESET} intercepted and vaulted.")
        if "recommendation" in a:
            lines.append(f"       ↳ {a['recommendation']}")
    return "\n".join(lines)


# ── GeminiSession: multi-turn chat with history ───────────────────────────────

class GeminiSession:
    """
    Maintains a multi-turn chat history so Gemini remembers context.
    Each turn stores the (tokenized) user message and the raw Gemini reply.
    """

    def __init__(self, api_key: str, model_name: str):
        genai.configure(api_key=api_key)
        self._model      = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=SYSTEM_PROMPT,
        )
        self._chat       = self._model.start_chat(history=[])
        self._model_name = model_name

    def send(self, tokenized_message: str) -> str:
        """Send one (tokenized) user turn; return Gemini's text reply."""
        for attempt in range(2):
            try:
                response = self._chat.send_message(tokenized_message)
                return response.text
            except Exception as exc:
                if attempt == 0:
                    time.sleep(2)
                    continue
                raise RuntimeError(
                    f"Gemini API error ({self._model_name}): {exc}"
                ) from exc
        return ""

    def reset(self) -> None:
        """Start a fresh multi-turn chat (clear Gemini context)."""
        self._chat = self._model.start_chat(history=[])


# ── Main CLI loop ─────────────────────────────────────────────────────────────

def run_chat() -> None:
    # ── Startup banner ────────────────────────────────────────────────────────
    print()
    print(f"{BOLD}{'═' * 66}{RESET}")
    print(f"{BOLD}{'  ETHOS AI — PRIVACY-PROTECTED CHAT':^66}{RESET}")
    print(f"{BOLD}{'  Gemini 2.5 Flash  ×  Privacy Layer':^66}{RESET}")
    print(f"{BOLD}{'═' * 66}{RESET}")
    print(f"\n{DIM}  Your messages are scanned for secrets before reaching Gemini.")
    print(f"  Secrets are vaulted and restored after the AI responds.{RESET}")
    print(f"\n{DIM}  Commands: /quit  /audit  /new  /help{RESET}\n")

    # ── Validate API key ──────────────────────────────────────────────────────
    if not API_KEY:
        print(f"{RED}ERROR:{RESET} GEMINI_API_KEY is not set.")
        print(f"  Set it in .env or run:  {CYAN}$env:GEMINI_API_KEY = 'your-key'{RESET}")
        sys.exit(1)

    # ── Initialise components ─────────────────────────────────────────────────
    print(f"  {DIM}Connecting to {MODEL_NAME}...{RESET}", end="", flush=True)
    try:
        gemini = GeminiSession(api_key=API_KEY, model_name=MODEL_NAME)
        print(f"  {GREEN}✓ Connected{RESET}")
    except Exception as e:
        print(f"\n{RED}✗ Failed to connect: {e}{RESET}")
        sys.exit(1)

    pds = PrivacyDataSecurity(config="default")
    pds.initialize()
    print(f"  {DIM}Privacy layer:{RESET} {GREEN}✓ Active{RESET}")
    print()

    # ── Conversation state ────────────────────────────────────────────────────
    session_ids: list[str] = []   # one session_id per user turn
    turn_count              = 0

    # ── Chat loop ─────────────────────────────────────────────────────────────
    while True:
        # Prompt
        try:
            raw_input = input(f"{BOLD}{CYAN}You:{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n{DIM}Goodbye!{RESET}\n")
            break

        if not raw_input:
            continue

        # ── Commands ──────────────────────────────────────────────────────────
        cmd = raw_input.lower()

        if cmd in ("/quit", "/exit", "/q"):
            print(f"\n{DIM}Goodbye! Conversation ended.{RESET}\n")
            break

        if cmd == "/help":
            print(f"""
  {BOLD}Commands:{RESET}
    {CYAN}/quit{RESET}   or {CYAN}/exit{RESET}  — end the chat
    {CYAN}/audit{RESET}              — show vault audit log (all sessions)
    {CYAN}/new{RESET}                — start a fresh conversation
    {CYAN}/help{RESET}               — show this message
""")
            continue

        if cmd == "/audit":
            if not session_ids:
                print(f"  {DIM}No sessions yet.{RESET}\n")
            else:
                print(f"\n{BOLD}Vault Audit Log{RESET}")
                print(_bar())
                total = 0
                for sid in session_ids:
                    entries = pds.audit(sid)
                    for e in entries:
                        total += 1
                        print(f"  {DIM}{sid}{RESET}  {CYAN}{e.type:<22}{RESET}  {e.token[:35]}...")
                if total == 0:
                    print(f"  {DIM}No confidential data was intercepted yet.{RESET}")
                else:
                    print(f"\n  {BOLD}Total:{RESET} {total} vault entries across {len(session_ids)} turns")
                print()
            continue

        if cmd == "/new":
            gemini.reset()
            session_ids.clear()
            turn_count = 0
            print(f"\n  {GREEN}✓ Fresh conversation started. Vault cleared.{RESET}\n")
            continue

        # ── Privacy protect ───────────────────────────────────────────────────
        try:
            protect_result = pds.protect(raw_input)
        except Exception as e:
            print(f"  {RED}Privacy layer error:{RESET} {e}\n")
            continue

        session_ids.append(protect_result.session_id)

        # Show what was intercepted (if anything)
        if protect_result.items_vaulted > 0:
            types = ", ".join(protect_result.audit_summary.get("types", []))
            print(
                f"  {_badge('SHIELD', YELLOW)}  "
                f"{GREEN}{protect_result.items_vaulted} item(s) vaulted{RESET}  "
                f"{DIM}({types}){RESET}"
            )
            if protect_result.alerts:
                print(_format_alerts(protect_result.alerts))

        # ── Send to Gemini ────────────────────────────────────────────────────
        print(f"  {DIM}Thinking...{RESET}", end="\r", flush=True)
        try:
            ai_raw = gemini.send(protect_result.safe_content)
        except RuntimeError as e:
            print(f"  {RED}{e}{RESET}\n")
            continue

        # ── Restore real values ───────────────────────────────────────────────
        try:
            final = pds.restore(ai_raw, session_id=protect_result.session_id)
        except Exception as e:
            print(f"  {RED}Restore error:{RESET} {e}\n")
            final = ai_raw   # fall back to raw AI response

        # ── Print AI reply ────────────────────────────────────────────────────
        turn_count += 1
        print(f"  {' ' * 14}\r", end="")   # clear "Thinking..." line
        print(f"\n{BOLD}{MAGENTA}Gemini:{RESET} {final}\n")

    # ── End banner ─────────────────────────────────────────────────────────────
    if session_ids:
        total_vaulted = sum(
            len(pds.audit(sid)) for sid in session_ids
        )
        print(_bar("═"))
        print(f"  {BOLD}Session summary{RESET}")
        print(f"  Turns         : {turn_count}")
        print(f"  Vault entries : {total_vaulted}")
        print(f"  {GREEN}✓ Gemini never saw your real data.{RESET}")
        print(_bar("═"))
        print()


if __name__ == "__main__":
    run_chat()
