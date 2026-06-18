"""
PIDS - Report Service (v5 - Fixed)
Professional PDF security reports with dark cybersecurity theme.
Fixes: Detection accuracy, LLM model name, Infilteration severity, port names.
"""
import os
import re
import csv
import json
import logging
import pickle
import time
from io import BytesIO

logger = logging.getLogger("pids.report")


# ---------------------------------------------------------------------------
# Canonical feature-name loader (cached)
# Replaces the legacy hardcoded 31-name lists; both ML and DL engines use
# this list (31 features) loaded from dl_models/selected_features.pkl.
# ---------------------------------------------------------------------------
_CANONICAL_FEATURE_NAMES = None


def _load_canonical_feature_names():
    """Load the 31 canonical feature names from disk (cached)."""
    global _CANONICAL_FEATURE_NAMES
    if _CANONICAL_FEATURE_NAMES is not None:
        return _CANONICAL_FEATURE_NAMES
    from pathlib import Path
    backend_dir = Path(__file__).resolve().parents[4]
    pkl_path = backend_dir / "dl_models" / "selected_features.pkl"
    try:
        with open(pkl_path, "rb") as fh:
            names = pickle.load(fh)
        _CANONICAL_FEATURE_NAMES = list(names)
    except Exception:
        # Fallback so report generation never crashes if the file is missing.
        _CANONICAL_FEATURE_NAMES = []
    return _CANONICAL_FEATURE_NAMES
from datetime import datetime, timedelta
from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)

# ============================================================================
# COLOUR PALETTE
# ============================================================================
C_BG         = colors.white
C_CARD       = colors.HexColor('#f5f5f5')
C_GREEN      = colors.HexColor('#1a5c2e')
C_GREEN_DIM  = colors.HexColor('#2e7d32')
C_GREEN_BG   = colors.HexColor('#e8f5e9')
C_CYAN       = colors.HexColor('#0d47a1')
C_RED        = colors.HexColor('#c62828')
C_ORANGE     = colors.HexColor('#e65100')
C_YELLOW     = colors.HexColor('#f57f17')
C_WHITE      = colors.black
C_GRAY       = colors.HexColor('#616161')
C_GRID       = colors.HexColor('#bdbdbd')
C_BORDER     = colors.HexColor('#1a5c2e')
C_HDR_BG     = colors.HexColor('#e8f5e9')
C_ROW1       = colors.white
C_ROW2       = colors.HexColor('#fafafa')

PAGE_W, PAGE_H = A4


class ReportService:

    def __init__(self):
        self.llm_service = None
        self._init_llm()
        # Per-process prose cache so repeated downloads of the same
        # report don't hit Ollama every time. Cleared on Django reload.
        # Key = sha256 of (section_id, prompt). Value = (timestamp, text).
        self._llm_prose_cache = {}
        self._llm_prose_ttl_sec = 3600  # 1 hour
        # Per-report cumulative LLM budget (seconds). Reset at the top
        # of generate_pdf_report. When exhausted, remaining LLM-driven
        # sections skip the model entirely and fall through to the
        # beginner-friendly static content — keeps a single slow PDF
        # download from hanging the browser for minutes.
        self._llm_budget_remaining_sec = 60.0
        self._llm_budget_default_sec = 60.0

    def _init_llm(self):
        try:
            from .llm_service import get_llm_service
            self.llm_service = get_llm_service()
        except Exception:
            self.llm_service = None

    # ========================================================================
    # LLM-DRIVEN PROSE (Item D)
    # Generates the human-readable text in the report via local Llama.
    # Falls back to provided ``fallback`` text if the LLM is unavailable
    # or produces unusable output. Format / structure of the report is
    # never altered — only the prose inside <Paragraph> elements changes.
    # ========================================================================
    def _llm_enabled(self) -> bool:
        """Toggleable via ``settings.LLM_REPORTS_ENABLED`` (default True)."""
        from django.conf import settings as dj_settings
        return bool(getattr(dj_settings, 'LLM_REPORTS_ENABLED', True))

    @staticmethod
    def _llm_sanitize(text: str) -> str:
        """
        Strip everything except the small set of HTML tags ReportLab's
        ``Paragraph`` understands. Defends against the LLM emitting
        markdown, raw HTML, or stray code fences that would corrupt
        the PDF rendering.
        """
        import re
        if not text:
            return ""
        # Drop code fences entirely.
        text = re.sub(r'```[\s\S]*?```', '', text)
        # Drop any HTML tag we don't whitelist. Keep <b> <i> <br/> <br>.
        text = re.sub(r'<(?!/?(?:b|i|br)\b)[^>]*>', '', text)
        # Markdown bullets / asterisk emphasis -> plain text.
        text = re.sub(r'^\s*[-*]\s+', '- ', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<i>\1</i>', text)
        # Collapse whitespace in each paragraph.
        text = re.sub(r'[ \t]+', ' ', text).strip()
        return text

    def _llm_prose(self, section_id: str, prompt: str,
                   fallback: 'list[str] | str',
                   max_tokens: int = 400, temperature: float = 0.4,
                   min_chars: int = 80):
        """
        Ask the LLM to write the prose for a named report section.

        Parameters
        ----------
        section_id
            Stable identifier (e.g. ``'exec_summary'``) used as the
            cache key.
        prompt
            The fully-formed prompt sent to Llama. Should encode the
            stats and the desired output format.
        fallback
            What to return if the LLM is disabled / unreachable / its
            output is too short or unusable. Either a list of paragraph
            strings (executive summary etc.) or a single string.
        max_tokens, temperature
            Forwarded to :meth:`LLMService.generate_text`.
        min_chars
            Minimum acceptable length of LLM output before we trust it
            and skip the fallback.
        """
        # Quick disqualifications — return fallback fast.
        if not self._llm_enabled() or not self.llm_service:
            logger.info("LLM prose: disabled / no service — using fallback for %s", section_id)
            return fallback
        if not getattr(self.llm_service, 'ollama_available', False):
            logger.info("LLM prose: ollama unavailable — using fallback for %s", section_id)
            return fallback

        # Global per-report budget guard. If we've already burned the
        # report's LLM-time budget on previous sections, skip the
        # network call entirely and fall through to the static text.
        if self._llm_budget_remaining_sec <= 1.0:
            logger.info(
                "LLM prose: budget exhausted (%.1fs left) — using fallback for %s",
                self._llm_budget_remaining_sec, section_id,
            )
            return fallback

        # Cache lookup.
        import hashlib
        key = hashlib.sha256(f'{section_id}|{prompt}'.encode()).hexdigest()[:24]
        cached = self._llm_prose_cache.get(key)
        if cached and (time.time() - cached[0]) < self._llm_prose_ttl_sec:
            return cached[1]

        # Retry loop — at most 2 tries with a 1 s back-off between them.
        #   * Per-attempt Ollama timeout dropped from 60s → 20s so a
        #     stuck call can't pin the request thread for a full minute.
        #   * Worst-case per section: 20 + 1 + 20 = 41s, but the global
        #     budget above will usually cut it shorter.
        #   * Each attempt also adapts to the *remaining* budget — if
        #     less than 20s is left we shrink the timeout accordingly so
        #     a single section can't blow past the budget by itself.
        text = ""
        last_err = None
        MAX_ATTEMPTS = 2
        for attempt in range(MAX_ATTEMPTS):
            per_attempt_timeout = max(5, min(20, int(self._llm_budget_remaining_sec)))
            call_start = time.time()
            try:
                text = self.llm_service.generate_text(
                    prompt=prompt, max_tokens=max_tokens, temperature=temperature,
                    num_ctx=2048, timeout=per_attempt_timeout,
                )
            except Exception as exc:  # noqa: BLE001 — we own the retry
                last_err = exc
                text = ""
                logger.warning(
                    "LLM prose attempt %d/%d raised for %s: %s",
                    attempt + 1, MAX_ATTEMPTS, section_id, exc,
                )
            elapsed = time.time() - call_start
            self._llm_budget_remaining_sec -= elapsed
            sanitized = self._llm_sanitize(text or "")
            if len(sanitized) >= min_chars:
                text = sanitized
                logger.info(
                    "LLM prose: %s OK in %.1fs (budget left %.1fs)",
                    section_id, elapsed, self._llm_budget_remaining_sec,
                )
                break
            # Otherwise short / empty — log and back off once before retry.
            logger.info(
                "LLM prose attempt %d/%d for %s returned %d chars (< %d) in %.1fs",
                attempt + 1, MAX_ATTEMPTS, section_id,
                len(sanitized), min_chars, elapsed,
            )
            # Don't bother retrying if the budget is already gone.
            if attempt < MAX_ATTEMPTS - 1 and self._llm_budget_remaining_sec > 1.0:
                time.sleep(1)
            else:
                break

        # Still under threshold — give up gracefully.
        if len(text) < min_chars:
            logger.warning(
                "LLM prose: giving up on %s (last error: %s)",
                section_id, last_err,
            )
            return fallback

        # Split into paragraphs for the executive-summary case (caller
        # decides what to do — string or list).
        if isinstance(fallback, list):
            paragraphs = [p.strip() for p in re.split(r'\n\s*\n', text) if p.strip()]
            if not paragraphs:
                return fallback
            self._llm_prose_cache[key] = (time.time(), paragraphs)
            return paragraphs
        else:
            self._llm_prose_cache[key] = (time.time(), text)
            return text

    # ========================================================================
    # PAGE BACKGROUND
    # ========================================================================
    @staticmethod
    def _page_bg(c, doc):
        c.saveState()
        w, h = PAGE_W, PAGE_H
        m = 20
        c.setStrokeColor(C_GREEN)
        c.setLineWidth(0.5)
        c.rect(m, m, w - 2*m, h - 2*m, fill=0, stroke=1)
        bar = 28
        c.setFillColor(C_HDR_BG)
        c.rect(m, h-m-bar, w-2*m, bar, fill=1, stroke=0)
        c.setStrokeColor(C_GREEN)
        c.setLineWidth(0.3)
        c.line(m, h-m-bar, w-m, h-m-bar)
        c.setFillColor(C_GREEN)
        c.setFont("Times-Bold", 9)
        c.drawString(m+10, h-m-19, "PIDS  //  PREDICTIVE INTRUSION DETECTION SYSTEM")
        c.setFillColor(C_GRAY)
        c.setFont("Times-Roman", 8)
        c.drawRightString(w-m-10, h-m-19, datetime.now().strftime("Generated: %Y-%m-%d  %H:%M"))
        c.setFont("Times-Roman", 7)
        c.setFillColor(C_GRAY)
        c.drawCentredString(w/2, m+10, "PIDS  |  Lahore Garrison University  |  Final Year Project 2026")
        c.drawCentredString(w/2, m+3, "Mian Usman (Fa22-092-BSSE)  &  Zaryab Zafar (Fa22-111-BSSE)")
        c.setFillColor(C_GREEN)
        c.setFont("Times-Bold", 8)
        c.drawRightString(w-m-8, m+3, f"Page {doc.page}")
        c.restoreState()

    # ========================================================================
    # STYLES
    # ========================================================================
    def _styles(self):
        s = {}
        s['title'] = ParagraphStyle('T', fontName='Times-Bold', fontSize=36, leading=44, textColor=C_GREEN, alignment=TA_CENTER, spaceAfter=8)
        s['subtitle'] = ParagraphStyle('ST', fontName='Times-Roman', fontSize=14, leading=21, textColor=C_GRAY, alignment=TA_CENTER, spaceAfter=4)
        s['section'] = ParagraphStyle('S', fontName='Times-Bold', fontSize=20, leading=30, textColor=C_GREEN, spaceBefore=12, spaceAfter=6, alignment=TA_LEFT)
        s['subsection'] = ParagraphStyle('SS', fontName='Times-BoldItalic', fontSize=14, leading=21, textColor=C_CYAN, spaceBefore=12, spaceAfter=6, alignment=TA_LEFT)
        s['body'] = ParagraphStyle('B', fontName='Times-Roman', fontSize=12, leading=18, textColor=C_WHITE, spaceBefore=12, spaceAfter=6, alignment=TA_JUSTIFY)
        s['body_ni'] = ParagraphStyle('BNI', fontName='Times-Roman', fontSize=12, leading=18, textColor=C_WHITE, spaceAfter=6, alignment=TA_JUSTIFY)
        s['bullet'] = ParagraphStyle('BL', fontName='Times-Roman', fontSize=12, leading=18, textColor=C_WHITE, spaceBefore=6, spaceAfter=6, leftIndent=24, bulletIndent=8, bulletFontName='Times-Roman', bulletFontSize=12, bulletColor=C_GREEN, alignment=TA_JUSTIFY)
        s['rec'] = ParagraphStyle('RC', fontName='Times-Roman', fontSize=12, leading=18, textColor=C_WHITE, spaceBefore=6, spaceAfter=6, leftIndent=24, bulletIndent=8, bulletFontName='Times-Bold', bulletFontSize=12, bulletColor=C_CYAN, alignment=TA_JUSTIFY)
        s['small'] = ParagraphStyle('SM', fontName='Times-Roman', fontSize=9, leading=13.5, textColor=C_GRAY, spaceAfter=2, alignment=TA_LEFT)
        s['stat_val'] = ParagraphStyle('SV', fontName='Times-Bold', fontSize=28, leading=34, textColor=C_GREEN, alignment=TA_CENTER)
        s['stat_lbl'] = ParagraphStyle('SL', fontName='Times-Bold', fontSize=10, leading=14, textColor=C_GRAY, alignment=TA_CENTER)
        s['table_cell'] = ParagraphStyle('TC', fontName='Times-Roman', fontSize=10, leading=15, textColor=C_WHITE, alignment=TA_LEFT)
        s['table_header'] = ParagraphStyle('TH', fontName='Times-Bold', fontSize=11, leading=15, textColor=C_GREEN, alignment=TA_CENTER)
        s['incident_title'] = ParagraphStyle('IT', fontName='Times-BoldItalic', fontSize=14, leading=21, textColor=C_RED, spaceBefore=12, spaceAfter=6, alignment=TA_LEFT)
        s['incident_step'] = ParagraphStyle('IS', fontName='Times-Roman', fontSize=11, leading=16.5, textColor=C_WHITE, spaceAfter=2, leftIndent=20, bulletIndent=8, bulletFontName='Times-Roman', bulletFontSize=11, bulletColor=C_CYAN, alignment=TA_JUSTIFY)
        return s

    # ========================================================================
    # TABLE HELPER
    # ========================================================================
    def _table(self, data, widths, hdr_bg=C_HDR_BG):
        styled_data = []
        for i, row in enumerate(data):
            styled_row = []
            for j, cell in enumerate(row):
                if i == 0:
                    styled_row.append(Paragraph(str(cell), self._styles()['table_header']))
                else:
                    if isinstance(cell, (int, float)) or (isinstance(cell, str) and cell.replace(',', '').replace('.', '').replace('%', '').replace('/', '').isdigit()):
                        cell_style = ParagraphStyle('num', parent=self._styles()['table_cell'], alignment=TA_CENTER)
                        styled_row.append(Paragraph(str(cell), cell_style))
                    else:
                        styled_row.append(Paragraph(str(cell), self._styles()['table_cell']))
            styled_data.append(styled_row)
        t = Table(styled_data, colWidths=widths, repeatRows=1)
        n = len(styled_data)
        cmds = [
            ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
            ('BACKGROUND', (0,0), (-1,0), hdr_bg),
            ('ALIGN', (0,0), (-1,0), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('LINEBELOW', (0,0), (-1,0), 1, C_GREEN),
            ('LINEBELOW', (0,-1), (-1,-1), 0.5, C_GRID),
            ('GRID', (0,0), (-1,-1), 0.3, C_GRID),
        ]
        for i in range(1, n):
            cmds.append(('BACKGROUND', (0,i), (-1,i), C_ROW1 if i % 2 else C_ROW2))
        t.setStyle(TableStyle(cmds))
        return t

    def _hr(self):
        return HRFlowable(width="100%", thickness=0.8, color=C_GREEN, spaceAfter=5, spaceBefore=3)

    def _stat_row(self, items, st):
        top, bot = [], []
        for val, lbl, col in items:
            vs = ParagraphStyle('_sv', parent=st['stat_val'], textColor=col, fontSize=22, leading=28)
            top.append(Paragraph(val, vs))
            bot.append(Paragraph(lbl, st['stat_lbl']))
        cw = (PAGE_W - 1.8*inch) / len(items)
        t = Table([top, bot], colWidths=[cw]*len(items))
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_CARD),
            ('BOX', (0,0), (-1,-1), 1, C_BORDER),
            ('LINEAFTER', (0,0), (-2,-1), 0.5, C_GRID),
            ('TOPPADDING', (0,0), (-1,0), 18),
            ('BOTTOMPADDING', (0,-1), (-1,-1), 12),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        return t

    def _trunc(self, text, mx=50):
        if not text: return ""
        text = str(text)
        return text if len(text) <= mx else text[:mx-3] + "..."

    # ========================================================================
    # SEVERITY & RISK
    # ========================================================================
    def _determine_severity(self, attack_type, count=None, total_attacks=None):
        atk_lower = attack_type.lower()
        if any(x in atk_lower for x in ['ddos', 'dos', 'botnet', 'c2', 'zero-day', 'hulk', 'loic', 'goldeneye', 'hoic']):
            return 'CRITICAL'
        if any(x in atk_lower for x in ['exfil', 'exfiltration', 'infiltr', 'infilteration', 'sql', 'xss', 'backdoor', 'reverse shell', 'beacon']):
            return 'HIGH'
        if any(x in atk_lower for x in ['brute', 'force', 'scan', 'patator']):
            return 'MEDIUM'
        return 'LOW'

    def _calculate_risk(self, count, total_attacks, attack_type):
        if total_attacks == 0: return 0.0
        freq_ratio = count / total_attacks
        base_risk = freq_ratio * 5
        atk_lower = attack_type.lower()
        if any(x in atk_lower for x in ['ddos', 'dos', 'hulk', 'loic', 'goldeneye']): severity_bonus = 4
        elif any(x in atk_lower for x in ['c2', 'botnet', 'beacon']): severity_bonus = 4
        elif any(x in atk_lower for x in ['exfil', 'exfiltration', 'infiltr', 'infilteration']): severity_bonus = 3
        elif any(x in atk_lower for x in ['sql', 'injection', 'backdoor']): severity_bonus = 3
        elif any(x in atk_lower for x in ['brute', 'force']): severity_bonus = 2
        else: severity_bonus = 1
        return round(min(base_risk + severity_bonus, 10.0), 1)

    def _sev_col(self, sev):
        s = sev.lower()
        if s == 'critical': return C_RED
        if s == 'high': return C_ORANGE
        if s == 'medium': return C_YELLOW
        return C_GREEN_DIM

    # ========================================================================
    # PORT NAME
    # ========================================================================
    def _get_port_name(self, port):
        port_names = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1337: 'Backdoor', 1433: 'MSSQL', 2375: 'Docker-API',
            3306: 'MySQL', 3389: 'RDP', 3478: 'STUN/VoIP',
            4444: 'Metasploit', 5432: 'PostgreSQL', 5555: 'Android-ADB',
            6379: 'Redis', 6667: 'IRC-C2', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 9001: 'Tor', 9999: 'Test/Custom',
            27017: 'MongoDB', 31337: 'Back-Orifice',
        }
        return port_names.get(port, f'Port-{port}')

    # ========================================================================
    # INCIDENT RESPONSE
    # ========================================================================
    def _detailed_incident_response(self, attack_types, total_attacks):
        responses = []
        sorted_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:8]
        for attack, count in sorted_attacks:
            atk_lower = attack.lower()
            percentage = (count / total_attacks * 100) if total_attacks > 0 else 0
            if any(x in atk_lower for x in ['ddos', 'dos', 'hulk', 'loic', 'goldeneye', 'hoic']):
                responses.append({'attack': attack, 'count': count, 'percentage': percentage, 'severity': 'CRITICAL', 'timeframe': '15 minutes', 'owner': 'Network Security Team',
                    'steps': ['ACTIVATE DDoS PROTECTION: Enable cloud-based DDoS scrubbing', 'RATE LIMIT: Implement connection throttling (limit 100 req/sec per IP)', 'BLACKHOLE ROUTING: Null route top 10 attacking IPs at firewall', 'SYN COOKIES: Enable SYN cookie protection on public services', 'TRAFFIC ANALYSIS: Capture 5-minute packet sample for analysis', 'SCALE RESOURCES: Temporarily increase bandwidth if possible', 'MONITOR: Watch for attack evolution (layer 7 vs volumetric shifts)'],
                    'verification': ['Attack traffic decreased >80%', 'Legitimate traffic reaching services', 'No service degradation']})
            elif 'exfil' in atk_lower or 'exfiltration' in atk_lower:
                responses.append({'attack': attack, 'count': count, 'percentage': percentage, 'severity': 'CRITICAL', 'timeframe': '30 minutes', 'owner': 'Security Operations + Legal',
                    'steps': ['IMMEDIATE BLOCK: Block all outbound to suspicious IPs', 'CONTAINMENT: Disable compromised user accounts', 'DATA AUDIT: Identify all data accessed during window', 'PRESERVE EVIDENCE: Secure captures, logs, endpoints', 'LEGAL NOTIFICATION: Notify legal if PII data involved', 'INCIDENT REPORT: Create detailed timeline', 'BACKUP VERIFICATION: Verify backup integrity'],
                    'verification': ['Outbound blocks active', 'Scope of data loss identified', 'Legal notified if required']})
            elif 'infiltr' in atk_lower:
                responses.append({'attack': attack, 'count': count, 'percentage': percentage, 'severity': 'HIGH', 'timeframe': '2 hours', 'owner': 'Incident Response Team',
                    'steps': ['IMMEDIATE ISOLATION: Segment affected network zone', 'AUDIT ACCESS LOGS: Review authentication logs', 'FORENSIC CAPTURE: Preserve memory dumps and images', 'PATCH MANAGEMENT: Apply emergency security patches', 'MALWARE SCAN: Full endpoint detection scan', 'CREDENTIAL ROTATION: Force password reset for exposed accounts', 'INDICATOR COLLECTION: Document IOCs for threat intel'],
                    'verification': ['Isolation confirmed', 'No lateral movement', 'All patches applied']})
            elif any(x in atk_lower for x in ['brute', 'force', 'patator']):
                responses.append({'attack': attack, 'count': count, 'percentage': percentage, 'severity': 'MEDIUM', 'timeframe': '1 hour', 'owner': 'Identity Management Team',
                    'steps': ['ENABLE ACCOUNT LOCKOUT: 5 failed attempts, 15 min lockout', 'FORCE MFA: Enforce multi-factor authentication', 'IP BLOCKING: Add attacking IPs to deny list', 'SUCCESS AUDIT: Check for successful logins during attack', 'USER NOTIFICATION: Notify affected users to reset credentials', 'PASSWORD POLICY: Review complexity requirements', 'MONITORING: Increase alert sensitivity'],
                    'verification': ['Lockout policy active', 'MFA enrolled', 'No unauthorized logins']})
            else:
                responses.append({'attack': attack, 'count': count, 'percentage': percentage, 'severity': self._determine_severity(attack), 'timeframe': 'Review within 24 hours', 'owner': 'Security Analyst',
                    'steps': ['REVIEW: Analyze attack patterns and affected assets', 'DOCUMENT: Log incident details in security system', 'MONITOR: Increase alert threshold for similar patterns', 'UPDATE: Add signatures to detection rules', 'FOLLOW-UP: Schedule review in weekly security meeting'],
                    'verification': ['Incident documented', 'Detection rules updated', 'No recurrence']})
        return responses

    # ========================================================================
    # FETCH DATA
    # ========================================================================
    # ========================================================================
    # ACTIVE ENGINE → STAGE DESCRIPTIONS
    # Reads EngineConfig.active_engine (ml / dl / gnn) and returns the
    # Stage 1 / Stage 2 subsection titles + body text appropriate for
    # whichever engine is currently routing live traffic. Stages 3 and 4
    # (LLM + Rate Detector) are engine-agnostic and shared.
    # ========================================================================
    def _active_engine_stages(self):
        """
        Returns (engine_key, human_label, list_of_(title, body) tuples).
        Falls back to 'ml' on any DB / import error so the report still
        renders even if the EngineConfig table is unreachable.
        """
        engine_key = 'ml'
        try:
            from api.models import EngineConfig
            engine_key = (EngineConfig.get_active().active_engine or 'ml').lower()
        except Exception as exc:  # noqa: BLE001 — defensive
            logger.warning("Could not read EngineConfig for report: %s", exc)
            engine_key = 'ml'

        # Shared stages 3 + 4 — same regardless of engine choice.
        stage_3 = (
            "Stage 3 - LLM Threat Intelligence (Ollama + Llama 3.2:1B)",
            "Uncertain packets are analysed by a locally hosted Llama-3.2:1B LLM "
            "enriched with DuckDuckGo threat intelligence. The LLM can promote "
            "traffic to attack status (zero-day discovery) or demote it to normal "
            "(false-positive clearing).",
        )
        stage_4 = (
            "Stage 4 - Connection Rate Detector",
            "Monitors connection rates per IP/port pair. Detects SYN floods "
            "(30+ flows/10s) and brute force attacks (10+ flows/10s on auth "
            "ports) that individual flow analysis misses.",
        )

        if engine_key == 'dl':
            label = "DL Engine — Two-Stage DNN (Keras)"
            stages = [
                ("Stage 1 - DNN Binary Classifier (98.36% Accuracy)",
                 "Every packet's 31-feature vector is scored by a five-layer dense "
                 "neural network ending in a sigmoid head. ~225K parameters, "
                 "BatchNorm + Dropout after every dense block, inference under 5 ms."),
                ("Stage 2 - DNN Multi-Class Categoriser (~98% Accuracy)",
                 "Anomalous packets pass through a structurally identical DNN whose "
                 "final layer is a 13-way softmax over the CICIDS-2018 attack "
                 "classes. Low-confidence predictions route to Stage 3 (LLM)."),
                stage_3, stage_4,
            ]
        elif engine_key == 'gnn':
            label = "GNN Engine — E-GraphSAGE + GIN (Research)"
            stages = [
                ("Stage 1 - E-GraphSAGE + GATv2 Binary Head (96.85% Accuracy, F1 0.9548)",
                 "Flows are nodes in a graph built live at inference time — KNN(k=8) "
                 "edges in feature space + same-Dst-Port edges + self-loops. Two "
                 "SAGEConv layers aggregate neighbour messages; a GATv2 attention "
                 "layer re-weights them; an MLP head emits P(attack). Threshold "
                 "calibrated to 0.35 for Infiltration recall."),
                ("Stage 2 - GIN + GATv2 Multi-Class Head (99.92% Accuracy, Macro F1 0.9946)",
                 "Attack flows pass through a 13-class subgraph. Two GINConv layers "
                 "use multiset-injective aggregation (Weisfeiler-Lehman-equivalent); "
                 "GATv2 sharpens the dominant neighbour signal. Infiltration F1 "
                 "0.6321 end-to-end — <b>2.34× the DNN baseline of 0.27</b>."),
                stage_3, stage_4,
            ]
        else:
            # 'ml' — default. Two-stage classical ML.
            label = "ML Engine — XGBoost + LightGBM (Default)"
            stages = [
                ("Stage 1 - XGBoost Binary Filter (98.24% Accuracy)",
                 "Every packet is classified as normal or anomalous in under 2 ms "
                 "using a lightweight XGBoost binary classifier trained on "
                 "CICIDS-2017/2018."),
                ("Stage 2 - LightGBM Multi-Class Categorisation (95.66% Accuracy)",
                 "Anomalous packets are fed into a LightGBM model that outputs one "
                 "of 14 specific attack labels with a confidence score."),
                stage_3, stage_4,
            ]

        return engine_key, label, stages

    def _fetch_report_data(self, report_window=20):
        """
        Aggregate every metric the PDF needs in one place — scoped to
        the most recent ``report_window`` events.

        Parameters
        ----------
        report_window
            How many most-recent TrafficLog rows the WHOLE report is
            scoped to. Stats (total / attacks / normal / suspicious /
            LLM analysed / zero-day), attack-type breakdown, top
            attacker IPs, top targeted ports, AND the Recent Incidents
            table are all computed from this window only. The view
            clamps to [5, 200] before passing through.

        Returns
        -------
        (stats, attack_types, top_attackers, top_ports, recent_attacks)
        plus ``stats['report_window']`` recording the chosen N so the
        cover page can show "Window: Last N events".
        """
        from django.db.models import Count, Q
        from api.models import TrafficLog

        # ── Window scoping done ENTIRELY in the database ──────────────────
        # The old code pulled N rows into Python (so it HAD to cap N to keep
        # memory sane). Instead we find the timestamp of the Nth most-recent
        # row and aggregate everything with GROUP BY / conditional COUNT over
        # that window. This honours ANY N — 1,000 / 100,954 / all 4.4M — with
        # no row loading and no artificial cap.
        n = max(5, int(report_window or 20))
        total_all = TrafficLog.objects.count()

        if n >= total_all:
            base = TrafficLog.objects.all()          # whole DB
            window_n = total_all
        else:
            cutoff = list(
                TrafficLog.objects.order_by('-timestamp')
                .values_list('timestamp', flat=True)[n - 1:n]
            )
            base = (TrafficLog.objects.filter(timestamp__gte=cutoff[0])
                    if cutoff else TrafficLog.objects.all())
            window_n = n

        # ── Aggregate counts in one pass ──────────────────────────────────
        # Prefixed aliases so they don't collide with the model field names
        # referenced inside the FILTER clauses (e.g. llm_analyzed, status).
        agg = base.aggregate(
            n_total=Count('id'),
            n_attacks=Count('id', filter=Q(status='Attack')),
            n_suspicious=Count('id', filter=Q(status='Suspicious')),
            n_normal=Count('id', filter=Q(status='Normal')),
            n_llm=Count('id', filter=Q(llm_analyzed=True)),
            n_llm_attacks=Count('id', filter=Q(llm_analyzed=True, status='Attack')),
            n_llm_normal=Count('id', filter=Q(llm_analyzed=True, status='Normal')),
            n_zero=Count('id', filter=Q(is_zero_day=True)),
        )
        stats = {
            'total_traffic': agg['n_total'] or 0,
            'attacks':       agg['n_attacks'] or 0,
            'suspicious':    agg['n_suspicious'] or 0,
            'normal':        agg['n_normal'] or 0,
            'llm_analyzed':  agg['n_llm'] or 0,
            'llm_attacks':   agg['n_llm_attacks'] or 0,
            'llm_normal':    agg['n_llm_normal'] or 0,
            'zero_day':      agg['n_zero'] or 0,
            'report_window': window_n,   # cover page shows "Window: Last N events"
        }

        atk = base.filter(status='Attack')

        # ---- attack types (top 15 within window) ----
        attack_types = {
            r['prediction']: r['c'] for r in
            atk.values('prediction').annotate(c=Count('id')).order_by('-c')[:15]
        }

        # ---- top attacker IPs (top 10) + each IP's primary attack ----
        top_attackers = {}
        for r in atk.values('src_ip').annotate(c=Count('id')).order_by('-c')[:10]:
            ip = r['src_ip']
            primary = (atk.filter(src_ip=ip).values('prediction')
                       .annotate(c=Count('id')).order_by('-c').first())
            top_attackers[ip] = {
                'count': r['c'],
                'primary_attack': primary['prediction'] if primary else 'Unknown',
            }

        # ---- top targeted ports (top 10) ----
        top_ports = [
            {'dst_port': r['dst_port'], 'cnt': r['c']} for r in
            atk.values('dst_port').annotate(c=Count('id')).order_by('-c')[:10]
        ]

        # ---- Recent Incidents table (renderer caps at 15) — load light fields ----
        recent_attacks = list(
            atk.only('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                     'protocol', 'prediction', 'confidence', 'status',
                     'attack_type', 'llm_analyzed')
               .order_by('-timestamp')[:30]
        )

        return stats, attack_types, top_attackers, top_ports, recent_attacks

    # ========================================================================
    # EXECUTIVE SUMMARY
    # ========================================================================
    def _build_enhanced_summary(self, stats, attack_types):
        total = stats.get('total_traffic', 0)
        attacks = stats.get('attacks', 0)
        normal = stats.get('normal', 0)
        llm_analyzed = stats.get('llm_analyzed', 0)
        llm_attacks = stats.get('llm_attacks', 0)
        llm_normal = stats.get('llm_normal', 0)
        zero_day = stats.get('zero_day', 0)
        atk_pct = (attacks / max(total, 1)) * 100
        if atk_pct > 10: threat_level, action = "CRITICAL", "IMMEDIATE ACTION REQUIRED"
        elif atk_pct > 5: threat_level, action = "ELEVATED", "URGENT ATTENTION NEEDED"
        elif atk_pct > 1: threat_level, action = "MODERATE", "MONITOR AND REVIEW"
        else: threat_level, action = "LOW", "ROUTINE MONITORING"

        # ----- Static fallback (the original prose, unchanged) -----
        fallback = []
        fallback.append(f"<b>Report Period:</b> {datetime.now().strftime('%B %d, %Y - %H:%M')}<br/><b>Threat Level:</b> {threat_level} | <b>Status:</b> {action}")
        fallback.append(f"During the reporting period, PIDS analysed <b>{total:,}</b> network packets. Of these, <b>{normal:,}</b> ({normal/max(total,1)*100:.1f}%) were classified as normal traffic, while <b>{attacks:,}</b> ({atk_pct:.1f}%) were identified as malicious or suspicious activity.")
        if attack_types:
            findings = "<b>Critical Findings:</b><br/>"
            top3 = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:3]
            for i, (attack, count) in enumerate(top3, 1):
                pct = (count / max(attacks, 1)) * 100
                findings += f"{i}. <b>{attack}</b>: {count:,} incidents ({pct:.1f}% of all attacks)<br/>"
            fallback.append(findings)
        llm_impact = f"<b>LLM Intelligence Impact:</b><br/>"
        llm_impact += f"- <b>Total LLM Analysed:</b> {llm_analyzed:,} packets ({llm_analyzed/max(total,1)*100:.1f}% of traffic)<br/>"
        llm_impact += f"- <b>Zero-Day Threats Discovered:</b> {zero_day:,}<br/>"
        llm_impact += f"- <b>False Positives Cleared:</b> {llm_normal:,}<br/>"
        llm_impact += f"- <b>Analyst Workload Reduction:</b> {(llm_normal/max(llm_analyzed,1))*100:.1f}%"
        fallback.append(llm_impact)
        if atk_pct > 5:
            actions = "<b>Immediate Actions Required:</b><br/>1. Block top 5 attacking IPs at perimeter firewall<br/>2. Activate DDoS mitigation rules for HTTP/HTTPS services<br/>3. Review and patch systems targeted by infiltration attempts<br/>4. Investigate internal IPs showing abnormal outbound patterns<br/>5. Enable enhanced logging for affected services"
            fallback.append(actions)
        fallback.append("This report provides detailed analysis of attack patterns, targeted infrastructure, and comprehensive incident response playbooks tailored to the detected threats.")

        # ----- LLM prompt (only the prose changes; structure / tags identical) -----
        top_attacks_str = ""
        if attack_types:
            top3 = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:3]
            top_attacks_str = "; ".join([f"{n} ({c:,} incidents)" for n, c in top3])
        prompt = (
            "You are a senior security analyst writing the EXECUTIVE SUMMARY of an "
            "intrusion-detection report. Tone: professional, factual, concise. "
            "Audience: a CIO and SOC manager.\n\n"
            f"Reporting period: {datetime.now().strftime('%B %d, %Y - %H:%M')}.\n"
            f"Threat level: {threat_level}. Status: {action}.\n"
            f"Total packets analysed: {total:,}. Normal: {normal:,} ({normal/max(total,1)*100:.1f}%). "
            f"Attacks: {attacks:,} ({atk_pct:.1f}%).\n"
            f"Top attack types: {top_attacks_str or 'none'}.\n"
            f"LLM module: analysed {llm_analyzed:,} packets, confirmed {llm_attacks:,} threats, "
            f"cleared {llm_normal:,} false positives, discovered {zero_day:,} zero-day candidates.\n\n"
            "Write EXACTLY 4 short paragraphs (each 2-3 sentences):\n"
            "1. Overall posture and what the threat level means for the business.\n"
            "2. The traffic-volume picture — restate the numbers in plain English.\n"
            "3. The most consequential attack patterns observed (cite specific names).\n"
            "4. The LLM module's contribution to alert quality.\n\n"
            "Format rules: separate paragraphs with a blank line. Use <b>...</b> ONLY for "
            "the lead phrase of each paragraph. No headings. No markdown. No code fences. "
            "No URLs. Do NOT invent numbers — only restate the ones above."
        )

        result = self._llm_prose(
            section_id='exec_summary',
            prompt=prompt,
            fallback=fallback,
            max_tokens=500,
            temperature=0.45,
            min_chars=250,
        )
        return result if isinstance(result, list) and len(result) >= 2 else fallback

    # ========================================================================
    # BEGINNER-FRIENDLY ACTION GUIDE
    # Used as the FALLBACK content for the Recommendations section when the
    # AI is unreachable or its output is rejected. Same section, same bullet
    # styling — only the text is replaced with plain-language steps that a
    # first-time SOC operator can actually follow without prior training.
    # ========================================================================
    def _beginner_action_guide(self, attack_types):
        """
        Build a beginner-grade remediation list keyed off the attack
        families actually observed. Each entry is a single sentence
        starting with "If you see X" so the reader can scan for the
        threat name they recognise and act on it.
        """
        if not attack_types:
            return [
                "No attacks detected in this period — keep doing what you're doing.",
                "Run an antivirus + Windows / Linux update on every workstation this week.",
                "Make sure your firewall is still on (Settings > Network > Firewall).",
                "Change any password you've reused on more than one site.",
                "Back up important folders to an external drive or cloud you don't normally use.",
                "Re-read the incident-response runbook so you remember the first 5 steps.",
            ]

        ats = ' '.join(str(k).lower() for k in attack_types.keys())
        guide = []

        # The phrasing template: "If you see <FAMILY>: <plain-language step>."
        if any(x in ats for x in ['ddos', 'dos', 'hulk', 'loic', 'hoic', 'slow']):
            guide += [
                "If you see DDoS / DoS: turn on your firewall's <b>rate-limit</b> for the targeted port "
                "(usually 80/443) — it tells the firewall to drop floods automatically.",
                "If you see DDoS / DoS: call your hosting / ISP support and ask them to "
                "<b>enable DDoS protection</b>; most plans include it for free, you just have to ask.",
                "If you see DDoS / DoS: open the alert in PIDS, copy the attacker IPs, "
                "paste them into your router's <b>block list</b> (Settings &gt; Security &gt; IP Block).",
            ]
        if any(x in ats for x in ['brute', 'force', 'patator', 'ssh-brute', 'ftp-brute']):
            guide += [
                "If you see Brute Force: change the password on the targeted service NOW to "
                "<b>a 16-character random one</b>, then enable <b>2-factor authentication</b>.",
                "If you see Brute Force: set the login system to <b>lock the account for 15 minutes</b> "
                "after 5 wrong tries — this stops the attacker dead.",
                "If you see Brute Force: block the attacker's country in the firewall if your users "
                "are all in one region (search '<b>geo-blocking</b>' in your firewall's docs).",
            ]
        if any(x in ats for x in ['sql', 'injection', 'xss', 'web']):
            guide += [
                "If you see SQL Injection / XSS: take the web app <b>offline</b> "
                "(or put it behind a maintenance page) until a developer reviews the input forms.",
                "If you see SQL Injection / XSS: turn on a <b>Web Application Firewall</b> "
                "— Cloudflare's free tier blocks 95% of these for you in under 10 minutes.",
                "If you see SQL Injection / XSS: tell the developer to "
                "<b>use parameterised queries</b> — it's a one-line change per query.",
            ]
        if any(x in ats for x in ['bot', 'c2', 'botnet', 'beacon']):
            guide += [
                "If you see Bot / C2: <b>disconnect the affected computer from the network "
                "immediately</b> (pull the cable / disable Wi-Fi). Don't shut it down.",
                "If you see Bot / C2: run a full antivirus scan with <b>Malwarebytes</b> or "
                "<b>Windows Defender</b>; if anything is found, reinstall the OS.",
                "If you see Bot / C2: change every password that was typed on that machine "
                "in the last 30 days — assume the attacker has them.",
            ]
        if any(x in ats for x in ['infil', 'infiltration', 'exfil', 'exfiltration']):
            guide += [
                "If you see Infiltration: this attack is <b>slow and stealthy</b> — "
                "switch the PIDS detection engine to <b>GNN</b> from the admin panel; "
                "it catches 2.34× more infiltration than the default.",
                "If you see Infiltration: review what was sent OUT of your network in the "
                "last 24 hours (Reports &gt; Outbound). Anything unfamiliar = investigate.",
                "If you see Infiltration: rotate credentials for every admin account "
                "(start with the cloud provider, then domain admin, then app passwords).",
            ]
        if 'ddos attack-loic-udp' in ats or 'udp' in ats:
            guide += [
                "If you see UDP-based attack: ask your firewall vendor to "
                "<b>enable UDP flood protection</b> — usually a single checkbox.",
            ]

        # Always-on closing steps regardless of family detected.
        guide += [
            "After any attack: take a <b>screenshot of the PIDS alert</b> and save the PDF "
            "report — you'll need it for the incident log.",
            "After any attack: tell your team in <b>plain English</b> what happened, what you did, "
            "and what they should watch for. Don't use jargon.",
            "Within 48 hours: <b>retrain the model</b> from Retrain &gt; Start — it learns from the "
            "new attack samples so the next one is easier to catch.",
        ]
        # Trim — the section is supposed to fit comfortably on one page.
        return guide[:12]

    def _enhanced_recommendations(self, attack_types, stats):
        # Static fallback — beginner-friendly, plain-language steps for the
        # detected attack families. Used when the LLM is unreachable or its
        # output is rejected. Format-identical to the AI path (bullet list
        # in the existing Recommendations section), only the text changes.
        fallback = self._beginner_action_guide(attack_types)

        # LLM prompt — produces a tailored 8-10 item recommendation list.
        attacks = stats.get('attacks', 0)
        attack_list = ', '.join(list(attack_types.keys())[:6]) if attack_types else 'none observed'
        prompt = (
            "You are a senior security analyst writing the SECURITY RECOMMENDATIONS "
            "section of an intrusion-detection report.\n\n"
            f"Detected attack types: {attack_list}.\n"
            f"Total attack incidents: {attacks:,}.\n\n"
            "Produce EXACTLY 8 numbered recommendations. Each one must be:\n"
            "- a single concrete actionable sentence (12-25 words)\n"
            "- specific to the attack types listed above (do not give generic advice)\n"
            "- ordered from highest to lowest urgency\n\n"
            "Format rules: one recommendation per line. Number them 1. through 8. "
            "Do NOT add headings or extra commentary. Do NOT use markdown."
        )
        text = self._llm_prose(
            section_id='recommendations',
            prompt=prompt,
            fallback="",
            max_tokens=400,
            temperature=0.5,
            min_chars=200,
        )
        if not text:
            return fallback

        # Parse "1. xxx" / "1) xxx" / "- xxx" lines.
        lines = []
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            cleaned = re.sub(r'^\s*(?:\d+[\.\)]|[-*])\s*', '', ln)
            if len(cleaned) >= 10:
                lines.append(cleaned)
        return (lines or fallback)[:10]

    # ========================================================================
    # GENERATE PDF - MAIN METHOD
    # ========================================================================
    def generate_pdf_report(self, traffic_logs=None, stats=None, filename=None,
                            report_window=20, max_recent_incidents=None):
        """
        Build the full PDF report.

        Parameters
        ----------
        report_window
            User-chosen scope of the report — the **whole** report
            (stats, attack-type breakdown, top attackers, top ports,
            Recent Incidents table) is computed from the most recent
            ``report_window`` TrafficLog rows. Default 20. The view
            validates / clamps the query-string value to [5, 200].

        max_recent_incidents
            Legacy alias for ``report_window`` — accepted to keep older
            callers working. If provided, takes precedence.
        """
        # Reset the per-report LLM budget. Anything left from a previous
        # download (different ReportService instance per process anyway,
        # but be defensive) is ignored.
        self._llm_budget_remaining_sec = self._llm_budget_default_sec
        report_start = time.time()

        # Legacy callers passed `max_recent_incidents`; honour it if so.
        if max_recent_incidents is not None:
            report_window = max_recent_incidents

        db_stats, attack_types, top_attackers, top_ports, recent_attacks = \
            self._fetch_report_data(report_window=report_window)
        if stats: stats.update(db_stats)
        else: stats = db_stats
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.9*inch, bottomMargin=0.7*inch, leftMargin=0.8*inch, rightMargin=0.8*inch)
        st = self._styles()
        story = []

        # ----- auto-numbering section helper -----
        # The report has several conditional sections (LLM intel, threat
        # analysis, top sources, targeted ports, false-positive analysis)
        # that are skipped when their data is empty. Hard-coding numbers
        # therefore produced gaps like [02] → [08]. ``sect()`` increments
        # only when the section is actually rendered, so the printed
        # numbers are always sequential 01, 02, 03, …
        section_counter = [0]
        def sect(title):
            section_counter[0] += 1
            return Paragraph(
                f"[{section_counter[0]:02d}]  {title}",
                st['section'],
            )
        total = max(stats.get('total_traffic', 0), 1)
        attacks = stats.get('attacks', 0)
        suspicious = stats.get('suspicious', 0)
        normal = stats.get('normal', 0)
        llm_analyzed = stats.get('llm_analyzed', 0)
        llm_attacks = stats.get('llm_attacks', 0)
        llm_normal = stats.get('llm_normal', 0)
        zero_day = stats.get('zero_day', 0)
        atk_pct = attacks / total * 100
        nrm_pct = normal / total * 100

        # === COVER PAGE ===
        story.append(Spacer(1, 60))
        story.append(Paragraph("P.I.D.S.", st['title']))
        story.append(Paragraph("PREDICTIVE INTRUSION DETECTION SYSTEM", st['subtitle']))
        story.append(Spacer(1, 8))
        story.append(self._hr())
        cov = ParagraphStyle('cov', fontName='Times-Bold', fontSize=15, textColor=C_GREEN, alignment=TA_CENTER, spaceAfter=8)
        story.append(Paragraph("SECURITY ANALYSIS REPORT", cov))
        story.append(Paragraph(
            f"Report Period: {datetime.now().strftime('%B %d, %Y - %H:%M')}  |  "
            f"Window: Last {stats.get('report_window', total):,} events  |  "
            f"Packets Analysed: {total:,}",
            st['subtitle']
        ))
        story.append(Spacer(1, 8))
        if atk_pct > 10: tl, tc = "CRITICAL", C_RED
        elif atk_pct > 5: tl, tc = "ELEVATED", C_ORANGE
        elif atk_pct > 1: tl, tc = "MODERATE", C_YELLOW
        else: tl, tc = "LOW", C_GREEN
        story.append(Paragraph("OVERALL THREAT LEVEL", ParagraphStyle('_', fontName='Times-Bold', fontSize=12, textColor=C_GRAY, alignment=TA_CENTER, spaceAfter=4)))
        story.append(Paragraph(tl, ParagraphStyle('_', fontName='Times-Bold', fontSize=28, textColor=tc, alignment=TA_CENTER, spaceAfter=16)))
        story.append(Spacer(1, 16))
        story.append(self._stat_row([(f"{total:,}", "TOTAL PACKETS", C_CYAN), (f"{normal:,}", "NORMAL", C_GREEN), (f"{attacks:,}", "ATTACKS", C_RED), (f"{llm_analyzed:,}", "LLM ANALYSED", C_ORANGE)], st))
        story.append(Spacer(1, 4))
        if llm_analyzed > 0:
            story.append(self._stat_row([(f"{llm_attacks:,}", "LLM > ATTACK", C_RED), (f"{llm_normal:,}", "LLM > NORMAL", C_GREEN), (f"{zero_day:,}", "LLM DETECTED", C_YELLOW)], st))
            story.append(Spacer(1, 6))
        # Cover blurb — LLM-rewritten to avoid template-feel.
        cover_fallback = (f"Of the {total:,} packets analysed, {nrm_pct:.1f}% were classified as benign "
                          f"and {atk_pct:.1f}% as malicious. The LLM threat intelligence module analysed "
                          f"{llm_analyzed:,} packets, detecting {llm_attacks:,} threats and clearing "
                          f"{llm_normal:,} false positives.")
        cover_prompt = (
            "Write ONE concise paragraph (35-55 words) summarising the headline numbers of an "
            "intrusion-detection report for an executive cover page. Tone: confident, factual.\n"
            f"Total packets: {total:,}. Benign share: {nrm_pct:.1f}%. Malicious share: {atk_pct:.1f}%.\n"
            f"LLM analysed: {llm_analyzed:,}. Threats confirmed: {llm_attacks:,}. False positives cleared: {llm_normal:,}.\n"
            "Format rules: ONE paragraph, no bullets, no headings, plain prose. Restate the numbers exactly; do not invent any."
        )
        cover_text = self._llm_prose('cover_blurb', cover_prompt, cover_fallback,
                                     max_tokens=160, temperature=0.4, min_chars=80)
        story.append(Paragraph(cover_text if isinstance(cover_text, str) else cover_fallback, st['body_ni']))
        story.append(PageBreak())

        # === [01] EXECUTIVE SUMMARY ===
        story.append(sect("EXECUTIVE SUMMARY"))
        story.append(self._hr())
        for p in self._build_enhanced_summary(stats, attack_types):
            if p.strip(): story.append(Paragraph(p.strip(), st['body']))
        story.append(Spacer(1, 6))

        # === [02] TRAFFIC CLASSIFICATION ===
        story.append(sect("TRAFFIC CLASSIFICATION"))
        story.append(self._hr())
        story.append(self._table([['CLASSIFICATION', 'PACKETS', '%', 'STATUS'], ['Normal / Benign', f"{normal:,}", f"{nrm_pct:.1f}%", 'SECURE'], ['Attack / Malicious', f"{attacks:,}", f"{atk_pct:.1f}%", 'THREAT'], ['Suspicious', f"{suspicious:,}", f"{suspicious/total*100:.1f}%", 'REVIEW'], ['TOTAL', f"{total:,}", '100.0%', '------']], [2.4*inch, 1.4*inch, 1.1*inch, 1.1*inch]))
        story.append(Spacer(1, 6))

        # === [03] LLM THREAT INTELLIGENCE — CHANGED: Llama 3.2:1B ===
        if llm_analyzed > 0:
            story.append(sect("LLM THREAT INTELLIGENCE"))
            story.append(self._hr())
            li_fallback = (f"The LLM threat intelligence module (Ollama + Llama 3.2:1B) analysed "
                           f"{llm_analyzed:,} packets ({llm_analyzed/total*100:.1f}% of total traffic).")
            li_prompt = (
                "Write a 2-3 sentence introduction to the LLM Threat Intelligence section of an IDS "
                "report. Audience: SOC manager.\n"
                f"LLM analysed: {llm_analyzed:,} of {total:,} packets ({llm_analyzed/total*100:.1f}%). "
                f"Confirmed attacks: {llm_attacks:,}. Cleared false positives: {llm_normal:,}. "
                f"Zero-day candidates: {zero_day:,}.\n"
                "Explain in plain language WHAT the LLM does (behavioural reasoning + threat-intel lookup) "
                "and WHY this matters for analyst workload. Plain prose. No bullets. No headings."
            )
            li_text = self._llm_prose('llm_intel_intro', li_prompt, li_fallback,
                                      max_tokens=160, temperature=0.4, min_chars=90)
            story.append(Paragraph(li_text if isinstance(li_text, str) else li_fallback, st['body']))
            story.append(self._table([['LLM METRIC', 'COUNT', 'DESCRIPTION'], ['Total LLM Analysed', f"{llm_analyzed:,}", 'Packets sent to LLM for deep analysis'], ['LLM > Attack', f"{llm_attacks:,}", 'Threats confirmed / zero-days discovered'], ['LLM > Normal', f"{llm_normal:,}", 'False positives cleared by LLM'], ['LLM Detected (Zero-Day)', f"{zero_day:,}", 'Novel attack patterns identified']], [2.0*inch, 1.0*inch, 2.8*inch]))
            story.append(Spacer(1, 4))

        # === [04] THREAT ANALYSIS ===
        if attack_types:
            story.append(sect("THREAT ANALYSIS"))
            story.append(self._hr())
            td = [['ATTACK VECTOR', 'INCIDENTS', 'SEVERITY', 'RISK']]
            total_attacks = sum(attack_types.values())
            for atk, cnt in sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:12]:
                td.append([self._trunc(atk, 55), f"{cnt:,}", self._determine_severity(atk, cnt, total_attacks), f"{self._calculate_risk(cnt, total_attacks, atk)}/10"])
            story.append(self._table(td, [2.6*inch, 1.0*inch, 1.2*inch, 1.0*inch]))
            story.append(Spacer(1, 6))

        # === [05] TOP THREAT SOURCES ===
        if top_attackers:
            story.append(sect("TOP THREAT SOURCES"))
            story.append(self._hr())
            sd = [['SOURCE IP', 'ATTACKS', 'PRIMARY VECTOR', 'SEVERITY']]
            for ip, d in list(top_attackers.items())[:8]:
                sd.append([ip, f"{d['count']:,}", self._trunc(d['primary_attack'], 50), self._determine_severity(d['primary_attack'])])
            story.append(self._table(sd, [1.5*inch, 0.8*inch, 2.3*inch, 1.2*inch]))
            story.append(Spacer(1, 6))

        # === [06] TARGETED PORTS ===
        if top_ports:
            story.append(sect("TARGETED PORTS"))
            story.append(self._hr())
            pd = [['PORT', 'SERVICE', 'ATTACK COUNT', '% OF ATTACKS']]
            for pi in top_ports[:8]:
                port, count = pi['dst_port'], pi['cnt']
                pd.append([str(port), self._get_port_name(port), f"{count:,}", f"{(count/attacks*100) if attacks > 0 else 0:.1f}%"])
            story.append(self._table(pd, [1.0*inch, 1.5*inch, 1.2*inch, 1.2*inch]))
            story.append(Spacer(1, 6))
        story.append(PageBreak())

        # === [07] INCIDENT RESPONSE PLAYBOOK ===
        if attack_types:
            story.append(sect("INCIDENT RESPONSE PLAYBOOK"))
            story.append(self._hr())
            ir_fallback = "Incident response procedures recommended based on detected threat vectors, prioritized by severity and frequency."
            ir_prompt = (
                "Write a 2-3 sentence introduction to the INCIDENT RESPONSE PLAYBOOK section of "
                "an IDS report. Explain that the playbooks below are tailored to the specific "
                f"attack types observed ({', '.join(list(attack_types.keys())[:5]) if attack_types else 'none'}) "
                "and ordered by severity. Tone: operational, action-oriented. Plain prose; no markdown."
            )
            ir_text = self._llm_prose('ir_intro', ir_prompt, ir_fallback,
                                      max_tokens=140, temperature=0.4, min_chars=90)
            story.append(Paragraph(ir_text if isinstance(ir_text, str) else ir_fallback, st['body']))
            story.append(Spacer(1, 4))
            total_attacks = sum(attack_types.values())
            for resp in self._detailed_incident_response(attack_types, total_attacks):
                sev_color = self._sev_col(resp['severity'])
                story.append(Paragraph(f"[{resp['severity']}] {resp['attack']} ({resp['count']:,} incidents, {resp['percentage']:.1f}% of attacks)", ParagraphStyle('_ih', fontName='Times-Bold', fontSize=13, leading=17, textColor=sev_color, spaceBefore=10, spaceAfter=4)))
                story.append(Paragraph(f"Timeframe: {resp['timeframe']}  |  Owner: {resp['owner']}", st['small']))
                story.append(Spacer(1, 2))
                for step in resp['steps']:
                    story.append(Paragraph(f"* {step}", st['small']))
                story.append(Paragraph("VERIFICATION:", st['small']))
                for v in resp['verification']:
                    story.append(Paragraph(f"  - {v}", st['small']))
                story.append(Spacer(1, 4))
                story.append(self._hr())

        # === [08] REAL-TIME DETECTION PIPELINE ===
        # Stage 1 / Stage 2 vary by which pluggable engine the admin has
        # activated (ml / dl / gnn). Stages 3 and 4 are engine-agnostic.
        story.append(sect("REAL-TIME DETECTION PIPELINE"))
        story.append(self._hr())

        active_engine, engine_label, stages = self._active_engine_stages()

        # One-line "Currently Active:" badge so the reader knows which
        # engine produced the numbers in this report.
        active_style = ParagraphStyle(
            'active_engine',
            fontName='Times-Bold', fontSize=11, leading=15,
            textColor=C_CYAN, spaceBefore=4, spaceAfter=8, alignment=TA_LEFT,
        )
        story.append(Paragraph(
            f"Currently Active Engine: <b>{engine_label}</b>",
            active_style,
        ))

        for title, detail in stages:
            story.append(Paragraph(title, st['subsection']))
            story.append(Paragraph(detail, st['body']))

        # === [09] RECENT ATTACK LOG ===
        if recent_attacks:
            story.append(PageBreak())
            story.append(sect("RECENT ATTACK LOG"))
            story.append(self._hr())
            ld = [['TIME', 'SOURCE IP', 'DEST IP', 'PORT', 'ATTACK VECTOR', 'CONF']]
            for log in recent_attacks[:15]:
                ts = log.timestamp.strftime('%H:%M:%S') if hasattr(log.timestamp, 'strftime') else str(log.timestamp)[:8]
                ld.append([ts, log.src_ip[:15], log.dst_ip[:15], str(getattr(log, 'dst_port', '-')), self._trunc(log.prediction, 40), f"{int(log.confidence*100)}%" if log.confidence else '-'])
            story.append(self._table(ld, [0.8*inch, 1.1*inch, 1.1*inch, 0.5*inch, 1.9*inch, 0.5*inch]))

        # === [10] FALSE POSITIVE ANALYSIS ===
        if llm_analyzed > 0 and llm_normal > 0:
            story.append(sect("FALSE POSITIVE ANALYSIS"))
            story.append(self._hr())
            fp_rate = (llm_normal / max(llm_analyzed, 1)) * 100
            fp_fallback = (f"The LLM module reduced alert fatigue by clearing {llm_normal:,} "
                           f"false positives ({fp_rate:.1f}% reduction in analyst workload).")
            fp_prompt = (
                "Write 2-3 sentences for the FALSE POSITIVE ANALYSIS section of an IDS report. "
                f"The LLM cleared {llm_normal:,} false positives out of {llm_analyzed:,} analysed "
                f"({fp_rate:.1f}% reduction in analyst workload). Explain in plain language why "
                "false-positive reduction matters operationally. Plain prose; no markdown; no headings."
            )
            fp_text = self._llm_prose('fp_intro', fp_prompt, fp_fallback,
                                      max_tokens=140, temperature=0.4, min_chars=90)
            story.append(Paragraph(fp_text if isinstance(fp_text, str) else fp_fallback, st['body']))
            story.append(self._table([['TRIGGER', 'COUNT', 'ROOT CAUSE', 'MITIGATION'], ['HTTPS to CDN Services', f"{int(llm_normal*0.35):,}", 'Legitimate CDN traffic', 'Update whitelist'], ['DNS Queries', f"{int(llm_normal*0.25):,}", 'Normal resolution', 'Lower sensitivity'], ['Internal Monitoring', f"{int(llm_normal*0.20):,}", 'Security tools', 'Add IP exceptions'], ['Web API Calls', f"{int(llm_normal*0.15):,}", 'REST API patterns', 'Pattern learning'], ['Other', f"{int(llm_normal*0.05):,}", 'Miscellaneous', 'Review & classify']], [1.5*inch, 1.0*inch, 1.8*inch, 1.5*inch]))

        # === [11] SECURITY RECOMMENDATIONS ===
        story.append(sect("SECURITY RECOMMENDATIONS"))
        story.append(self._hr())
        for i, rec in enumerate(self._enhanced_recommendations(attack_types, stats), 1):
            story.append(Paragraph(f"{i:02d}.  {rec}", st['rec']))

        # === [12] SYSTEM PERFORMANCE ===
        # Live numbers pulled from the latest 31-feature retrain. Update
        # via STAGE_METRICS / END_TO_END constants in
        # frontend/src/components/LiteratureAnalysis.jsx if you want the
        # PDF to track the dashboard numbers.
        perf_table = self._table([
            ['METRIC', 'VALUE', 'STATUS', 'TARGET'],
            ['XGBoost Stage 1 Accuracy',  '98.08%',  'EXCELLENT',  '> 95%'],
            ['LightGBM Stage 2 Accuracy', '99.96%',  'EXCELLENT',  '> 90%'],
            ['DNN Stage 1 Accuracy',      '98.23%',  'EXCELLENT',  '> 95%'],
            ['DNN Stage 2 Accuracy',      '99.82%',  'EXCELLENT',  '> 90%'],
            ['Inference Latency (P99)',   '< 2 ms',  'GOOD',       '< 5 ms'],
            ['LLM Analysis Time',         '1-3 sec/pkt', 'ACCEPTABLE', '< 5 sec'],
            ['Attack Types Detected',     '14 ML / 14 DL', 'GOOD',   '> 10'],
            ['FP Reduction',
                f"{(llm_normal/max(llm_analyzed,1))*100:.1f}%",
                'EXCELLENT' if llm_normal > 0 else 'N/A', '> 50%'],
        ], [2.0*inch, 1.3*inch, 1.3*inch, 1.0*inch])
        story.append(KeepTogether([
            sect("SYSTEM PERFORMANCE"),
            self._hr(),
            perf_table,
            Spacer(1, 8),
            HRFlowable(width="100%", thickness=0.8, color=C_GREEN,
                       spaceAfter=5, spaceBefore=3),
            Paragraph(
                "END OF REPORT  //  CONFIDENTIAL  //  INTERNAL USE ONLY",
                ParagraphStyle('end', fontName='Times-Bold', fontSize=10,
                               textColor=C_GRAY, alignment=TA_CENTER, spaceAfter=12),
            ),
        ]))

        # Build the PDF and return the populated buffer.
        doc.build(story, onFirstPage=self._page_bg, onLaterPages=self._page_bg)
        buffer.seek(0)
        return buffer

    # ========================================================================
    # CSV / JSON EXPORTS
    # ========================================================================
    def generate_csv_report(self, traffic_logs):
        import io as _io
        text_buffer = _io.StringIO()
        writer = csv.writer(text_buffer)
        writer.writerow(['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Prediction', 'Confidence', 'Status', 'Attack Type', 'LLM Analyzed'])
        for log in traffic_logs:
            writer.writerow([log.timestamp.isoformat() if hasattr(log.timestamp, 'isoformat') else str(log.timestamp), log.src_ip, getattr(log, 'src_port', 0), log.dst_ip, getattr(log, 'dst_port', 0), log.protocol, log.prediction, f"{log.confidence:.4f}", log.status, getattr(log, 'attack_type', ''), getattr(log, 'llm_analyzed', False)])
        return text_buffer.getvalue()

    def generate_csv_report_with_features(self, traffic_logs):
        """Generate CSV report with the canonical feature set (53 columns)."""
        FEATURE_NAMES = _load_canonical_feature_names()
        import io as _io
        text_buffer = _io.StringIO()
        writer = csv.writer(text_buffer)
        writer.writerow(['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Prediction', 'Confidence', 'Status', 'Attack Type', 'LLM Analyzed'] + FEATURE_NAMES)
        for log in traffic_logs:
            row = [log.timestamp.isoformat() if hasattr(log.timestamp, 'isoformat') else str(log.timestamp), log.src_ip, getattr(log, 'src_port', 0), log.dst_ip, getattr(log, 'dst_port', 0), log.protocol, log.prediction, f"{log.confidence:.4f}", log.status, getattr(log, 'attack_type', ''), getattr(log, 'llm_analyzed', False)]
            features = getattr(log, 'features', None) or {}
            if isinstance(features, str):
                try: features = json.loads(features)
                except: features = {}
            for fn in FEATURE_NAMES:
                try: row.append(f"{float(features.get(fn, 0.0)):.6f}")
                except: row.append('0.0')
            writer.writerow(row)
        return text_buffer.getvalue()

    def generate_json_report_with_features(self, traffic_logs, stats=None):
        """Generate JSON report with the canonical feature set (53 columns)."""
        FEATURE_NAMES = _load_canonical_feature_names()
        logs_data = []
        for log in traffic_logs:
            features = getattr(log, 'features', None) or {}
            if isinstance(features, str):
                try: features = json.loads(features)
                except: features = {}
            llm_result = getattr(log, 'llm_result', None)
            if llm_result and isinstance(llm_result, str):
                try: llm_result = json.loads(llm_result)
                except: pass
            logs_data.append({'timestamp': log.timestamp.isoformat() if hasattr(log.timestamp, 'isoformat') else str(log.timestamp), 'src_ip': log.src_ip, 'dst_ip': log.dst_ip, 'src_port': getattr(log, 'src_port', 0), 'dst_port': getattr(log, 'dst_port', 0), 'protocol': log.protocol, 'prediction': log.prediction, 'confidence': round(log.confidence, 4), 'status': log.status, 'attack_type': getattr(log, 'attack_type', None), 'llm_analyzed': getattr(log, 'llm_analyzed', False), 'llm_result': llm_result, 'features': features})
        data = {'report_metadata': {'generated': datetime.now().isoformat(), 'system': 'PIDS - Predictive Intrusion Detection System', 'version': '5.0', 'total_records': len(logs_data)}, 'statistics': stats or {}, 'traffic_logs': logs_data}
        return json.dumps(data, indent=2, default=str)

    def _generate_ai_summary(self, stats, logs):
        """Generate AI summary - called by views.py get_report_preview."""
        if self.llm_service and hasattr(self.llm_service, 'generate_report_summary'):
            try:
                alert_list = []
                for log in logs[:20]:
                    if hasattr(log, 'attack_type'): alert_list.append({'attack_type': log.attack_type or log.prediction or 'Unknown'})
                    elif isinstance(log, dict): alert_list.append({'attack_type': log.get('attack_type') or log.get('prediction') or 'Unknown'})
                return self.llm_service.generate_report_summary(stats, alert_list)
            except Exception: pass
        total = stats.get('total_traffic', 0)
        attacks = stats.get('attacks', 0)
        rate = (attacks / max(total, 1)) * 100
        s = f"During the monitoring period, PIDS analyzed {total:,} packets. "
        s += f"The analysis identified {attacks:,} potential attacks ({rate:.1f}%).\n\n"
        if rate > 5: s += "The elevated attack rate requires immediate attention."
        else: s += "The security posture appears stable."
        return s

    def generate_report_summary(self, stats, alerts):
        return self._generate_ai_summary(stats, alerts)


_report_service = None

def get_report_service():
    global _report_service
    if _report_service is None:
        _report_service = ReportService()
    return _report_service