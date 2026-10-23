"""
SentinelSOC -- Project Report PDF Generator
Run:    python generate_report.py
Output: SentinelSOC_Project_Report.pdf

Uses only built-in Helvetica/Courier fonts (no external TTF needed).
All text is ASCII/latin-1 safe.
"""
from fpdf import FPDF, XPos, YPos
from datetime import datetime

# ---------------------------------------------------------------
#  Colour palette
# ---------------------------------------------------------------
DARK_BG     = (13,  17,  23)
NAVY        = (22,  27,  34)
NAVY2       = (30,  37,  50)
ACCENT      = (9,  105, 218)
LIGHT_BLUE  = (88, 166, 255)
TEXT_DARK   = (31,  35,  40)
TEXT_MUTED  = (87,  96, 106)
WHITE       = (255, 255, 255)
RED         = (207,  34,  46)
ORANGE      = (188,  76,   0)
YELLOW_D    = (154, 103,   0)
GREEN       = ( 26, 127,  55)
BORDER      = (208, 215, 222)
ROW_ALT     = (246, 248, 250)
CYAN        = ( 30,  80, 160)


class Report(FPDF):
    def __init__(self):
        super().__init__("P", "mm", "A4")
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(20, 14, 20)

    # ---- colour helpers ----------------------------------------
    def fc(self, rgb):  self.set_text_color(*rgb)
    def dc(self, rgb):  self.set_draw_color(*rgb)
    def bc(self, rgb):  self.set_fill_color(*rgb)

    def hline(self, color=BORDER, lw=0.3):
        self.dc(color); self.set_line_width(lw)
        self.line(self.l_margin, self.get_y(),
                  self.w - self.r_margin, self.get_y())
        self.ln(3)

    # ---- layout helpers ----------------------------------------
    def section(self, title, color=ACCENT):
        self.ln(5)
        self.set_font("Helvetica", "B", 13)
        self.fc(color)
        self.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.hline(color, 0.5)
        self.fc(TEXT_DARK)

    def sub(self, title):
        self.ln(2)
        self.set_font("Helvetica", "B", 10)
        self.fc(ACCENT)
        self.cell(0, 6, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.fc(TEXT_DARK)
        self.ln(1)

    def body(self, text, size=9.5):
        self.set_font("Helvetica", "", size)
        self.fc(TEXT_MUTED)
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    def kv(self, key, val, alt=False):
        fill = alt
        if alt: self.bc(ROW_ALT)
        self.set_font("Helvetica", "B", 9); self.fc(TEXT_DARK)
        self.cell(58, 7, key, fill=fill)
        self.set_font("Helvetica", "",  9); self.fc(TEXT_MUTED)
        self.cell(0,  7, val, fill=fill, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def thead(self, cols):
        self.bc(NAVY); self.fc(WHITE)
        self.set_font("Helvetica", "B", 8.5)
        for lbl, w in cols:
            self.cell(w, 7, lbl, fill=True)
        self.ln()

    def trow(self, vals_widths, alt=False):
        self.bc(ROW_ALT if alt else WHITE)
        self.fc(TEXT_DARK); self.set_font("Helvetica", "", 8.5)
        for val, w in vals_widths:
            self.cell(w, 6.5, str(val), fill=True)
        self.ln()

    # ---- cover page --------------------------------------------
    def cover(self):
        # full dark background
        self.bc(DARK_BG); self.rect(0, 0, self.w, self.h, "F")
        # top accent bar
        self.bc(ACCENT); self.rect(0, 0, self.w, 4, "F")
        # header band
        self.bc(NAVY2); self.rect(0, 4, self.w, 72, "F")

        # title
        self.set_y(20)
        self.set_font("Helvetica", "B", 34); self.fc(WHITE)
        self.cell(0, 13, "SentinelSOC", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Helvetica", "", 13); self.fc((88, 166, 255))
        self.cell(0, 8, "Mini Security Operations Center", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Helvetica", "I", 10); self.fc((139, 148, 158))
        self.cell(0, 6, "Detect . Investigate . Defend", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # divider
        self.set_y(80)
        self.dc(ACCENT); self.set_line_width(0.8)
        self.line(20, self.get_y(), self.w-20, self.get_y())

        # meta
        self.ln(8)
        meta = [
            ("Project Type", "Cybersecurity Web Application"),
            ("Purpose",      "IBM Cybersecurity Bootcamp -- Final Project"),
            ("Technology",   "Python 3.14 . Flask 3.1 . SQLite . Chart.js"),
            ("Version",      "1.0"),
            ("Generated",    datetime.now().strftime("%B %d, %Y  %H:%M")),
        ]
        for k, v in meta:
            self.set_font("Helvetica", "B", 9); self.fc((139, 148, 158))
            self.cell(42, 7, k.upper() + ":", align="R")
            self.set_font("Helvetica", "", 9); self.fc(WHITE)
            self.cell(0, 7, v, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # stats row
        self.set_y(148)
        stats = [("1","App File"), ("47","Tests Pass"), ("5","Det. Rules"),
                 ("9","Pages"), ("3","User Roles")]
        cw = (self.w - 40) / len(stats)
        for val, lbl in stats:
            x = self.get_x()
            self.bc((22, 27, 34)); self.dc((48, 54, 61))
            self.rect(x, self.get_y(), cw-4, 22, "FD")
            self.set_font("Helvetica", "B", 18); self.fc(LIGHT_BLUE)
            self.cell(cw-4, 13, val, align="C")
            self.set_xy(x, self.get_y()+13)
            self.set_font("Helvetica", "", 7); self.fc((139, 148, 158))
            self.cell(cw-4, 6, lbl.upper(), align="C",
                      new_x=XPos.RIGHT, new_y=YPos.TMARGIN)
            self.set_xy(self.get_x()+4, 148)
        self.ln(30)

        # warning banner
        self.bc((62, 46, 0))
        self.rect(20, self.get_y(), self.w-40, 12, "F")
        self.set_x(20)
        self.set_font("Helvetica", "B", 8.5); self.fc((227, 179, 65))
        self.cell(self.w-40, 12,
                  "[!] DEMO DATA -- Educational Prototype -- Not for Production Use",
                  align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # bottom bar
        self.bc(ACCENT); self.rect(0, self.h-4, self.w, 4, "F")

    # ---- running header/footer ---------------------------------
    def header(self):
        if self.page_no() == 1: return
        self.bc(NAVY); self.rect(0, 0, self.w, 10, "F")
        self.set_font("Helvetica", "B", 8); self.fc(LIGHT_BLUE)
        self.set_y(2)
        self.cell(0, 6, "SentinelSOC -- Project Report",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_y(13)

    def footer(self):
        if self.page_no() == 1: return
        self.set_y(-12)
        self.hline(BORDER, 0.2)
        self.set_font("Helvetica", "", 7.5); self.fc(TEXT_MUTED)
        self.cell(0, 5,
            f"SentinelSOC Project Report  |  Page {self.page_no()}  |  IBM Cybersecurity Bootcamp",
            align="C")


# ================================================================
#  CONTENT
# ================================================================
def build():
    pdf = Report()

    # ---- Cover -------------------------------------------------
    pdf.add_page()
    pdf.cover()

    # ---- Page 2: Overview & Objectives -------------------------
    pdf.add_page()
    pdf.section("1.  Project Overview")
    pdf.body(
        "SentinelSOC (Mini Security Operations Center) is a full-stack defensive cybersecurity "
        "web application built for the IBM Cybersecurity Bootcamp. It ingests security log files, "
        "detects suspicious authentication patterns using five rule-based detection algorithms, "
        "generates explainable alerts, manages security incidents, and presents all findings in a "
        "professional dashboard with light and dark mode support."
    )

    pdf.section("2.  Problem Statement")
    pdf.body(
        "Security Operations Center analysts review thousands of log events every day. Manually "
        "identifying attack patterns -- such as brute-force login attempts or password spraying -- "
        "from raw log data is slow, error-prone, and exhausting.\n\n"
        "SentinelSOC demonstrates how a rule-based detection engine can automatically surface "
        "suspicious patterns so analysts can focus on investigation and response rather than log "
        "triage. Every alert includes a plain-English explanation and evidence so the analyst "
        "always understands WHY the alert fired."
    )

    pdf.section("3.  Objectives")
    objectives = [
        "Process CSV and JSON Lines security log files uploaded by analysts.",
        "Normalize raw log fields (timestamps, IPs, auth results) into a consistent format.",
        "Detect five categories of suspicious authentication behaviour automatically.",
        "Generate explainable alerts with full evidence and investigation recommendations.",
        "Allow analysts to manage alert status and escalate to incidents.",
        "Track incident investigations with notes, linked alerts, and resolution records.",
        "Export events, alerts, and reports as CSV for further analysis.",
        "Provide a professional responsive security dashboard (dark + light mode).",
        "Protect the application with login auth, input validation, and security headers.",
        "Pass a full automated test suite (47 tests) covering all core features.",
    ]
    for i, obj in enumerate(objectives, 1):
        pdf.set_font("Helvetica", "B", 9); pdf.fc(ACCENT)
        pdf.cell(8, 6, f"{i}.")
        pdf.set_font("Helvetica", "", 9); pdf.fc(TEXT_MUTED)
        pdf.cell(0, 6, obj, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ---- Page 3: Architecture ----------------------------------
    pdf.add_page()
    pdf.section("4.  System Architecture")
    pdf.body(
        "SentinelSOC is implemented as a single Python file using the Flask micro-framework. "
        "The architecture follows a layered design: HTTP routes delegate to service functions "
        "that operate on a SQLite database. All templates are rendered server-side using Jinja2. "
        "Chart.js handles client-side data visualisation."
    )

    pdf.sub("Architecture Diagram")
    arch_lines = [
        "  Browser (HTML / CSS / JavaScript / Chart.js)",
        "       |",
        "       v  HTTP",
        "  +--------------------------------------------+",
        "  |        sentinelsoc.py  (Flask App)         |",
        "  |                                            |",
        "  |  Routes --> Service Functions --> SQLite   |",
        "  |                                            |",
        "  |  /dashboard  /events   /alerts             |",
        "  |  /incidents  /ingestion  /rules            |",
        "  |  /reports    /settings  /about             |",
        "  |  /how-to-use  /customer-care               |",
        "  |                                            |",
        "  |  Log Parser --> Normalizer                 |",
        "  |             --> Detection Engine           |",
        "  |                  +-- Rule 1: Brute Force   |",
        "  |                  +-- Rule 2: Password Spray|",
        "  |                  +-- Rule 3: Success/Fail  |",
        "  |                  +-- Rule 4: Lockout Spike |",
        "  |                  +-- Rule 5: Multi-IP      |",
        "  +--------------------------------------------+",
    ]
    pdf.bc(NAVY2)
    box_h = len(arch_lines) * 4.8 + 6
    pdf.rect(pdf.l_margin, pdf.get_y(),
             pdf.w - pdf.l_margin - pdf.r_margin, box_h, "F")
    pdf.set_font("Courier", "", 8); pdf.fc(LIGHT_BLUE)
    pdf.set_x(pdf.l_margin + 3)
    for line in arch_lines:
        pdf.cell(0, 4.8, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(pdf.l_margin + 3)
    pdf.ln(4); pdf.fc(TEXT_DARK)

    pdf.sub("Technology Stack")
    stack = [
        ("Backend Language",  "Python 3.14"),
        ("Web Framework",     "Flask 3.1"),
        ("Database",          "SQLite (WAL mode, parameterized queries)"),
        ("Frontend",          "HTML5 / CSS3 / Vanilla JavaScript"),
        ("Charts",            "Chart.js 4"),
        ("Icons",             "Lucide Icons (CDN)"),
        ("Testing",           "pytest 8 + pytest-cov"),
        ("Authentication",    "Session-based (demo credentials)"),
        ("PDF Generation",    "fpdf2"),
        ("Deployment",        "Local -- python sentinelsoc.py"),
    ]
    for i, (k, v) in enumerate(stack):
        pdf.kv(k, v, alt=(i % 2 == 0))
    pdf.ln(2)

    # ---- Page 4: Database & Security ---------------------------
    pdf.add_page()
    pdf.section("5.  Database Schema")
    pdf.body("SQLite database with 7 tables, foreign key constraints, and indexes on "
             "frequently queried columns. All queries use parameterized statements.")

    tables = [
        ("security_events",    "Parsed log events: timestamp, source_ip, username, event_type, auth_result"),
        ("ingestion_batches",  "Each file upload: filename, accepted/rejected counts, format, ingested_at"),
        ("detection_rules",    "Built-in rules: rule_key, name, severity, threshold, window_minutes"),
        ("alerts",             "Generated alerts: rule_key, severity, status, evidence (JSON), dedup_key"),
        ("incidents",          "Investigation records: title, severity, status, assigned_to, resolution"),
        ("incident_alerts",    "Many-to-many join: links alerts to incidents"),
        ("incident_notes",     "Free-text notes attached to incidents with author and timestamp"),
    ]
    cols = [("Table Name", 52), ("Purpose & Key Columns", 130)]
    pdf.thead(cols)
    for i, (tbl, desc) in enumerate(tables):
        pdf.bc(ROW_ALT if i % 2 else WHITE)
        pdf.set_font("Courier", "B" if i % 2 == 0 else "", 8); pdf.fc(ACCENT)
        pdf.cell(52, 6.5, tbl, fill=True)
        pdf.set_font("Helvetica", "", 8); pdf.fc(TEXT_MUTED)
        pdf.cell(130, 6.5, desc, fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    pdf.sub("Security Controls")
    measures = [
        ("SQL Injection",       "All queries use parameterized statements -- no string concatenation"),
        ("XSS",                 "Jinja2 auto-escaping on all template variables"),
        ("Path Traversal",      "os.path.basename() strips directory components from filenames"),
        ("File Upload",         "5 MB limit; decoded safely; files never stored to disk or executed"),
        ("CSV Injection",       "Cells starting with =+-@|% prefixed with apostrophe"),
        ("Security Headers",    "X-Content-Type-Options, X-Frame-Options, X-XSS-Protection"),
        ("Input Validation",    "Status and severity values checked against explicit allowlists"),
        ("Authentication",      "Session-based login; all routes protected by before_request hook"),
        ("No Auto-Remediation", "App never blocks IPs, locks accounts, or runs system commands"),
    ]
    for i, (k, v) in enumerate(measures):
        pdf.kv(k, v, alt=(i % 2 == 0))

    # ---- Page 5: Detection Rules --------------------------------
    pdf.add_page()
    pdf.section("6.  Detection Rules")
    pdf.body(
        "All five rules are configurable (threshold and time window adjustable in Settings). "
        "Each alert includes evidence referencing the underlying events and a deduplication key "
        "to prevent the same alert from being generated twice."
    )

    rules = [
        ("Rule 1", "Repeated Failed Logins (Brute Force)",
         "HIGH",    RED,
         "5+ failed login attempts from the same source IP within 5 minutes.",
         "Investigate the source IP. Review affected accounts."),
        ("Rule 2", "Multiple-Account Login Failures (Password Spray)",
         "HIGH",    RED,
         "1 source IP failing against 3+ distinct usernames within 10 minutes.",
         "Review all targeted accounts. Investigate the source IP."),
        ("Rule 3", "Successful Login After Repeated Failures",
         "HIGH",    RED,
         "3+ failures for same username+IP followed by a success within 10 minutes.",
         "Contact the account owner to verify the login was legitimate."),
        ("Rule 4", "Account Lockout Spike",
         "MEDIUM", ORANGE,
         "5+ account lockout events within 10 minutes.",
         "Unlock affected accounts. Identify source of failed attempts."),
        ("Rule 5", "Suspicious Authentication Pattern (Multi-IP)",
         "MEDIUM", ORANGE,
         "3+ distinct source IPs failing against the same account within 15 minutes.",
         "Verify with the account owner. Preserve relevant log entries."),
    ]
    for rid, name, sev, sev_col, trigger, rec in rules:
        pdf.bc(ROW_ALT)
        pdf.rect(pdf.l_margin, pdf.get_y(),
                 pdf.w - pdf.l_margin - pdf.r_margin, 27, "F")
        pdf.set_font("Helvetica", "B", 9); pdf.fc(TEXT_DARK)
        pdf.cell(16, 6, rid)
        pdf.fc(ACCENT)
        pdf.cell(0, 6, name, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_x(pdf.l_margin + 16)
        pdf.bc(sev_col); pdf.fc(WHITE)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(18, 5, sev, fill=True, align="C")
        pdf.fc(TEXT_MUTED); pdf.set_font("Helvetica", "", 8.5)
        pdf.cell(0, 5, "  " + trigger,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_x(pdf.l_margin + 16)
        pdf.set_font("Helvetica", "B", 8); pdf.fc(GREEN)
        pdf.cell(22, 5, "REC: ")
        pdf.set_font("Helvetica", "", 8); pdf.fc(TEXT_MUTED)
        pdf.cell(0, 5, rec, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)

    # ---- Page 6: Features & Tests ------------------------------
    pdf.add_page()
    pdf.section("7.  Application Features")
    features = [
        ("Overview Dashboard",   "Event/alert counts, Chart.js trend + donut + bar charts, recent tables"),
        ("Security Events",      "Paginated list, search/filter by IP/user/result/date, CSV export"),
        ("Alerts",               "Alert list, severity badges, detail view, status update, incident creation"),
        ("Incidents",            "Create, link alerts, add notes, assign analyst, status, resolution"),
        ("Log Ingestion",        "CSV + JSON Lines upload, drag-and-drop, validation summary, auto-detection"),
        ("Detection Rules",      "View 5 rules with description, threshold, window, alert count"),
        ("Reports",              "Aggregated metrics, trend charts, top rules/IPs, printable report, CSV exports"),
        ("Settings",             "Per-rule threshold/window config, manual detection run, demo data reset"),
        ("About Website",        "Platform info, user roles, tech stack, important notices"),
        ("How to Use",           "8-step workflow guide, log format reference, alert status guide, tips"),
        ("Customer Care",        "Contact cards (email/chat/phone), FAQ accordion, contact form"),
        ("Dark / Light Mode",    "Toggle button in topbar; choice saved in localStorage; no page flash"),
        ("Login / Logout",       "3 demo accounts (admin/analyst/viewer); all routes protected"),
    ]
    cols = [("Feature", 52), ("Description", 130)]
    pdf.thead(cols)
    for i, (f, d) in enumerate(features):
        pdf.trow([(f, 52), (d, 130)], alt=(i % 2 == 0))
    pdf.ln(4)

    pdf.section("8.  Test Results")
    pdf.body("Automated test suite using pytest. All 47 tests pass on Python 3.14 -- 0 failures, 0 warnings.")

    test_groups = [
        ("CSV Parsing",            5,  "Valid, missing cols, empty, header-only, extra cols"),
        ("JSON Lines Parsing",     3,  "Valid, invalid lines, blank lines skipped"),
        ("Log Normalizer",         7,  "Valid record, bad ts, missing type, bad IP, auth mapping"),
        ("Brute Force Rule",       4,  "Threshold, below threshold, window boundary, dedup"),
        ("Password Spray Rule",    2,  "Multi-account trigger, same account (no spray)"),
        ("Success After Fail",     2,  "Trigger on success after fails, no trigger on solo success"),
        ("Lockout Spike Rule",     2,  "Spike trigger, below threshold"),
        ("Multi-IP Rule",          1,  "Multiple IPs targeting same account"),
        ("Empty Database",         4,  "Detection, dashboard, alerts page, incidents page"),
        ("Alert Status",           3,  "Update, invalid rejected, all valid statuses"),
        ("Incident Management",    5,  "Create, empty title, note, link alert, invalid ID"),
        ("File Upload",            4,  "Valid CSV, valid JSONL, no file, invalid records"),
        ("CSV Export Safety",      3,  "Formula injection, normal values, None handling"),
        ("DB Persistence",         2,  "Events stored, alerts across connections"),
    ]
    cols2 = [("Test Category", 58), ("Count", 16), ("Coverage", 108)]
    pdf.thead(cols2)
    total = 0
    for i, (cat, cnt, cov) in enumerate(test_groups):
        pdf.bc(ROW_ALT if i % 2 else WHITE)
        pdf.set_font("Helvetica", "", 8.5); pdf.fc(TEXT_DARK)
        pdf.cell(58, 6.5, cat, fill=True)
        pdf.fc(GREEN); pdf.set_font("Helvetica", "B", 8.5)
        pdf.cell(16, 6.5, str(cnt), fill=True, align="C")
        pdf.fc(TEXT_MUTED); pdf.set_font("Helvetica", "", 8.5)
        pdf.cell(108, 6.5, cov, fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        total += cnt
    # total row
    pdf.bc(NAVY); pdf.fc(WHITE); pdf.set_font("Helvetica", "B", 8.5)
    pdf.cell(58, 7, "TOTAL", fill=True)
    pdf.fc(LIGHT_BLUE)
    pdf.cell(16, 7, str(total), fill=True, align="C")
    pdf.fc((139, 148, 158)); pdf.set_font("Helvetica", "", 8.5)
    pdf.cell(108, 7, "All passing -- 0 failures, 0 warnings", fill=True,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ---- Page 7: Demo, Users, Files ----------------------------
    pdf.add_page()
    pdf.section("9.  Demo Scenarios (Pre-loaded)")
    pdf.body(
        "On first launch SentinelSOC seeds 110 synthetic events using RFC 5737 documentation "
        "IP ranges (198.51.100.x, 203.0.113.x) and fictional usernames. All 5 rules are triggered."
    )
    scenarios = [
        ("Brute Force",      "6 failures from 198.51.100.42 against alice.smith in < 5 min",    "High Alert",   RED),
        ("Password Spray",   "1 IP targeting 4 accounts (alice/bob/charlie/diana) in < 10 min", "High Alert",   RED),
        ("Success/Fail",     "4 failures then a success for bob.jones from attacker IP",         "High Alert",   RED),
        ("Lockout Spike",    "7 account lockouts across 7 users within 10 minutes",             "Medium Alert", ORANGE),
        ("Multi-IP Attack",  "4 distinct IPs (203.0.113.10-13) targeting charlie.dev < 15 min", "Medium Alert", ORANGE),
    ]
    cols3 = [("Scenario", 44), ("What Happens", 100), ("Result", 38)]
    pdf.thead(cols3)
    for i, (sc, what, result, sc_col) in enumerate(scenarios):
        pdf.bc(ROW_ALT if i % 2 else WHITE)
        pdf.set_font("Helvetica", "B", 8.5); pdf.fc(TEXT_DARK)
        pdf.cell(44, 6.5, sc, fill=True)
        pdf.set_font("Helvetica", "", 8.5); pdf.fc(TEXT_MUTED)
        pdf.cell(100, 6.5, what, fill=True)
        pdf.fc(sc_col); pdf.set_font("Helvetica", "B", 8)
        pdf.cell(38, 6.5, result, fill=True, align="C",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.section("10.  User Accounts")
    accounts = [
        ("admin",   "Admin@1234",   "Administrator", "Full access -- settings, reset, configure rules"),
        ("analyst", "Analyst@1234", "SOC Analyst",   "Standard -- investigate alerts, manage incidents"),
        ("viewer",  "Viewer@1234",  "Read-Only",      "View dashboard, events, alerts, reports"),
    ]
    cols4 = [("Username", 30), ("Password", 34), ("Role", 30), ("Access Level", 88)]
    pdf.thead(cols4)
    for i, (u, p, r, a) in enumerate(accounts):
        pdf.bc(ROW_ALT if i % 2 else WHITE)
        pdf.set_font("Courier", "B", 8.5); pdf.fc(ACCENT)
        pdf.cell(30, 6.5, u, fill=True)
        pdf.set_font("Courier", "", 8.5); pdf.fc(TEXT_DARK)
        pdf.cell(34, 6.5, p, fill=True)
        pdf.set_font("Helvetica", "B", 8.5); pdf.fc(GREEN)
        pdf.cell(30, 6.5, r, fill=True)
        pdf.set_font("Helvetica", "", 8.5); pdf.fc(TEXT_MUTED)
        pdf.cell(88, 6.5, a, fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.section("11.  Project Files")
    files = [
        ("sentinelsoc.py",               "Complete app -- routes, DB, detection engine, templates"),
        ("requirements.txt",             "Python dependencies (Flask, pytest, fpdf2)"),
        ("generate_report.py",           "This PDF generator"),
        ("README.md",                    "Full setup guide, architecture, demo walkthrough"),
        (".env.example",                 "Environment variable template"),
        ("tests/test_sentinelsoc.py",    "47 automated pytest tests"),
        ("sentinelsoc.db",               "SQLite database (auto-created, not committed to git)"),
        ("SentinelSOC_Project_Report.pdf", "This report"),
    ]
    cols5 = [("File", 72), ("Purpose", 110)]
    pdf.thead(cols5)
    for i, (f, p) in enumerate(files):
        pdf.bc(ROW_ALT if i % 2 else WHITE)
        pdf.set_font("Courier", "", 8.5); pdf.fc(ACCENT)
        pdf.cell(72, 6.5, f, fill=True)
        pdf.set_font("Helvetica", "", 8.5); pdf.fc(TEXT_MUTED)
        pdf.cell(110, 6.5, p, fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ---- Page 8: Quick Start, Limitations, Sign-off ------------
    pdf.add_page()
    pdf.section("12.  Quick Start (Windows)")
    steps = [
        ("Step 1", "Open Command Prompt",  "Press Win + R, type cmd, press Enter"),
        ("Step 2", "Go to project folder", "cd /d E:\\bootcamp-project"),
        ("Step 3", "Run the application",  "python sentinelsoc.py"),
        ("Step 4", "Open in browser",      "http://127.0.0.1:5000  (admin / Admin@1234)"),
        ("Step 5", "Run tests (optional)", "python -m pytest tests/ -v"),
        ("Step 6", "Stop the app",         "Press Ctrl + C in the terminal"),
    ]
    for num, title, cmd in steps:
        pdf.set_font("Helvetica", "B", 9); pdf.fc(ACCENT)
        pdf.cell(14, 7, num)
        pdf.fc(TEXT_DARK)
        pdf.cell(44, 7, title)
        pdf.set_font("Courier", "", 8.5); pdf.fc(CYAN)
        pdf.cell(0, 7, cmd, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    pdf.section("13.  Limitations")
    limits = [
        "Demo accounts only -- not suitable for public deployment without proper user management.",
        "No TLS -- runs on HTTP; add a reverse proxy with HTTPS for any production-like use.",
        "Synthetic data only -- do not process real user credentials without authorisation.",
        "Rule-based detection only -- novel attack patterns not matching 5 rules go undetected.",
        "No live monitoring -- detection runs on upload or manual trigger, not as a stream.",
        "Detections are indicators -- all alerts require analyst investigation before action.",
    ]
    for i, lim in enumerate(limits, 1):
        pdf.set_font("Helvetica", "B", 9); pdf.fc(RED)
        pdf.cell(8, 6, f"{i}.")
        pdf.set_font("Helvetica", "", 9); pdf.fc(TEXT_MUTED)
        pdf.cell(0, 6, lim, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    pdf.section("14.  Responsible Use Statement", RED)
    pdf.body(
        "SentinelSOC is built strictly for educational and demonstration purposes as part of the "
        "IBM Cybersecurity Bootcamp.\n\n"
        "  * Do NOT use this tool to monitor real users without explicit knowledge and consent.\n"
        "  * Do NOT process real authentication credentials, passwords, or personal data.\n"
        "  * Do NOT automatically block IP addresses or lock accounts based solely on these alerts.\n"
        "  * Always follow your organisation's security policies and applicable laws.\n"
        "  * This prototype is NOT production-ready. Deploy only on a trusted local machine.\n\n"
        "Every alert is an INDICATOR of suspicious behaviour requiring human investigation. "
        "The application never claims a confirmed attack without analyst review."
    )
    pdf.ln(4)

    pdf.section("15.  Sign-off")
    pdf.bc(ROW_ALT)
    pdf.rect(pdf.l_margin, pdf.get_y(),
             pdf.w - pdf.l_margin - pdf.r_margin, 46, "F")
    pdf.ln(4)
    sign = [
        ("Project Name",  "SentinelSOC -- Mini Security Operations Center"),
        ("Tagline",       "Detect. Investigate. Defend."),
        ("Bootcamp",      "IBM Cybersecurity Bootcamp"),
        ("Developer",     "Daksh.A.Saraswala"),
        ("Email",         "Dakshsaraswala23@gmail.com"),
        ("Contact",       "+91 6359058845"),
        ("College",       "Dr.S.&S.S.Gandhi College Of Engineering & Technology"),
        ("Program",       "Diploma College"),
        ("App File",      "sentinelsoc.py  (single-file Flask application)"),
        ("Test Suite",    "47 / 47 tests passing -- pytest 8 on Python 3.14"),
        ("Report Date",   datetime.now().strftime("%B %d, %Y")),
    ]
    # background box sized for all rows
    pdf.bc(ROW_ALT)
    pdf.rect(pdf.l_margin, pdf.get_y(),
             pdf.w - pdf.l_margin - pdf.r_margin, 85, "F")
    pdf.ln(4)
    for k, v in sign:
        pdf.set_font("Helvetica", "B", 9); pdf.fc(TEXT_DARK)
        pdf.set_x(pdf.l_margin + 6)
        highlight_keys = ("Developer", "Email", "Contact", "College", "Program")
        if k in highlight_keys:
            pdf.fc(ACCENT)
        pdf.cell(48, 6.5, k + ":")
        if k == "Developer":
            pdf.set_font("Helvetica", "B", 9); pdf.fc(ACCENT)
        elif k in ("Email", "Contact"):
            pdf.set_font("Helvetica", "B", 9); pdf.fc(GREEN)
        elif k in ("College", "Program"):
            pdf.set_font("Helvetica", "B", 9); pdf.fc((0, 90, 160))
        else:
            pdf.set_font("Helvetica", "", 9); pdf.fc(TEXT_MUTED)
        pdf.cell(0, 6.5, v, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 10); pdf.fc(ACCENT)
    pdf.cell(0, 7, "Built with Python - Flask - SQLite - Chart.js - fpdf2",
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ---- save --------------------------------------------------
    out = "SentinelSOC_Project_Report.pdf"
    pdf.output(out)
    print(f"\nPDF saved:  {out}")
    print(f"Pages:      {pdf.page}")
    print(f"Location:   E:\\bootcamp-project\\{out}")


if __name__ == "__main__":
    build()
