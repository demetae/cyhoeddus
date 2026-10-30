#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import Optional

from bs4 import BeautifulSoup, Tag
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Border, Side, Alignment


@dataclass
class ControlBlock:
    control_id: str
    title: str
    table: list[list[str]]
    finding_count: int
    query: str = ""
    result: str = ""
    expected_output: str = ""
    explanation: str = ""
    remediation: str = ""


HEADER_FILL = PatternFill("solid", fgColor="D9D9A6")
TEST_FILL = PatternFill("solid", fgColor="F4B183")
SECTION_FILL = PatternFill("solid", fgColor="DDEBF7")
BORDER = Border(
    left=Side(style="thin", color="777777"),
    right=Side(style="thin", color="777777"),
    top=Side(style="thin", color="777777"),
    bottom=Side(style="thin", color="777777"),
)


def clean_text(value: str) -> str:
    value = unescape(value or "")
    value = value.replace("\xa0", " ")
    value = value.replace("&nbsp;", " ")
    value = re.sub(r"[ \t\r\f\v]+", " ", value)
    return value.strip()


def get_table_rows_from_html(table_html: str) -> list[list[str]]:
    soup = BeautifulSoup(table_html, "html.parser")
    table = soup.find("table")
    if not table:
        return []
    return get_table_rows(table)


def get_table_rows(table: Tag) -> list[list[str]]:
    rows = []
    for tr in table.find_all("tr"):
        cells = tr.find_all(["th", "td"])
        if cells:
            rows.append([clean_text(c.get_text(" ", strip=True)) for c in cells])
    return [r for r in rows if any(c for c in r)]


def parse_row_count(text: str) -> Optional[int]:
    text = unescape(text)
    m = re.search(r"\b(\d+)\s+rows?\s+selected\b", text, re.I)
    if m:
        return int(m.group(1))
    if re.search(r"\bno\s+rows\s+selected\b", text, re.I):
        return 0
    return None


def parse_audit_context(raw_html: str) -> list[list[str]]:
    m = re.search(r"&lt;h2&gt;\s*Audit Context\s*&lt;/h2&gt;(.*?)(?:&lt;h2&gt;|&lt;h3&gt;)", raw_html, re.I | re.S)
    if not m:
        m = re.search(r"<h2>\s*Audit Context\s*</h2>(.*?)(?:<h2>|<h3>|&lt;h2&gt;|&lt;h3&gt;)", raw_html, re.I | re.S)
    if not m:
        return []

    section = m.group(1)
    tm = re.search(r"<table\b.*?</table>", section, re.I | re.S)
    if not tm:
        return []
    return get_table_rows_from_html(tm.group(0))


def parse_controls_from_raw_html(raw_html: str) -> tuple[list[list[str]], list[ControlBlock]]:
    audit_context = parse_audit_context(raw_html)

    heading_pattern = re.compile(
        r"(?:&lt;|<)h3(?:&gt;|>)\s*([0-9]+(?:\.[0-9]+)+)\s*-\s*(.*?)\s*(?:&lt;|<)/h3(?:&gt;|>)",
        re.I | re.S,
    )
    matches = list(heading_pattern.finditer(raw_html))
    controls = []

    for i, m in enumerate(matches):
        cid = clean_text(m.group(1))
        title = clean_text(m.group(2))
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw_html)
        section = raw_html[start:end]

        table_rows = []
        tm = re.search(r"<table\b.*?</table>", section, re.I | re.S)
        if tm:
            table_rows = get_table_rows_from_html(tm.group(0))

        count = parse_row_count(section)
        if count is None:
            count = max(len(table_rows) - 1, 0) if table_rows else 0

        controls.append(ControlBlock(cid, title, table_rows, count))

    return audit_context, controls


def parse_queries_from_sql_runner(sql_path: Optional[Path]) -> dict[str, str]:
    if not sql_path or not sql_path.exists():
        return {}

    text = sql_path.read_text(errors="replace")
    queries = {}

    pattern = re.compile(
        r"PROMPT\s+<h3>\s*([0-9]+(?:\.[0-9]+)+)\s*-\s*.*?</h3>\s*"
        r"PROMPT\s+<p>Finding rows:</p>\s*"
        r"(?P<sql>.*?);(?=\s*PROMPT\s+<h3>|\s*PROMPT\s+<h2>Cleanup</h2>|\Z)",
        re.I | re.S,
    )

    for m in pattern.finditer(text):
        queries[m.group(1)] = re.sub(r"\n{3,}", "\n\n", m.group("sql").strip())

    return queries


def expected_output_for(control: ControlBlock) -> str:
    if "(MANUAL)" in control.title.upper():
        return "Manual review required; returned rows are evidence for review, not an automatic failure."
    return "Empty result / no rows selected."


def remediation_for(control: ControlBlock) -> str:
    remediations = {
        "2.3.1": "ALTER SYSTEM SET BACKGROUND_CORE_DUMP = 'partial' SCOPE = SPFILE;",
        "2.3.2": "ALTER SYSTEM SET SHADOW_CORE_DUMP = 'partial' SCOPE = SPFILE;",
        "2.3.3": "ALTER SYSTEM SET ALLOW_GROUP_ACCESS_TO_SGA = FALSE SCOPE = SPFILE;",
        "2.3.5": "ALTER SYSTEM SET OS_ROLES = FALSE SCOPE = SPFILE;",
        "2.3.6": "ALTER SYSTEM SET REMOTE_OS_ROLES = FALSE SCOPE = SPFILE;",
        "2.3.7": "ALTER SYSTEM SET SEC_MAX_FAILED_LOGIN_ATTEMPTS = 3 SCOPE = SPFILE;",
        "2.3.8": "ALTER SYSTEM SET SEC_PROTOCOL_ERROR_FURTHER_ACTION = '(DROP,3)' SCOPE = SPFILE;",
        "2.3.9": "ALTER SYSTEM SET SEC_PROTOCOL_ERROR_TRACE_ACTION = LOG SCOPE = SPFILE;",
        "2.3.10": "ALTER SYSTEM SET SEC_RETURN_SERVER_RELEASE_BANNER = FALSE SCOPE = SPFILE;",
        "2.3.11": "ALTER SYSTEM SET REMOTE_LOGIN_PASSWORDFILE = 'NONE' SCOPE = SPFILE;",
        "2.3.12": "ALTER SYSTEM SET REMOTE_LISTENER = '' SCOPE = SPFILE;",
        "2.3.13": "ALTER SYSTEM SET RESOURCE_LIMIT = TRUE SCOPE = SPFILE;",
        "2.3.14": "ALTER SYSTEM SET REMOTE_OS_AUTHENT = FALSE SCOPE = SPFILE;",
        "2.3.15": "ALTER SYSTEM SET SEC_CASE_SENSITIVE_LOGON = TRUE SCOPE = SPFILE;",
        "3.1": "ALTER PROFILE <profile_name> LIMIT FAILED_LOGIN_ATTEMPTS 5;",
        "3.2": "ALTER PROFILE <profile_name> LIMIT PASSWORD_LOCK_TIME 1;",
        "3.3": "ALTER PROFILE <profile_name> LIMIT PASSWORD_LIFE_TIME <value> PASSWORD_GRACE_TIME <value>; ensure the combined total is <= 365.",
        "3.4": "ALTER PROFILE <profile_name> LIMIT PASSWORD_REUSE_MAX UNLIMITED;",
        "3.5": "ALTER PROFILE <profile_name> LIMIT PASSWORD_VERIFY_FUNCTION <approved_verify_function>;",
        "3.6": "Review the password verify function source and update it to meet organisational password complexity policy.",
        "3.7": "ALTER PROFILE <profile_name> LIMIT PASSWORD_ROLLOVER_TIME 0;",
        "3.8": "ALTER PROFILE <profile_name> LIMIT INACTIVE_ACCOUNT_TIME 120;",
        "4.7": "DROP PUBLIC DATABASE LINK <link_name>;",
    }

    if control.control_id in remediations:
        return remediations[control.control_id]

    title = control.title.upper()
    if "REVOKED" in title or "REVOKE" in title:
        return "Revoke the listed privilege/role/object grant from unauthorized grantees after confirming business need."
    if "AUDIT" in title and "(AUTOMATED)" in title:
        return "Create or enable the required audit policy/action according to the benchmark remediation guidance."
    if "PASSWORD" in title:
        return "Alter the affected profile(s) to match the CIS benchmark requirement."
    if "MANUAL" in title:
        return "Review the returned evidence and remediate according to the benchmark and organisational policy."
    return "Review the returned rows and apply the CIS benchmark remediation for this control."


def explain(control: ControlBlock) -> str:
    title = control.title.upper()
    n = control.finding_count

    if "(MANUAL)" in title:
        return f"This is a manual CIS control. The audit returned {n} row(s) of evidence that must be reviewed to determine compliance."

    if n == 0:
        return "No findings were returned by the audit query."

    if "PASSWORD_LIFE_TIME" in title and "PASSWORD_GRACE_TIME" in title:
        return f"The audit returned {n} profile row(s) where PASSWORD_LIFE_TIME plus PASSWORD_GRACE_TIME exceeds the CIS threshold."
    if "PASSWORD_REUSE_MAX" in title:
        return f"The audit returned {n} profile row(s) where PASSWORD_REUSE_MAX is not set to the CIS-required value."
    if "FAILED_LOGIN_ATTEMPTS" in title:
        return f"The audit returned {n} profile row(s) where FAILED_LOGIN_ATTEMPTS exceeds the CIS maximum or is set to UNLIMITED."
    if "REMOTE_LOGIN_PASSWORDFILE" in title:
        return f"The audit returned {n} row(s) showing REMOTE_LOGIN_PASSWORDFILE is not set to NONE."
    if "SEC_PROTOCOL_ERROR_TRACE_ACTION" in title:
        return f"The audit returned {n} row(s) showing SEC_PROTOCOL_ERROR_TRACE_ACTION is not set to LOG."
    if "REVOKED" in title or "REVOKE" in title:
        return f"The audit returned {n} unauthorized or review-required grant/privilege row(s)."
    if "AUDIT" in title:
        return f"The audit returned {n} row(s), indicating the expected audit action/policy is not enabled as required."

    return f"The audit query returned {n} row(s). For this automated CIS check, returned rows represent findings because the expected output is an empty result set."


def result_for(control: ControlBlock) -> str:
    if "(MANUAL)" in control.title.upper():
        return "REVIEW"
    return "FAIL" if control.finding_count > 0 else "PASS"


def apply_table_style(ws, start_row: int, start_col: int, rows: list[list[str]]):
    if not rows:
        return

    max_cols = max(len(r) for r in rows)
    for r_idx, row in enumerate(rows, start_row):
        for c_idx in range(start_col, start_col + max_cols):
            value = row[c_idx - start_col] if c_idx - start_col < len(row) else ""
            cell = ws.cell(r_idx, c_idx, value)
            cell.border = BORDER
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            if r_idx == start_row:
                cell.fill = HEADER_FILL
                cell.font = Font(bold=True, color="0070C0")
                cell.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")


def write_line(ws, row: int, text: str, bold: bool = False, fill=None):
    cell = ws.cell(row, 1, text)
    cell.alignment = Alignment(wrap_text=True, vertical="top")
    cell.font = Font(bold=bold)
    if fill:
        cell.fill = fill
    return cell


def write_workbook(audit_context, controls, xlsx_path: Path, include_passes: bool):
    wb = Workbook()
    ws = wb.active
    ws.title = "CIS Benchmark Output"

    row = 1
    cell = write_line(ws, row, "Appendix III: CIS Benchmark Output", True)
    cell.font = Font(bold=True, underline="single", size=12)
    row += 2

    if audit_context:
        write_line(ws, row, "[Audit Context]", True, SECTION_FILL)
        row += 1
        apply_table_style(ws, row, 1, audit_context)
        row += len(audit_context) + 2

    figure_no = 1

    for control in controls:
        control.result = result_for(control)
        if not include_passes and control.result == "PASS":
            continue

        control.expected_output = expected_output_for(control)
        control.explanation = explain(control)
        control.remediation = remediation_for(control)

        write_line(ws, row, "-" * 55)
        row += 1
        write_line(ws, row, f"[Test]: {control.control_id} - {control.title}", True, TEST_FILL)
        row += 1
        write_line(ws, row, f"[Query]: {control.query or 'Not captured. Re-run with --sql-script to include the audit SQL.'}")
        ws.row_dimensions[row].height = 60
        row += 1
        write_line(ws, row, "[Output]:", True)
        row += 1

        if control.table:
            apply_table_style(ws, row, 1, control.table)
            row += len(control.table)
            write_line(ws, row, f"{control.finding_count} row(s) selected.")
            row += 1
            clean_title = re.sub(r"\s*\((Automated|Manual)\)\s*$", "", control.title, flags=re.I)
            cap = write_line(ws, row, f"Figure {figure_no}: Output returned for {control.control_id} - {clean_title}.")
            cap.font = Font(italic=True)
            figure_no += 1
            row += 1
        else:
            write_line(ws, row, "No rows selected.")
            row += 1

        write_line(ws, row, f"[Expected Output]: {control.expected_output}")
        row += 1
        label = "[Why Non-Compliant]" if control.result == "FAIL" else "[Review Required]" if control.result == "REVIEW" else "[Result]"
        write_line(ws, row, f"{label}: {control.explanation}")
        row += 1
        write_line(ws, row, f"[Remediation]: {control.remediation}")
        row += 2

    for col, width in {
        "A": 34, "B": 42, "C": 32, "D": 32, "E": 24, "F": 24, "G": 24, "H": 24,
        "I": 24, "J": 24, "K": 24, "L": 24
    }.items():
        ws.column_dimensions[col].width = width

    for rows in ws.iter_rows():
        for cell in rows:
            cell.alignment = Alignment(wrap_text=True, vertical="top")

    wb.save(xlsx_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("html", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("CIS_Benchmark_Output.xlsx"))
    parser.add_argument("--sql-script", type=Path, default=None)
    parser.add_argument("--include-passes", action="store_true")
    args = parser.parse_args()

    raw_html = args.html.read_text(errors="replace")
    audit_context, controls = parse_controls_from_raw_html(raw_html)

    if not controls:
        raise SystemExit("No audit controls found. Expected escaped headings like &lt;h3&gt;3.3 - ...&lt;/h3&gt; or real <h3> tags.")

    queries = parse_queries_from_sql_runner(args.sql_script)
    for c in controls:
        c.query = queries.get(c.control_id, "")

    write_workbook(audit_context, controls, args.output, args.include_passes)

    print(f"Created: {args.output}")
    print(f"Controls parsed: {len(controls)}")
    print(f"FAIL: {sum(1 for c in controls if result_for(c) == 'FAIL')} | REVIEW: {sum(1 for c in controls if result_for(c) == 'REVIEW')} | PASS: {sum(1 for c in controls if result_for(c) == 'PASS')}")


if __name__ == "__main__":
    main()
