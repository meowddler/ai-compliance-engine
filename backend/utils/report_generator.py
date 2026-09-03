"""Compliance report generation.

The PDF is the auditor-facing artifact, so it states the same numbers the
dashboard does, including the denominator behind the posture score. A report
that shows a percentage without showing what it was computed from is not
evidence of anything.
"""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

HEADER_BG = colors.HexColor("#1f2937")
ACCENT = colors.HexColor("#c2570f")

_BASE_TABLE_STYLE = [
    ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("FONTSIZE", (0, 0), (-1, -1), 9),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
]


def _truncate(value, limit=48):
    """Keep long values from overflowing a fixed-width column.

    Uploaded identifiers can be arbitrarily long; clipping them keeps the table
    readable rather than letting text overlap into the next cell.
    """
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _table(data, col_widths, extra_style=None):
    # repeatRows only when the table is long enough to plausibly split a page;
    # on short tables it can duplicate the header mid-flow.
    t = Table(data, colWidths=col_widths, repeatRows=1 if len(data) > 20 else 0)
    t.setStyle(TableStyle(_BASE_TABLE_STYLE + (extra_style or [])))
    return t


def _page_footer(canvas, doc):
    """Page numbers, so a printed report can be checked for missing pages."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(letter[0] - 40, 25, f"Page {doc.page}")
    canvas.restoreState()


def generate_compliance_report(summary_data, organization_name=None):
    """Build the PDF. Missing keys degrade to a stated absence, never a crash."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        title="Compliance Audit Report", author="AI Compliance Engine",
    )
    styles = getSampleStyleSheet()
    elements = []

    # --- Header -------------------------------------------------------------
    elements.append(Paragraph("Compliance Audit Report", styles["Title"]))
    if organization_name:
        elements.append(Paragraph(f"Organisation: {organization_name}", styles["Normal"]))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(f"Generated: {generated}", styles["Normal"]))
    elements.append(Spacer(1, 18))

    # --- Posture ------------------------------------------------------------
    # Shown with its denominator. A bare percentage is not auditable.
    posture = summary_data.get("posture") or {}
    elements.append(Paragraph("Compliance Posture", styles["Heading2"]))

    if posture.get("scored"):
        posture_rows = [
            ["Metric", "Value"],
            ["Posture score", f"{posture.get('score')}%"],
            ["Controls evaluated", str(posture.get("controls_evaluated", 0))],
            ["Controls passing", str(posture.get("controls_passed", 0))],
            ["Controls failing", str(posture.get("controls_failed", 0))],
            ["Controls unverified", str(posture.get("controls_unverified", 0))],
            ["Rubric version", str(posture.get("rubric_version", "n/a"))],
        ]
    else:
        # Stating why there is no score is more honest than printing a zero.
        posture_rows = [
            ["Metric", "Value"],
            ["Posture score", "Not computed"],
            ["Reason", _truncate(posture.get("reason", "No evaluation data available."), 60)],
        ]
    elements.append(_table(posture_rows, [200, 240]))
    elements.append(Spacer(1, 18))

    # --- Summary ------------------------------------------------------------
    elements.append(Paragraph("Scan Summary", styles["Heading2"]))
    summary_rows = [
        ["Metric", "Value"],
        ["Total scans", str(summary_data.get("total_scans", 0))],
        ["Total findings", str(summary_data.get("total_violations", 0))],
        ["Anomalies detected", str(summary_data.get("anomaly_count", 0))],
    ]
    elements.append(_table(summary_rows, [200, 240]))
    elements.append(Spacer(1, 18))

    # --- Severity -----------------------------------------------------------
    elements.append(Paragraph("Findings by Severity", styles["Heading2"]))
    sev = summary_data.get("severity_breakdown") or {}
    sev_rows = [
        ["Severity", "Count"],
        ["HIGH", str(sev.get("HIGH", 0))],
        ["MEDIUM", str(sev.get("MEDIUM", 0))],
        ["LOW", str(sev.get("LOW", 0))],
    ]
    elements.append(_table(sev_rows, [200, 240], [
        ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#b91c1c")),
        ("TEXTCOLOR", (0, 2), (0, 2), colors.HexColor("#b45309")),
        ("TEXTCOLOR", (0, 3), (0, 3), colors.HexColor("#047857")),
    ]))
    elements.append(Spacer(1, 18))

    # --- Recent findings ----------------------------------------------------
    elements.append(Paragraph("Recent Findings", styles["Heading2"]))
    recent = summary_data.get("recent_violations") or []

    if recent:
        findings_rows = [["Server", "Control", "Severity", "Anomaly"]]
        for v in recent:
            findings_rows.append([
                _truncate(v.get("server_id"), 22),
                _truncate(v.get("rule_name"), 34),
                _truncate(v.get("severity"), 10),
                "Yes" if v.get("is_anomaly") else "No",
            ])
        elements.append(_table(findings_rows, [110, 190, 70, 60]))
    else:
        elements.append(Paragraph("No findings recorded.", styles["Normal"]))

    elements.append(Spacer(1, 24))
    elements.append(Paragraph(
        "Statuses in this report are assigned by the deterministic rule engine. "
        "Controls that could not be verified are reported as unverified and are "
        "excluded from the posture denominator; they are never counted as passing.",
        styles["Italic"],
    ))

    doc.build(elements, onFirstPage=_page_footer, onLaterPages=_page_footer)
    buffer.seek(0)
    return buffer