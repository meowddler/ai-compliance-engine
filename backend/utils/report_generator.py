from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import io


def generate_compliance_report(summary_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("Compliance Audit Report", styles["Title"]))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # Summary section
    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary_table_data = [
        ["Metric", "Value"],
        ["Total Scans", str(summary_data["total_scans"])],
        ["Total Violations", str(summary_data["total_violations"])],
        ["Anomalies Detected", str(summary_data["anomaly_count"])],
    ]
    summary_table = Table(summary_table_data, colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # Severity breakdown
    elements.append(Paragraph("Violations by Severity", styles["Heading2"]))
    sev = summary_data["severity_breakdown"]
    sev_table_data = [
        ["Severity", "Count"],
        ["HIGH", str(sev["HIGH"])],
        ["MEDIUM", str(sev["MEDIUM"])],
        ["LOW", str(sev["LOW"])],
    ]
    sev_table = Table(sev_table_data, colWidths=[200, 200])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 20))

    # Recent findings
    elements.append(Paragraph("Recent Findings", styles["Heading2"]))
    findings_data = [["Server", "Rule", "Severity", "Anomaly"]]
    for v in summary_data["recent_violations"]:
        findings_data.append([
            v["server_id"], v["rule_name"], v["severity"], "Yes" if v["is_anomaly"] else "No"
        ])
    findings_table = Table(findings_data, colWidths=[100, 180, 80, 80])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(findings_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer