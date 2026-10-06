"""
report.py

Handles generation of the human-readable compliance report:
 - build_report_context(): shared data prep used by both the HTML view and the PDF export
 - generate_pdf_report(): renders a PDF using reportlab (pure Python, no system deps)
"""

from datetime import datetime
from pathlib import Path

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc3545"),
    "High": colors.HexColor("#fd7e14"),
    "Medium": colors.HexColor("#ffc107"),
    "Low": colors.HexColor("#20c997"),
    "None": colors.HexColor("#6c757d"),
}


def build_report_context(df: pd.DataFrame, report_id: str) -> dict:
    """Shared data prep used by both the HTML report page and the PDF export."""
    per_app = (
        df.groupby(["app_id", "application_name"])
        .agg(
            avg_risk_score=("risk_score", "mean"),
            total_libraries=("library", "count"),
            flagged_libraries=("risk_type", lambda s: (s.str.upper() != "NONE").sum()),
        )
        .reset_index()
        .sort_values("avg_risk_score", ascending=False)
    )

    top_risky = df.sort_values("risk_score", ascending=False).head(20)

    summary = {
        "total_apps": int(df["app_id"].nunique()),
        "total_libraries": int(len(df)),
        "total_flagged": int((df["risk_type"].str.upper() != "NONE").sum()),
        "critical_count": int((df["severity"].str.upper() == "CRITICAL").sum()),
        "high_count": int((df["severity"].str.upper() == "HIGH").sum()),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }

    return {
        "report_id": report_id,
        "summary": summary,
        "per_app": per_app.to_dict(orient="records"),
        "top_risky": top_risky.to_dict(orient="records"),
    }


def generate_pdf_report(df: pd.DataFrame, report_id: str, output_path: Path) -> None:
    """Render a PDF compliance report using reportlab."""
    context = build_report_context(df, report_id)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=20, spaceAfter=12)
    subtitle_style = ParagraphStyle("SubtitleStyle", parent=styles["Normal"], fontSize=10, textColor=colors.grey)
    section_style = ParagraphStyle("SectionStyle", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=landscape(A4),
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
    )

    elements = []

    elements.append(Paragraph("Software Supply Chain Risk Report", title_style))
    elements.append(
        Paragraph(
            f"Report ID: {report_id} &nbsp;|&nbsp; Generated: {context['summary']['generated_at']}",
            subtitle_style,
        )
    )
    elements.append(Spacer(1, 0.5 * cm))

    summary = context["summary"]
    summary_data = [
        ["Applications Scanned", "Libraries Scanned", "Flagged", "Critical", "High"],
        [
            summary["total_apps"],
            summary["total_libraries"],
            summary["total_flagged"],
            summary["critical_count"],
            summary["high_count"],
        ],
    ]
    summary_table = Table(summary_data, hAlign="LEFT", colWidths=[5 * cm] * 5)
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    elements.append(summary_table)

    elements.append(Paragraph("Per-Application Risk Ranking", section_style))
    app_rows = [["Rank", "Application", "Avg Risk Score", "Libraries", "Flagged"]]
    for i, row in enumerate(context["per_app"], start=1):
        app_rows.append([
            i,
            row["application_name"],
            f"{row['avg_risk_score']:.1f}",
            row["total_libraries"],
            row["flagged_libraries"],
        ])
    app_table = Table(app_rows, hAlign="LEFT", colWidths=[2 * cm, 7 * cm, 3.5 * cm, 3 * cm, 3 * cm])
    app_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    elements.append(app_table)
    elements.append(PageBreak())

    elements.append(Paragraph("Top Risky Libraries & Remediation Priorities", section_style))
    lib_rows = [["Application", "Library", "Version", "Severity", "Risk Type", "Score", "Recommendation"]]
    for row in context["top_risky"]:
        lib_rows.append([
            row["application_name"],
            row["library"],
            str(row["version"]),
            row["severity"],
            str(row["risk_type"]).replace("_", " ").title(),
            f"{row['risk_score']:.0f}",
            row["recommendation"],
        ])
    lib_table = Table(
        lib_rows,
        hAlign="LEFT",
        colWidths=[3.5 * cm, 3.5 * cm, 2 * cm, 2 * cm, 3 * cm, 1.8 * cm, 6.5 * cm],
        repeatRows=1,
    )

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, row in enumerate(context["top_risky"], start=1):
        color = SEVERITY_COLORS.get(row["severity"], colors.grey)
        style_cmds.append(("TEXTCOLOR", (3, i), (3, i), color))

    lib_table.setStyle(TableStyle(style_cmds))
    elements.append(lib_table)

    doc.build(elements)
