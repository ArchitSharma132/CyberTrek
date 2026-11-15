
from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)

from core.statistics import get_dashboard_statistics
from storage.database import fetch_alerts, fetch_traffic


PAGE_WIDTH, PAGE_HEIGHT = A4

INK = colors.HexColor("#111111")
MUTED = colors.HexColor("#666666")
LIGHT_BG = colors.HexColor("#F3F5F8")
BORDER = colors.HexColor("#E1E5EB")
ACCENT = colors.HexColor("#111111")
RED = colors.HexColor("#C0392B")
GREEN = colors.HexColor("#27834A")
ORANGE = colors.HexColor("#D97706")
WHITE = colors.white


def build_report() -> dict[str, Any]:
    stats = get_dashboard_statistics()
    alerts = fetch_alerts(100)
    traffic = fetch_traffic(5000)

    return {
        "project": "Cyber Trek",
        "generated_at": datetime.now().astimezone().isoformat(
            timespec="seconds"
        ),
        "summary": {
            "total_packets": stats["total_packets"],
            "total_alerts": stats["total_alerts"],
            "protocols_observed": len(stats["protocol_distribution"]),
            "attack_types_observed": len(stats["attack_distribution"]),
        },
        "protocol_distribution": stats["protocol_distribution"],
        "attack_distribution": stats["attack_distribution"],
        "top_sources": stats["top_sources"],
        "severity_distribution": stats["severity_distribution"],
        "recent_alerts": alerts,
        "recommendations": [
            "Treat heuristic alerts as indicators requiring validation, not definitive proof of an attack.",
            "Investigate repeated alerts by reviewing source, destination, timestamps, and packet context.",
            "Tune detector thresholds to the normal traffic profile of the monitored network.",
            "Capture only traffic you are authorized to monitor.",
        ],
        "traffic_sample_included": len(traffic),
    }


def _styles():
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=25,
            leading=30,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=5,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=14,
            textColor=MUTED,
        ),
        "section": ParagraphStyle(
            "Section",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=INK,
            spaceBefore=15,
            spaceAfter=8,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=INK,
            spaceAfter=3,
            wordWrap="CJK",
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=MUTED,
            wordWrap="CJK",
        ),
        "table_header": ParagraphStyle(
            "TableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=WHITE,
        ),
        "table_cell": ParagraphStyle(
            "TableCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=INK,
            wordWrap="CJK",
        ),
        "table_muted": ParagraphStyle(
            "TableMuted",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=MUTED,
            wordWrap="CJK",
        ),
        "metric_label": ParagraphStyle(
            "MetricLabel",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=MUTED,
        ),
        "metric_value": ParagraphStyle(
            "MetricValue",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=19,
            leading=23,
            textColor=INK,
        ),
        "right": ParagraphStyle(
            "Right",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=MUTED,
            alignment=TA_RIGHT,
        ),
    }


def _safe(value: Any) -> str:
    text = str(value if value is not None else "N/A")
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _format_number(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return "0"


def _section(title: str, styles: dict) -> list:
    return [
        Paragraph(_safe(title.upper()), styles["section"]),
        HRFlowable(
            width="100%",
            thickness=0.7,
            color=BORDER,
            spaceAfter=8,
        ),
    ]


def _metric_card(label: str, value: Any, styles: dict):
    content = [
        Paragraph(_safe(label.upper()), styles["metric_label"]),
        Spacer(1, 4),
        Paragraph(_safe(_format_number(value)), styles["metric_value"]),
    ]

    table = Table([[content]], colWidths=[(PAGE_WIDTH - 40 * mm) / 2])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return table


def _data_table(headers: list[str], rows: list[list[Any]], widths: list[float], styles: dict):
    header_row = [
        Paragraph(_safe(header), styles["table_header"])
        for header in headers
    ]

    formatted_rows = []
    for row in rows:
        formatted_rows.append(
            [
                cell if isinstance(cell, Paragraph)
                else Paragraph(_safe(cell), styles["table_cell"])
                for cell in row
            ]
        )

    table = Table(
        [header_row] + formatted_rows,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
    )

    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]

    for row_index in range(1, len(formatted_rows) + 1):
        if row_index % 2 == 0:
            commands.append(
                ("BACKGROUND", (0, row_index), (-1, row_index), LIGHT_BG)
            )

    table.setStyle(TableStyle(commands))
    return table


def _draw_page(canvas, doc):
    canvas.saveState()

    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.6)
    canvas.line(
        20 * mm,
        16 * mm,
        PAGE_WIDTH - 20 * mm,
        16 * mm,
    )

    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(INK)
    canvas.drawString(20 * mm, 10 * mm, "CYBER TREK")

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(
        PAGE_WIDTH - 20 * mm,
        10 * mm,
        f"CONFIDENTIAL  |  PAGE {doc.page}",
    )

    canvas.restoreState()


def render_report_pdf(report: dict[str, Any] | None = None) -> bytes:
    report = report or build_report()
    styles = _styles()
    summary = report.get("summary", {})
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=19 * mm,
        bottomMargin=23 * mm,
        title="Cyber Trek Security Report",
        author="Cyber Trek",
        subject="Network traffic monitoring and security alerts",
    )

    story = []

    story.append(
        Paragraph("CYBER TREK", styles["title"])
    )
    story.append(
        Paragraph("NETWORK SECURITY REPORT", styles["subtitle"])
    )
    story.append(Spacer(1, 8))

    metadata = Table(
        [[
            Paragraph(
                f"<b>Generated</b><br/>{_safe(report.get('generated_at', 'N/A'))}",
                styles["body"],
            ),
            Paragraph(
                "<b>Report type</b><br/>Traffic and threat summary",
                styles["right"],
            ),
        ]],
        colWidths=[105 * mm, 55 * mm],
    )
    metadata.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(metadata)

    story.extend(_section("Executive summary", styles))

    metric_cards = Table(
        [[
            _metric_card("Packets recorded", summary.get("total_packets", 0), styles),
            _metric_card("Alerts recorded", summary.get("total_alerts", 0), styles),
        ]],
        colWidths=[85 * mm, 85 * mm],
    )
    metric_cards.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(metric_cards)
    story.append(Spacer(1, 8))

    summary_rows = [
        [
            "Protocols observed",
            _format_number(summary.get("protocols_observed", 0)),
            "Alert types observed",
            _format_number(summary.get("attack_types_observed", 0)),
        ]
    ]
    summary_table = Table(summary_rows, colWidths=[42 * mm, 28 * mm, 42 * mm, 28 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                ("TEXTCOLOR", (0, 0), (-1, -1), INK),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(summary_table)

    story.extend(_section("Protocol distribution", styles))
    protocols = report.get("protocol_distribution", [])

    if protocols:
        rows = [
            [item.get("protocol", "Unknown"), _format_number(item.get("count", 0))]
            for item in protocols
        ]
        story.append(
            _data_table(
                ["Protocol", "Packets"],
                rows,
                [115 * mm, 45 * mm],
                styles,
            )
        )
    else:
        story.append(Paragraph("No protocol data recorded.", styles["body"]))

    story.extend(_section("Alert distribution", styles))
    attacks = report.get("attack_distribution", [])

    if attacks:
        rows = [
            [item.get("type", "Unknown"), _format_number(item.get("count", 0))]
            for item in attacks
        ]
        story.append(
            _data_table(
                ["Alert type", "Occurrences"],
                rows,
                [115 * mm, 45 * mm],
                styles,
            )
        )
    else:
        story.append(Paragraph("No alert types recorded.", styles["body"]))

    story.extend(_section("Severity distribution", styles))
    severities = report.get("severity_distribution", [])

    if severities:
        rows = [
            [
                item.get("severity", item.get("type", "Unknown")),
                _format_number(item.get("count", 0)),
            ]
            for item in severities
        ]
        story.append(
            _data_table(
                ["Severity", "Occurrences"],
                rows,
                [115 * mm, 45 * mm],
                styles,
            )
        )
    else:
        story.append(Paragraph("No severity data recorded.", styles["body"]))

    story.extend(_section("Recent security alerts", styles))
    alerts = report.get("recent_alerts", [])

    if alerts:
        alert_rows = []
        for alert in alerts:
            severity = str(alert.get("severity", "UNKNOWN")).upper()
            severity_color = (
                RED if severity in {"HIGH", "CRITICAL"}
                else ORANGE if severity == "MEDIUM"
                else GREEN if severity in {"LOW", "INFO", "INFORMATIONAL"}
                else MUTED
            )

            alert_rows.append(
                [
                    Paragraph(_safe(alert.get("timestamp", "N/A")), styles["table_muted"]),
                    Paragraph(_safe(alert.get("type", "Unknown")), styles["table_cell"]),
                    Paragraph(
                        f'<font color="{severity_color.hexval()}"><b>{_safe(severity)}</b></font>',
                        styles["table_cell"],
                    ),
                    Paragraph(_safe(alert.get("source", "N/A")), styles["table_cell"]),
                    Paragraph(_safe(alert.get("destination", "N/A")), styles["table_cell"]),
                    Paragraph(_safe(alert.get("description", "No description")), styles["table_muted"]),
                ]
            )

        story.append(
            _data_table(
                ["Timestamp", "Alert", "Severity", "Source IP", "Destination IP", "Details"],
                alert_rows,
                [25 * mm, 25 * mm, 19 * mm, 25 * mm, 25 * mm, 41 * mm],
                styles,
            )
        )
    else:
        story.append(
            Paragraph("No security alerts have been recorded.", styles["body"])
        )

    story.extend(_section("Recommended actions", styles))

    for index, recommendation in enumerate(
        report.get("recommendations", []), start=1
    ):
        story.append(
            Paragraph(
                f"<b>{index:02d}</b> &nbsp; {_safe(recommendation)}",
                styles["body"],
            )
        )
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 10))
    story.append(
        KeepTogether(
            [
                HRFlowable(width="100%", thickness=0.7, color=BORDER),
                Spacer(1, 7),
                Paragraph(
                    "<b>Important note</b>",
                    styles["body"],
                ),
                Paragraph(
                    "Cyber Trek uses heuristic detection rules. An alert indicates "
                    "potentially suspicious activity and is not, by itself, proof "
                    "of a confirmed attack. Validate findings against authorized "
                    "network logs and operational context.",
                    styles["small"],
                ),
            ]
        )
    )

    document.build(
        story,
        onFirstPage=_draw_page,
        onLaterPages=_draw_page,
    )

    return buffer.getvalue()


def render_report_text(report: dict[str, Any] | None = None) -> str:
    report = report or build_report()
    summary = report.get("summary", {})

    lines = [
        "CYBER TREK SECURITY REPORT",
        "=" * 60,
        f"Generated at: {report.get('generated_at', 'N/A')}",
        "",
        "SYSTEM SUMMARY",
        f"Packets recorded: {summary.get('total_packets', 0)}",
        f"Alerts recorded: {summary.get('total_alerts', 0)}",
        f"Protocols observed: {summary.get('protocols_observed', 0)}",
        f"Alert types observed: {summary.get('attack_types_observed', 0)}",
        "",
        "PROTOCOL DISTRIBUTION",
    ]

    lines.extend(
        f"- {item.get('protocol', 'Unknown')}: {item.get('count', 0)}"
        for item in report.get("protocol_distribution", [])
    )

    lines.extend(["", "ALERT TYPE DISTRIBUTION"])

    lines.extend(
        f"- {item.get('type', 'Unknown')}: {item.get('count', 0)}"
        for item in report.get("attack_distribution", [])
    )

    lines.extend(["", "RECENT ALERTS"])

    alerts = report.get("recent_alerts", [])

    if not alerts:
        lines.append("No alerts have been recorded.")

    for alert in alerts:
        lines.extend(
            [
                f"[{alert.get('severity', 'UNKNOWN')}] {alert.get('type', 'Unknown')}",
                f"Time: {alert.get('timestamp', 'N/A')}",
                f"Source: {alert.get('source', 'N/A')} -> "
                f"Destination: {alert.get('destination', 'N/A')}",
                f"Details: {alert.get('description', 'N/A')}",
                "-" * 40,
            ]
        )

    lines.extend(["", "RECOMMENDATIONS"])
    lines.extend(
        f"- {recommendation}"
        for recommendation in report.get("recommendations", [])
    )
    lines.extend(
        [
            "",
            "Note: Detection is heuristic and can produce false positives.",
            "END OF REPORT",
        ]
    )

    return "\n".join(lines)
