
from datetime import datetime

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, Response

from capture import sniffer
from core.statistics import get_dashboard_statistics
from reports.report_generator import (
    build_report,
    render_report_pdf,
    render_report_text,
)
from storage.database import fetch_alerts, fetch_traffic, get_counts

router = APIRouter()


@router.get("/")
def home():
    return {
        "project": "Cyber Trek",
        "status": "Running",
        "capture": sniffer.capture_status(),
    }


@router.get("/health")
def health():
    return {
        "status": "ok",
        "capture": sniffer.capture_status(),
    }


@router.get("/traffic")
def get_traffic(
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    items = fetch_traffic(limit, offset)

    for item in items:
        item["port"] = (
            item.get("destination_port")
            if item.get("destination_port") is not None
            else "N/A"
        )

    return items


@router.get("/alerts")
def get_alerts(
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    return fetch_alerts(limit, offset)


@router.get("/report")
def get_report():
    report = build_report()

    return {
        **report,
        "total_packets": report["summary"]["total_packets"],
        "total_alerts": report["summary"]["total_alerts"],
        "recent_alerts": report["recent_alerts"][:20],
    }


@router.get("/report/download")
def download_report():
    report = build_report()
    pdf_bytes = render_report_pdf(report)

    filename = (
        f"cyber_trek_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/report/download/text")
def download_text_report():
    report = build_report()
    text_content = render_report_text(report)

    filename = (
        f"cyber_trek_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )

    return Response(
        content=text_content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get("/stats")
def get_stats():
    return get_dashboard_statistics()


@router.get("/history/traffic")
def traffic_history(
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    return {
        "items": fetch_traffic(limit, offset),
        "counts": get_counts(),
    }


@router.get("/history/alerts")
def alert_history(
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    return {
        "items": fetch_alerts(limit, offset),
        "counts": get_counts(),
    }
