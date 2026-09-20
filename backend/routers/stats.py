"""统计路由 — GET /api/stats"""

from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, extract

from database import get_db
from models import Report, IOCGlobalView, ThreatGroup, KGEdge, IOC

router = APIRouter()


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """获取仪表盘统计数据（含图表用聚合数据）"""
    total_reports = db.query(Report).count()
    total_iocs = db.query(IOCGlobalView).count()
    total_groups = db.query(ThreatGroup).count()
    total_edges = db.query(KGEdge).count()

    # ── 各类型 IOC 数量 ──
    type_rows = (
        db.query(IOCGlobalView.ioc_type, func.count(IOCGlobalView.id))
        .group_by(IOCGlobalView.ioc_type)
        .all()
    )
    iocs_by_type = {row[0]: row[1] for row in type_rows}

    # ── 近 12 月报告趋势 ──
    now = datetime.utcnow()
    twelve_months_ago = now - timedelta(days=365)
    monthly_rows = (
        db.query(
            func.strftime("%Y-%m", Report.created_at).label("month"),
            func.count(Report.id),
        )
        .filter(Report.created_at >= twelve_months_ago)
        .group_by("month")
        .order_by("month")
        .all()
    )
    reports_by_month = [{"month": row[0], "count": row[1]} for row in monthly_rows]

    # ── 最近报告 ──
    recent_reports = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .limit(5)
        .all()
    )

    return {
        "totalIOCs": total_iocs,
        "totalReports": total_reports,
        "totalGroups": total_groups,
        "totalKGEdges": total_edges,
        "iocsByType": iocs_by_type,
        "reportsByMonth": reports_by_month,
        "recentReports": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status.value if r.status else "unknown",
                "iocCount": r.ioc_count,
                "createdAt": r.created_at.isoformat() if r.created_at else "",
            }
            for r in recent_reports
        ],
    }
