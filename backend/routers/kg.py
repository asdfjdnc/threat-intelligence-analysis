"""知识图谱路由 — GET /api/knowledge-graph"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from models import Report, ThreatGroup, KGEdge
from services.kg_service import generate_mermaid, generate_global_mermaid

router = APIRouter()


@router.get("/knowledge-graph")
def get_knowledge_graph(
    report_id: int = Query(None),
    db: Session = Depends(get_db),
):
    """获取知识图谱 Mermaid 代码

    - 不指定 report_id：返回全局图谱
    - 指定 report_id：返回该报告的图谱
    """
    if report_id:
        report = db.query(Report).filter(Report.id == report_id).first()
        if not report:
            return {"mermaid": "", "error": "报告不存在"}

        return {
            "mermaid": report.mermaid_code or "",
            "reportId": report_id,
            "reportTitle": report.title,
        }

    # 全局图谱
    reports = (
        db.query(Report)
        .filter(Report.mermaid_code != "")
        .order_by(Report.created_at.desc())
        .limit(10)
        .all()
    )
    groups = db.query(ThreatGroup).limit(10).all()

    reports_data = [{"id": r.id, "title": r.title} for r in reports]
    groups_data = [{"name": g.name} for g in groups]

    return {
        "mermaid": generate_global_mermaid(reports_data, groups_data),
        "reportCount": len(reports),
        "groupCount": len(groups),
    }
