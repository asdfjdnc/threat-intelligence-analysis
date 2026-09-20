"""报告路由 — GET/DELETE /api/reports"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.orm import joinedload

from database import get_db
from models import Report, IOC, KGEdge

router = APIRouter()


@router.get("/reports")
def list_reports(db: Session = Depends(get_db)):
    """获取所有报告列表"""
    reports = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": r.id,
            "title": r.title,
            "source": r.source,
            "status": r.status.value,
            "iocCount": r.ioc_count,
            "knownIOCCount": r.known_ioc_count,
            "unknownIOCCount": r.unknown_ioc_count,
            "threatGroupsFound": r.threat_groups_found or [],
            "overallRiskLevel": r.overall_risk_level.value if r.overall_risk_level else None,
            "createdAt": r.created_at.isoformat() if r.created_at else "",
        }
        for r in reports
    ]


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db)):
    """获取单个报告详情（含 IOC 列表和 KG 边）"""
    report = (
        db.query(Report)
        .options(joinedload(Report.iocs), joinedload(Report.kg_edges))
        .filter(Report.id == report_id)
        .first()
    )

    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")

    return {
        "id": report.id,
        "title": report.title,
        "source": report.source,
        "fileName": report.file_name,
        "status": report.status.value,
        "iocCount": report.ioc_count,
        "knownIOCCount": report.known_ioc_count,
        "unknownIOCCount": report.unknown_ioc_count,
        "threatGroupsFound": report.threat_groups_found or [],
        "overallRiskLevel": report.overall_risk_level.value if report.overall_risk_level else "medium",
        "attributedGroup": report.attributed_group,
        "markdownReport": report.markdown_report,
        "mermaidCode": report.mermaid_code,
        "rawText": report.raw_text[:3000] if report.raw_text else "",
        "errorMessage": report.error_message,
        "createdAt": report.created_at.isoformat() if report.created_at else "",
        "updatedAt": report.updated_at.isoformat() if report.updated_at else "",
        "iocs": [
            {
                "ioc_type": i.ioc_type,
                "value": i.value,
                "context": i.context,
                "confidence": i.confidence,
                "isKnown": bool(i.is_known),
            }
            for i in (report.iocs or [])
        ],
        "kgEdges": [
            {
                "sourceLabel": e.source_label,
                "sourceType": e.source_type,
                "targetLabel": e.target_label,
                "targetType": e.target_type,
                "relation": e.relation,
                "confidence": e.confidence,
            }
            for e in (report.kg_edges or [])
        ],
    }


@router.delete("/reports/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    """删除报告及其关联的 IOC 和 KG 边"""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")

    db.delete(report)
    db.commit()
    return {"ok": True, "message": f"报告 #{report_id} 已删除"}
