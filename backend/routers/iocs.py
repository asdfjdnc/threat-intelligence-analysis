"""IOC 路由 — GET /api/iocs, /api/iocs/types, /api/iocs/{id}, /api/threat-search"""

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_

from database import get_db
from models import IOCGlobalView, IOC

router = APIRouter()


@router.get("/iocs")
def list_iocs(
    ioc_type: str = Query(None, alias="type"),
    search: str = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """查询 IOC 列表，支持类型筛选和关键词搜索"""
    query = db.query(IOCGlobalView).order_by(IOCGlobalView.last_seen.desc())

    if ioc_type:
        query = query.filter(IOCGlobalView.ioc_type == ioc_type)

    if search:
        like = f"%{search}%"
        query = query.filter(IOCGlobalView.value.ilike(like))

    total = query.count()
    iocs = query.offset(offset).limit(limit).all()

    return {
        "total": total,
        "items": [
            {
                "id": i.id,
                "type": i.ioc_type,
                "value": i.value,
                "firstSeen": i.first_seen.isoformat() if i.first_seen else "",
                "lastSeen": i.last_seen.isoformat() if i.last_seen else "",
                "occurrenceCount": i.occurrence_count,
                "associatedGroups": i.associated_groups or [],
            }
            for i in iocs
        ],
    }


@router.get("/iocs/types")
def list_ioc_types(db: Session = Depends(get_db)):
    """获取所有 IOC 类型列表（用于筛选下拉）"""
    types = (
        db.query(IOCGlobalView.ioc_type)
        .distinct()
        .order_by(IOCGlobalView.ioc_type)
        .all()
    )
    return [t[0] for t in types]


@router.get("/iocs/{ioc_id}")
def get_ioc_detail(ioc_id: int, db: Session = Depends(get_db)):
    """获取 IOC 详情（含同报告内关联 IOC）"""
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC 不存在")

    # 查询同报告内其他 IOC
    related_iocs = (
        db.query(IOC)
        .filter(IOC.report_id == ioc.report_id, IOC.id != ioc.id)
        .limit(20)
        .all()
    )

    return {
        "id": ioc.id,
        "reportId": ioc.report_id,
        "iocType": ioc.ioc_type,
        "value": ioc.value,
        "context": ioc.context or "",
        "confidence": ioc.confidence,
        "isKnown": bool(ioc.is_known),
        "firstSeen": ioc.first_seen.isoformat() if ioc.first_seen else "",
        "lastSeen": ioc.last_seen.isoformat() if ioc.last_seen else "",
        "occurrenceCount": ioc.occurrence_count,
        "relatedIOCs": [
            {
                "id": r.id,
                "reportId": r.report_id,
                "iocType": r.ioc_type,
                "value": r.value,
                "confidence": r.confidence,
                "isKnown": bool(r.is_known),
            }
            for r in related_iocs
        ],
    }


@router.get("/threat-search")
def threat_search(
    q: str = Query(..., min_length=1, description="搜索关键词"),
    db: Session = Depends(get_db),
):
    """统一威胁搜索 — 跨所有 IOC 类型模糊查询"""
    like = f"%{q}%"
    results = (
        db.query(IOCGlobalView)
        .filter(
            or_(
                IOCGlobalView.value.ilike(like),
                IOCGlobalView.ioc_type.ilike(like),
            )
        )
        .order_by(IOCGlobalView.last_seen.desc())
        .limit(50)
        .all()
    )

    return {
        "query": q,
        "total": len(results),
        "items": [
            {
                "id": i.id,
                "type": i.ioc_type,
                "value": i.value,
                "firstSeen": i.first_seen.isoformat() if i.first_seen else "",
                "lastSeen": i.last_seen.isoformat() if i.last_seen else "",
                "occurrenceCount": i.occurrence_count,
                "associatedGroups": i.associated_groups or [],
            }
            for i in results
        ],
    }
