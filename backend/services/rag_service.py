"""RAG 关联服务 — SQLite 历史 IOC 查询"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy import func

from models import IOC, IOCGlobalView

logger = logging.getLogger(__name__)


def correlate_iocs(db: Session, iocs: list[dict]) -> list[dict]:
    """对提取的 IOC 进行历史关联分析

    返回每个 IOC 的关联结果：
    - is_known: 是否在数据库中出现过
    - related_groups: 关联的已知威胁组织
    """
    results = []

    for ioc in iocs:
        ioc_type = ioc["ioc_type"]
        ioc_value = ioc["value"]

        # 查询全局 IOC 视图
        global_match = (
            db.query(IOCGlobalView)
            .filter(
                IOCGlobalView.ioc_type == ioc_type,
                IOCGlobalView.value == ioc_value,
            )
            .first()
        )

        if global_match:
            results.append({
                "iocType": ioc_type,
                "iocValue": ioc_value,
                "isKnown": True,
                "firstSeen": global_match.first_seen.isoformat() if global_match.first_seen else "",
                "lastSeen": global_match.last_seen.isoformat() if global_match.last_seen else "",
                "occurrenceCount": global_match.occurrence_count,
                "relatedGroups": global_match.associated_groups or [],
            })
        else:
            results.append({
                "iocType": ioc_type,
                "iocValue": ioc_value,
                "isKnown": False,
                "relatedGroups": [],
            })

    return results


def update_global_iocs(db: Session, iocs: list[dict], threat_groups: list[str]):
    """更新全局 IOC 视图 — 新 IOC 插入，已有 IOC 更新"""
    for ioc in iocs:
        ioc_type = ioc["ioc_type"]
        ioc_value = ioc["value"]

        existing = (
            db.query(IOCGlobalView)
            .filter(
                IOCGlobalView.ioc_type == ioc_type,
                IOCGlobalView.value == ioc_value,
            )
            .first()
        )

        if existing:
            existing.last_seen = datetime.utcnow()
            existing.occurrence_count += 1
            # 合并威胁组织
            merged_groups = list(set(existing.associated_groups or []) | set(threat_groups))
            existing.associated_groups = merged_groups
        else:
            db.add(IOCGlobalView(
                ioc_type=ioc_type,
                value=ioc_value,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                occurrence_count=1,
                associated_groups=threat_groups,
            ))

    db.commit()
    logger.info(f"全局 IOC 视图已更新，涉及 {len(iocs)} 条 IOC")
