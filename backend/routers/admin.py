"""管理路由 — DELETE /api/admin/clear-all"""

import os
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from database import get_db, engine
from models import Base

router = APIRouter()


@router.delete("/admin/clear-all")
def clear_all_data(db: Session = Depends(get_db)):
    """清空所有分析结果：报告、IOC、知识图谱、全局IOC视图

    保留威胁组织目录数据。
    """
    tables_cleared = []
    rows_deleted = {}

    try:
        # 按外键顺序删除（先删子表）
        tables = ["kg_edges", "iocs", "ioc_global", "reports"]
        for table in tables:
            result = db.execute(text(f"SELECT COUNT(*) FROM {table}"))
            count = result.scalar()
            db.execute(text(f"DELETE FROM {table}"))
            tables_cleared.append(table)
            rows_deleted[table] = count

        db.commit()

        # 清理上传目录
        upload_dir = Path(__file__).resolve().parent.parent / "uploads"
        files_deleted = 0
        if upload_dir.exists():
            for f in upload_dir.iterdir():
                if f.is_file():
                    f.unlink()
                    files_deleted += 1

        return {
            "ok": True,
            "tablesCleared": tables_cleared,
            "rowsDeleted": rows_deleted,
            "totalRowsDeleted": sum(rows_deleted.values()),
            "filesDeleted": files_deleted,
            "message": f"已清空 {sum(rows_deleted.values())} 条记录和 {files_deleted} 个上传文件",
        }
    except Exception as e:
        db.rollback()
        return {"ok": False, "error": str(e)}
