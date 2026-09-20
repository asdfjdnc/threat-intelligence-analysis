"""数据库 — SQLAlchemy engine + session + Base"""

import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

from config import settings

# 确保数据库目录存在
db_path = settings.database_url.replace("sqlite:///", "")
if db_path.startswith("./"):
    db_path = str(Path(__file__).resolve().parent / db_path[2:])
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False}, echo=False)
else:
    engine = create_engine(settings.database_url, echo=False)


# SQLite 外键支持
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI 依赖 — 获取数据库会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """创建所有表"""
    Base.metadata.create_all(bind=engine)
