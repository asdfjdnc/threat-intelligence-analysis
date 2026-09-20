"""SQLAlchemy ORM 模型"""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database import Base


class ReportStatus(str, enum.Enum):
    pending = "pending"
    parsing = "parsing"
    extracting = "extracting"
    analyzing = "analyzing"
    completed = "completed"
    error = "error"


class RiskLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Report(Base):
    """分析报告"""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    source = Column(String(50), default="txt")  # pdf / html / txt / url
    file_name = Column(String(500), default="")
    raw_text = Column(Text, default="")
    raw_text_length = Column(Integer, default=0)
    status = Column(Enum(ReportStatus), default=ReportStatus.pending)
    ioc_count = Column(Integer, default=0)
    known_ioc_count = Column(Integer, default=0)
    unknown_ioc_count = Column(Integer, default=0)
    threat_groups_found = Column(JSON, default=list)
    overall_risk_level = Column(Enum(RiskLevel), nullable=True)
    attributed_group = Column(String(200), default="")
    markdown_report = Column(Text, default="")
    mermaid_code = Column(Text, default="")
    error_message = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    iocs = relationship("IOC", back_populates="report", cascade="all, delete-orphan")
    kg_edges = relationship("KGEdge", back_populates="report", cascade="all, delete-orphan")


class IOC(Base):
    """威胁指标"""
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(Integer, ForeignKey("reports.id", ondelete="CASCADE"), nullable=False)
    ioc_type = Column(String(50), nullable=False)  # ip, domain, url, hash, cve, attack_technique, threat_group, email
    value = Column(String(500), nullable=False)
    context = Column(Text, default="")
    confidence = Column(Float, default=1.0)
    is_known = Column(Integer, default=0)  # 0=新发现, 1=已知
    first_seen = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, default=datetime.now)
    occurrence_count = Column(Integer, default=1)

    report = relationship("Report", back_populates="iocs")


class ThreatGroup(Base):
    """威胁组织"""
    __tablename__ = "threat_groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), unique=True, nullable=False)
    aliases = Column(JSON, default=list)
    description = Column(Text, default="")
    origin = Column(String(100), default="")
    threat_level = Column(String(20), default="medium")  # high / medium / low
    first_active = Column(String(10), default="")
    targeted_sectors = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class KGEdge(Base):
    """知识图谱边"""
    __tablename__ = "kg_edges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(Integer, ForeignKey("reports.id", ondelete="CASCADE"), nullable=False)
    source_label = Column(String(300), nullable=False)
    source_type = Column(String(50), nullable=False)  # report / ioc / threat_group
    target_label = Column(String(300), nullable=False)
    target_type = Column(String(50), nullable=False)
    relation = Column(String(100), nullable=False)  # contains / associated_with / attributed_to / uses / involves
    confidence = Column(Float, default=1.0)

    report = relationship("Report", back_populates="kg_edges")


class IOCGlobalView(Base):
    """IOC 全局聚合视图 — 跨报告合并"""
    __tablename__ = "ioc_global"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(50), nullable=False)
    value = Column(String(500), nullable=False)
    first_seen = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, default=datetime.now)
    occurrence_count = Column(Integer, default=1)
    associated_groups = Column(JSON, default=list)
