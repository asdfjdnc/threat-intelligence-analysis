"""分析路由 — POST /api/analyze (SSE 流式)"""

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Report, IOC, KGEdge, ReportStatus, RiskLevel
from services.ioc_extractor import IOCExtractor
from services.rag_service import correlate_iocs, update_global_iocs
from services.kg_service import generate_mermaid
from services.llm_client import (
    build_analysis_prompt, call_deepseek_stream, parse_llm_output, enrich_iocs,
)

router = APIRouter()
logger = logging.getLogger(__name__)

ioc_extractor = IOCExtractor()


class AnalyzeRequest(BaseModel):
    rawText: str
    fileName: str = "unknown"
    fileType: str = "txt"


@router.post("/analyze")
async def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)):
    """分析威胁情报文本，SSE 流式返回进度和结果

    流程: 输入验证 → IOC提取 → LLM分类 → RAG关联 → LLM分析 → 生成报告+KG → 存储到 SQLite
    """
    text = req.rawText or ""

    # ── 输入验证 ──
    if not text.strip():
        raise HTTPException(status_code=400, detail="文本内容为空")

    # 截断过长的文本（防止 token 爆炸）
    MAX_TEXT = 120_000
    if len(text) > MAX_TEXT:
        logger.warning(f"文本过长 ({len(text)} 字符)，截断到 {MAX_TEXT}")
        text = text[:MAX_TEXT]

    async def event_stream():
        try:
            # ── 阶段1: IOC 提取 ──
            yield _sse("progress", {"stage": "extracting", "message": "正在提取 IOC...", "percent": 20})

            extraction = ioc_extractor.extract(text, source=req.fileName)
            iocs_dict = [i.to_dict() for i in extraction.iocs]
            stats = extraction.statistics

            yield _sse("progress", {
                "stage": "extracting",
                "message": f"提取完成: {stats.get('total', 0)} 个 IOC",
                "percent": 35,
            })
            yield _sse("iocs", {
                "iocs": iocs_dict,
                "statistics": stats,
                "categories": extraction.categories,
            })

            # ── 阶段2: LLM 分类补全 ──
            yield _sse("progress", {"stage": "enriching", "message": "正在用 AI 补充分类...", "percent": 42})

            try:
                iocs_dict = await enrich_iocs(iocs_dict, text[:3000])
            except Exception as e:
                logger.warning(f"LLM enrich 异常（降级处理）: {e}")

            yield _sse("iocs_enriched", {"iocs": iocs_dict})
            yield _sse("progress", {"stage": "enriching", "message": "AI 分类完成", "percent": 48})

            # ── 阶段3: RAG 关联 ──
            yield _sse("progress", {"stage": "rag", "message": "正在进行历史关联分析...", "percent": 50})

            correlations = correlate_iocs(db, iocs_dict)
            known = [c for c in correlations if c["isKnown"]]
            unknown = [c for c in correlations if not c["isKnown"]]
            # 合并 RAG 历史关联 + 当前报告提取的 threat_group 类型 IOC
            all_related_groups = list(set(
                g for c in correlations for g in c.get("relatedGroups", [])
            ))
            # 从当前报告中提取的威胁组织名
            for ioc in iocs_dict:
                if ioc.get("ioc_type") == "threat_group" and ioc["value"] not in all_related_groups:
                    all_related_groups.append(ioc["value"])

            yield _sse("progress", {
                "stage": "rag",
                "message": f"关联完成: {len(known)} 已知, {len(unknown)} 新发现",
                "percent": 60,
            })
            yield _sse("correlations", {
                "known": len(known), "unknown": len(unknown), "groups": all_related_groups,
            })

            # ── 阶段4: LLM 分析 (流式) ──
            yield _sse("progress", {
                "stage": "analyzing",
                "message": "正在调用 LLM 进行分析...",
                "percent": 65,
            })

            prompt = build_analysis_prompt(
                iocs_dict, known, unknown, all_related_groups, text,
            )

            full_text = ""
            async for chunk in call_deepseek_stream(prompt):
                full_text += chunk
                yield _sse("llm_chunk", {"content": chunk})

            yield _sse("progress", {"stage": "analyzing", "message": "LLM 分析完成", "percent": 85})

            # 解析 LLM 输出
            parsed = parse_llm_output(full_text)

            # ── 阶段5: 生成知识图谱 ──
            yield _sse("progress", {"stage": "kg", "message": "正在生成知识图谱...", "percent": 90})

            # 构建 KG 边
            kg_edges_data = []
            for ioc in iocs_dict[:30]:
                kg_edges_data.append({
                    "source_label": req.fileName,
                    "source_type": "report",
                    "target_label": ioc["value"],
                    "target_type": "ioc",
                    "relation": "contains",
                    "confidence": ioc.get("confidence", 0.8),
                })

            for group in all_related_groups[:5]:
                kg_edges_data.append({
                    "source_label": group,
                    "source_type": "threat_group",
                    "target_label": req.fileName,
                    "target_type": "report",
                    "relation": "attributed_to",
                    "confidence": 0.85,
                })

            mermaid = generate_mermaid(req.fileName, iocs_dict, all_related_groups, kg_edges_data)

            # ── 阶段6: 存储到数据库 ──
            yield _sse("progress", {"stage": "saving", "message": "正在保存结果...", "percent": 95})

            risk_enum = RiskLevel.medium
            rl = parsed.get("overallRiskLevel", "medium")
            if rl in ("critical", "high", "medium", "low"):
                risk_enum = RiskLevel(rl)

            report = Report(
                title=req.fileName,
                source=req.fileType,
                file_name=req.fileName,
                raw_text=text[:50000],
                raw_text_length=len(text),
                status=ReportStatus.completed,
                ioc_count=stats.get("total", 0),
                known_ioc_count=len(known),
                unknown_ioc_count=len(unknown),
                threat_groups_found=all_related_groups,
                overall_risk_level=risk_enum,
                attributed_group=parsed.get("attributedGroup", ""),
                markdown_report=full_text,
                mermaid_code=mermaid,
            )
            db.add(report)
            db.flush()

            for ioc_data in iocs_dict:
                is_known = any(
                    c["iocType"] == ioc_data["ioc_type"]
                    and c["iocValue"] == ioc_data["value"]
                    and c["isKnown"]
                    for c in correlations
                )
                db.add(IOC(
                    report_id=report.id,
                    ioc_type=ioc_data["ioc_type"],
                    value=ioc_data["value"],
                    context=ioc_data.get("context", "")[:2000],  # 限制上下文长度
                    confidence=ioc_data.get("confidence", 1.0),
                    is_known=1 if is_known else 0,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    occurrence_count=1,
                ))

            for edge_data in kg_edges_data[:50]:
                db.add(KGEdge(
                    report_id=report.id,
                    source_label=edge_data["source_label"][:300],
                    source_type=edge_data["source_type"],
                    target_label=edge_data["target_label"][:300],
                    target_type=edge_data["target_type"],
                    relation=edge_data["relation"],
                    confidence=edge_data["confidence"],
                ))

            update_global_iocs(db, iocs_dict, all_related_groups)
            db.commit()

            # ── 完成 ──
            yield _sse("progress", {"stage": "completed", "message": "分析完成！", "percent": 100})
            yield _sse("result", {
                "reportId": report.id,
                "status": "completed",
                "iocCount": report.ioc_count,
                "knownIOCCount": report.known_ioc_count,
                "unknownIOCCount": report.unknown_ioc_count,
                "threatGroupsFound": all_related_groups,
                "overallRiskLevel": parsed.get("overallRiskLevel", "medium"),
                "mermaid": mermaid,
                "analysisParsed": parsed,
            })

        except Exception as e:
            logger.error(f"分析失败: {e}", exc_info=True)
            yield _sse("error", {"message": _safe_error_message(e)})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _sse(event: str, data: dict | Any) -> str:
    """生成安全的 SSE 事件字符串

    确保 data 始终是有效的 JSON，即使用户数据中包含特殊字符。
    """
    try:
        json_str = json.dumps(data, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as e:
        logger.warning(f"JSON 序列化失败 ({event}): {e}")
        json_str = json.dumps({"error": "序列化失败"}, ensure_ascii=False)
    return f"event: {event}\ndata: {json_str}\n\n"


def _safe_error_message(e: Exception) -> str:
    """生成安全的错误消息，过滤掉敏感信息"""
    msg = str(e)
    # 截断长错误消息
    if len(msg) > 500:
        msg = msg[:497] + "..."
    # 移除可能的路径信息（安全考虑）
    msg = msg.replace("\\", "/")
    return msg
