"""DeepSeek-v4 LLM 客户端 — 从 TypeScript ai_client.ts 重写为 Python"""

import json
import logging
from typing import AsyncGenerator

import httpx

from config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """你是一位资深的网络安全威胁情报分析师。你的任务是基于提取的 IOC（威胁指标）和 RAG 关联分析结果，生成专业的威胁情报分析报告。

请严格按照以下结构输出分析内容：

## 攻击链还原
- 根据 ATT&CK 技术编号还原完整攻击链
- 说明每个阶段使用的具体技术

## 关联原因分析
- 分析 IOC 之间的关联性
- 说明与已知威胁组织的相似度
- 指出技术重叠和基础设施复用

## 影响评估
- 评估攻击的严重程度
- 分析可能的受影响范围
- 评估数据泄露风险

## 防御建议
- 提供即时响应措施
- 列出长期防御策略
- 针对具体 ATT&CK 技术给出缓解建议

请使用简体中文输出。"""


def build_analysis_prompt(
    iocs: list[dict],
    known_iocs: list[dict],
    unknown_iocs: list[dict],
    related_groups: list[str],
    raw_text_snippet: str,
) -> str:
    """构建发给 LLM 的分析 prompt"""
    ioc_lines = []
    for ioc in iocs:
        ctx = ioc.get("context", "")[:80]
        ioc_lines.append(f"- [{ioc['ioc_type']}] {ioc['value']}" +
                         (f" (上下文: {ctx})" if ctx else ""))

    return f"""请分析以下威胁情报数据并生成报告：

## 提取的 IOC 列表
{chr(10).join(ioc_lines)}

## RAG 关联结果
- 已知 IOC: {len(known_iocs)} 个
- 新发现 IOC: {len(unknown_iocs)} 个
- 相关威胁组织: {', '.join(related_groups) if related_groups else '无'}

## 原始报告摘要
{raw_text_snippet[:1500]}

请按照系统提示中的结构输出完整分析报告。"""


async def call_deepseek_stream(
    prompt: str,
) -> AsyncGenerator[str, None]:
    """流式调用 DeepSeek API，逐块返回文本"""
    if not settings.is_deepseek_configured:
        yield "⚠️ DeepSeek API Key 未配置，无法生成分析报告。请在 backend/.env 中设置 DEEPSEEK_API_KEY。"
        return

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Bearer {settings.deepseek_api_key}",
    }

    payload = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": True,
        "temperature": 0.3,
        "max_tokens": 4096,
    }

    api_url = f"{settings.deepseek_base_url.rstrip('/')}/chat/completions"
    logger.info(f"调用 DeepSeek API: {api_url} model={settings.llm_model}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        async with client.stream(
            "POST",
            api_url,
            headers=headers,
            json=payload,
        ) as response:
            if response.status_code != 200:
                body = await response.aread()
                error_text = body.decode("utf-8", errors="replace")[:500]
                logger.error(f"DeepSeek API 错误 [{response.status_code}]: {error_text}")
                yield f"\n\n❌ API 调用失败 (HTTP {response.status_code})\n请检查 backend/.env 中的 DEEPSEEK_BASE_URL 和 LLM_MODEL。\n当前配置: URL={api_url}, Model={settings.llm_model}\n详情: {error_text}"
                return

            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        return
                    try:
                        parsed = json.loads(data)
                        content = parsed.get("choices", [{}])[0].get("delta", {}).get("content", "")
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        continue


async def call_deepseek(prompt: str) -> str:
    """非流式调用 DeepSeek API，返回完整文本"""
    if not settings.is_deepseek_configured:
        return "⚠️ DeepSeek API Key 未配置。请在 backend/.env 中设置 DEEPSEEK_API_KEY。"

    api_url = f"{settings.deepseek_base_url.rstrip('/')}/chat/completions"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Bearer {settings.deepseek_api_key}",
    }

    payload = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "temperature": 0.3,
        "max_tokens": 4096,
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            api_url,
            headers=headers,
            json=payload,
        )

        if response.status_code != 200:
            error_text = response.text[:500]
            logger.error(f"DeepSeek API 错误 [{response.status_code}]: {error_text}")
            return f"❌ API 调用失败 (HTTP {response.status_code})\n请检查 backend/.env 配置。\n当前: URL={api_url}, Model={settings.llm_model}\n详情: {error_text}"

        data = response.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")


def parse_llm_output(text: str) -> dict:
    """解析 LLM 输出的分析报告，提取结构化数据"""
    import re

    def extract_section(pattern: str) -> str:
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ""

    summary = text[:300]
    attack_chain = extract_section(r"攻击链还原\s*\n([\s\S]*?)(?=\n## |\n# |$)")
    correlation = extract_section(r"关联原因分析\s*\n([\s\S]*?)(?=\n## |\n# |$)")
    impact = extract_section(r"影响评估\s*\n([\s\S]*?)(?=\n## |\n# |$)")
    defense = extract_section(r"防御建议\s*\n([\s\S]*?)(?=\n## |\n# |$)")

    # 提取归因组织
    group_match = re.search(r"归因[：:]\s*(.+)", text) or re.search(r"威胁组织[：:]\s*(.+)", text)
    attributed_group = group_match.group(1).strip() if group_match else ""

    # 评估风险等级
    risk_level = "medium"
    if re.search(r"严重|危急|critical|severe", text, re.IGNORECASE):
        risk_level = "critical"
    elif re.search(r"高|high|重大", text, re.IGNORECASE):
        risk_level = "high"
    elif re.search(r"低|low", text, re.IGNORECASE):
        risk_level = "low"

    return {
        "summary": summary,
        "attackChain": attack_chain,
        "correlationReasoning": correlation,
        "impactAssessment": impact,
        "defenseSuggestions": defense,
        "attributedGroup": attributed_group,
        "overallRiskLevel": risk_level,
    }


# ─── IOC 补充分类 ────────────────────────────────────────

ENRICH_PROMPT = """你是威胁情报分析师。请对以下 IOC 进行分类标注。

对每个 IOC 补充:
- subtype: 细分类型 (如 c2_ip, phishing_domain, malware_hash, exploit_cve, 钓鱼邮件, 持久化技术, apt_group 等)
- role: 一句话角色 (如 "C2 服务器", "钓鱼页面", "恶意软件样本", "初始访问")
- risk_level: high/medium/low
- description: 结合上下文做一句话描述 (不超过 50 字)

输入 IOC 列表:
{ioc_list}

请严格按 JSON 格式输出:
{{"iocs": [{{"value": "原值", "subtype": "...", "role": "...", "risk_level": "high", "description": "..."}}, ...]}}

只输出 JSON，不要有其他文字。"""


async def enrich_iocs(
    iocs: list[dict],
    text_snippet: str = "",
    timeout: float = 20.0,
) -> list[dict]:
    """调用 LLM 为 IOC 补充分类标签

    Args:
        iocs: 基础 IOC 列表 [{ioc_type, value, context, ...}]
        text_snippet: 原始报告摘要（用于上下文理解）
        timeout: 超时秒数

    Returns:
        带 subtype/role/risk_level/description 的 IOC 列表（与输入顺序一致）
    """
    if not iocs or not settings.is_deepseek_configured:
        return iocs

    # 构建精简 IOC 列表（只传 value + context + type）
    compact = []
    for ioc in iocs:
        compact.append({
            "type": ioc.get("ioc_type", ioc.get("type", "")),
            "value": ioc.get("value", ""),
            "context": ioc.get("context", "")[:100],
        })

    ioc_json = json.dumps(compact, ensure_ascii=False, indent=2)
    prompt = ENRICH_PROMPT.format(ioc_list=ioc_json)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{settings.deepseek_base_url.rstrip('/')}/chat/completions",
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "Authorization": f"Bearer {settings.deepseek_api_key}",
                },
                json={
                    "model": settings.llm_model,
                    "messages": [
                        {"role": "user", "content": prompt},
                    ],
                    "stream": False,
                    "temperature": 0.1,
                    "max_tokens": 2048,
                },
            )

            if response.status_code != 200:
                logger.warning(f"IOC enrich API 失败: {response.status_code}")
                return iocs

            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

            # 提取 JSON（带容错处理）
            json_start = content.find("{")
            json_end = content.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                try:
                    payload = json.loads(content[json_start:json_end])
                    enriched_list = payload.get("iocs", [])

                    # 按 value 匹配回原始 IOC
                    enriched_map = {
                        e["value"].lower(): e
                        for e in enriched_list
                        if isinstance(e, dict) and "value" in e
                    }
                    for ioc in iocs:
                        key = ioc.get("value", "").lower()
                        if key in enriched_map:
                            e = enriched_map[key]
                            ioc["subtype"] = e.get("subtype", "")
                            ioc["role"] = e.get("role", "")
                            ioc["risk_level"] = e.get("risk_level", "")
                            ioc["description"] = e.get("description", "")
                except (json.JSONDecodeError, TypeError, KeyError) as je:
                    logger.warning(f"IOC enrich JSON 解析失败: {je}")
                    # 降级：保持原始 IOC 不变（无 LLM 分类）

            return iocs

    except Exception as e:
        logger.warning(f"IOC enrich 失败 (降级为纯 Regex): {e}")
        return iocs
