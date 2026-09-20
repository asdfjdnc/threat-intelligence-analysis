"""知识图谱服务 — Mermaid v11 兼容代码生成"""

import re
import logging

logger = logging.getLogger(__name__)


def _sanitize_id(s: str) -> str:
    """将任意字符串转为合法的 Mermaid 节点 ID（仅字母数字和下划线）"""
    s = re.sub(r'[^a-zA-Z0-9_]', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    return s or "node"


def _safe_label(s: str) -> str:
    """清洗 Mermaid 标签中的危险字符（配合前端 htmlLabels:false）"""
    # 移除换行、制表等破坏 Mermaid 行结构的控制字符
    s = s.replace("\r", "").replace("\n", " ").replace("\t", " ")
    # 双引号必须移除（破坏 Mermaid 标签引号）
    s = s.replace('"', "'")
    # # 号需要转义（Mermaid 注释符号）
    s = s.replace("#", "&num;")
    if len(s) > 35:
        s = s[:32] + "..."
    return s


def _icon_for(ioc_type: str) -> str:
    return {
        "ip": "[IP]", "domain": "[DOM]", "url": "[URL]",
        "hash": "[HASH]", "cve": "[CVE]", "attack_technique": "[T]",
        "threat_group": "[GRP]", "email": "[EML]",
    }.get(ioc_type, "")


def _class_for(ioc_type: str) -> str:
    if ioc_type == "cve":
        return "cve"
    if ioc_type == "attack_technique":
        return "technique"
    return "ioc"


def generate_mermaid(
    report_title: str,
    iocs: list[dict],
    threat_groups: list[str],
    kg_edges: list[dict] | None = None,
) -> str:
    """生成 Mermaid v11 兼容的知识图谱代码"""

    lines = [
        "flowchart TB",
        "  classDef ioc fill:#ff9800,stroke:#e65100,color:#fff",
        "  classDef group fill:#f44336,stroke:#b71c1c,color:#fff",
        "  classDef report fill:#4caf50,stroke:#1b5e20,color:#fff",
        "  classDef technique fill:#2196f3,stroke:#0d47a1,color:#fff",
        "  classDef cve fill:#9c27b0,stroke:#6a1b9a,color:#fff",
        "",
    ]

    classes = []
    nodes = set()

    # --- Report ---
    title = _safe_label(report_title[:30])
    lines.append(f'  report["{title}"]')
    classes.append("  class report report")
    nodes.add("report")
    lines.append("")

    # --- IOCs ---
    ioc_ids = []
    for i, ioc in enumerate(iocs[:20]):
        nid = _sanitize_id(f"ioc{i}_{ioc['value'][:30]}")
        icon = _icon_for(ioc["ioc_type"])
        label = _safe_label(f"{icon} {ioc['value'][:25]}".strip())
        css = _class_for(ioc["ioc_type"])
        lines.append(f'  {nid}["{label}"]')
        classes.append(f"  class {nid} {css}")
        nodes.add(nid)
        ioc_ids.append(nid)
        lines.append(f"  report -->|contains| {nid}")

    lines.append("")

    # --- Threat groups ---
    for i, group in enumerate(threat_groups[:5]):
        nid = f"group{i}"
        label = _safe_label(group[:20])
        lines.append(f'  {nid}["[GRP] {label}"]')
        classes.append(f"  class {nid} group")
        nodes.add(nid)
        lines.append(f"  {nid} -->|attributed_to| report")
        for j, ioc_nid in enumerate(ioc_ids[:3]):
            lines.append(f"  {nid} -->|uses| {ioc_nid}")

    lines.append("")

    # --- DB edges ---
    if kg_edges:
        seen = set()
        for edge in kg_edges[:30]:
            src = _sanitize_id(str(edge["source_label"])[:30])
            tgt = _sanitize_id(str(edge["target_label"])[:30])
            rel = _safe_label(str(edge["relation"])[:15])
            if src == tgt:
                continue
            key = (src, tgt, rel)
            if key in seen:
                continue
            seen.add(key)

            if src not in nodes:
                sl = _safe_label(str(edge["source_label"])[:25])
                sc = "group" if edge.get("source_type") == "threat_group" else "ioc"
                lines.append(f'  {src}["{sl}"]')
                classes.append(f"  class {src} {sc}")
                nodes.add(src)
            if tgt not in nodes:
                tl = _safe_label(str(edge["target_label"])[:25])
                tc = "group" if edge.get("target_type") == "threat_group" else "ioc"
                lines.append(f'  {tgt}["{tl}"]')
                classes.append(f"  class {tgt} {tc}")
                nodes.add(tgt)
            lines.append(f"  {src} -->|{rel}| {tgt}")

    lines.append("")
    lines.extend(classes)
    return "\n".join(lines)


def generate_global_mermaid(reports: list[dict], groups: list[dict]) -> str:
    """生成全局知识图谱"""

    lines = [
        "flowchart TB",
        "  classDef ioc fill:#ff9800,stroke:#e65100,color:#fff",
        "  classDef group fill:#f44336,stroke:#b71c1c,color:#fff",
        "  classDef report fill:#4caf50,stroke:#1b5e20,color:#fff",
        "  classDef technique fill:#2196f3,stroke:#0d47a1,color:#fff",
        "",
    ]

    classes = []

    for i, r in enumerate(reports[:10]):
        nid = f"rep{i}"
        label = _safe_label(r.get("title", "")[:25])
        lines.append(f'  {nid}["{label}"]')
        classes.append(f"  class {nid} report")

    lines.append("")

    for i, g in enumerate(groups[:10]):
        nid = f"grp{i}"
        label = _safe_label(g.get("name", "")[:20])
        lines.append(f'  {nid}["[GRP] {label}"]')
        classes.append(f"  class {nid} group")

    lines.append("")
    lines.extend(classes)
    return "\n".join(lines)
