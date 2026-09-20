"""文档解析服务 — pymupdf + bs4"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def parse_pdf_bytes(data: bytes) -> str:
    """从字节流解析 PDF"""
    import fitz  # pymupdf

    doc = fitz.open(stream=data, filetype="pdf")
    all_parts = []
    try:
        for page in doc:
            text = page.get_text("text")
            if text.strip():
                all_parts.append(text.strip())
    finally:
        doc.close()
    return "\n\n".join(all_parts)


def parse_pdf_file(file_path: str) -> str:
    """从文件路径解析 PDF"""
    import fitz

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")

    logger.info(f"解析 PDF: {file_path}")
    doc = fitz.open(str(path))
    all_parts = []
    try:
        for page in doc:
            text = page.get_text("text")
            if text.strip():
                all_parts.append(text.strip())
    finally:
        doc.close()

    result = "\n\n".join(all_parts)
    logger.info(f"PDF 解析完成: {len(result)} 字符, {len(all_parts)} 页")
    return result


def parse_html_string(html: str) -> str:
    """解析 HTML 字符串，提取正文文本"""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")

    # 移除脚本、样式
    for tag in soup.find_all(["script", "noscript", "style"]):
        tag.decompose()

    # 移除非正文元素
    for tag in soup.find_all(["nav", "footer", "header", "aside"]):
        tag.decompose()

    # 提取标题
    parts = []
    for h in soup.find_all(["h1", "h2", "h3", "h4"]):
        text = h.get_text(strip=True)
        if text:
            level = int(h.name[1])
            parts.append(f"{'#' * level} {text}")

    # 提取段落
    for p in soup.find_all("p"):
        text = p.get_text(strip=True)
        if text and len(text) > 5:
            parts.append(text)

    # 提取列表
    for ul in soup.find_all(["ul", "ol"]):
        for li in ul.find_all("li"):
            text = li.get_text(strip=True)
            if text:
                parts.append(f"- {text}")

    result = "\n\n".join(parts)
    if not result.strip():
        result = soup.get_text(separator="\n", strip=True)

    logger.info(f"HTML 解析完成: {len(result)} 字符")
    return result


def parse_html_file(file_path: str) -> str:
    """解析本地 HTML 文件"""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    html = path.read_text(encoding="utf-8", errors="replace")
    return parse_html_string(html)


def parse_text(content: str) -> str:
    """解析纯文本（直接返回）"""
    return content


def parse_file(file_path: str) -> tuple[str, str]:
    """根据扩展名自动选择解析器，返回 (文本, 类型)"""
    ext = Path(file_path).suffix.lower()
    if ext == ".pdf":
        return parse_pdf_file(file_path), "pdf"
    elif ext in (".html", ".htm"):
        return parse_html_file(file_path), "html"
    else:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), "txt"
