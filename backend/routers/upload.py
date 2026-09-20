"""上传路由 — POST /api/upload"""

import os
import uuid
import logging
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from config import settings
from services import parser

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/upload")
async def upload_file(file: UploadFile = File(None), text: str = Form(None)):
    """上传文件或直接提交文本进行解析

    - 文件上传：multipart/form-data, field name = "file"
    - 文本提交：multipart/form-data, field name = "text"
    - 返回解析后的文本和文件类型
    """
    raw_text = ""
    file_type = "txt"
    file_name = ""

    if file and file.filename:
        # 文件上传
        file_name = file.filename
        ext = Path(file.filename).suffix.lower()

        # 保存到 uploads 目录
        upload_dir = Path(settings.upload_dir)
        if not upload_dir.is_absolute():
            upload_dir = Path(__file__).resolve().parent.parent / settings.upload_dir
        upload_dir.mkdir(parents=True, exist_ok=True)

        safe_name = f"{uuid.uuid4().hex[:8]}_{file.filename}"
        file_path = upload_dir / safe_name

        content = await file.read()

        with open(file_path, "wb") as f:
            f.write(content)

        # 解析
        try:
            if ext == ".pdf":
                raw_text = parser.parse_pdf_bytes(content)
                file_type = "pdf"
            elif ext in (".html", ".htm"):
                raw_text = parser.parse_html_string(content.decode("utf-8", errors="replace"))
                file_type = "html"
            else:
                raw_text = content.decode("utf-8", errors="replace")
                file_type = "txt"
        except Exception as e:
            logger.error(f"文件解析失败: {e}")
            raise HTTPException(status_code=400, detail=f"文件解析失败: {str(e)}")

    elif text:
        # 文本直接提交
        raw_text = text
        file_name = "手动输入"
        file_type = "txt"

    else:
        raise HTTPException(status_code=400, detail="请上传文件或提供文本内容")

    return {
        "fileName": file_name,
        "fileType": file_type,
        "rawText": raw_text,
        "charCount": len(raw_text),
        "uploadedAt": datetime.utcnow().isoformat(),
    }
