"""FastAPI 主入口"""

import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import settings
from database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期 — 启动时初始化数据库"""
    init_db()
    # 确保上传目录存在
    upload_path = Path(settings.upload_dir)
    if not upload_path.is_absolute():
        upload_path = Path(__file__).resolve().parent / settings.upload_dir
    upload_path.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="威胁情报分析平台",
    description="本地化威胁情报自动化提取与分析系统",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — 允许前端开发服务器
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 静态文件 — 上传目录
uploads_abs = str(Path(__file__).resolve().parent / settings.upload_dir)
if os.path.isdir(uploads_abs):
    app.mount("/uploads", StaticFiles(directory=uploads_abs), name="uploads")


@app.get("/api/health")
def health_check():
    return {"status": "ok", "version": "2.0.0"}


@app.get("/api/config")
def get_config():
    """返回当前运行配置（模型、API 地址等）"""
    return {
        "deepseek_configured": settings.is_deepseek_configured,
        "model": {
            "name": settings.llm_model,
            "base_url": settings.deepseek_base_url,
        },
    }


# 注册路由
from routers import upload, analysis, reports, iocs, threat_groups, kg, stats, admin

app.include_router(upload.router, prefix="/api", tags=["上传"])

app.include_router(admin.router, prefix="/api", tags=["管理"])
app.include_router(analysis.router, prefix="/api", tags=["分析"])
app.include_router(reports.router, prefix="/api", tags=["报告"])
app.include_router(iocs.router, prefix="/api", tags=["IOC"])
app.include_router(threat_groups.router, prefix="/api", tags=["威胁组织"])
app.include_router(kg.router, prefix="/api", tags=["知识图谱"])
app.include_router(stats.router, prefix="/api", tags=["统计"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=True)
