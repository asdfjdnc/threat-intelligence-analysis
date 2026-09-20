"""应用配置 — 从 .env 文件和环境变量读取"""

import os
from pathlib import Path
from dotenv import load_dotenv

# 加载 backend/.env（override=True 覆盖 Shell 环境变量中的旧值）
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(env_path, override=True)


class Settings:
    """应用配置"""

    # DeepSeek API
    deepseek_api_key: str = os.getenv("DEEPSEEK_API_KEY", "")
    deepseek_base_url: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    llm_model: str = os.getenv("LLM_MODEL", "deepseek-chat")

    # 数据库
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./threat_intel.db")

    # 服务
    port: int = int(os.getenv("PORT", "8000"))
    host: str = os.getenv("HOST", "0.0.0.0")

    # 上传
    upload_dir: str = os.getenv("UPLOAD_DIR", "./uploads")

    @property
    def is_deepseek_configured(self) -> bool:
        return bool(self.deepseek_api_key and "sk-your-api-key" not in self.deepseek_api_key)


settings = Settings()
