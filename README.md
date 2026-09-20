# 威胁情报自动化提取与分析平台

本地化网络安全威胁情报分析平台，支持文档解析、IOC 提取、LLM 分析、知识图谱生成。

## 功能

1. **文档解析** — 上传 PDF/HTML/文本威胁报告，自动提取文本
2. **IOC 提取** — 正则识别 IP、域名、URL、文件哈希、CVE、ATT&CK 技术
3. **RAG 关联分析** — SQLite 历史情报库检索，判断 IOC 是否已知
4. **LLM 报告生成** — DeepSeek-v4 流式生成结构化 Markdown 分析报告
5. **知识图谱** — Mermaid 可视化，展示 IOC/组织/报告关系

## 架构

```
浏览器 (React + Vite + Ant Design)
    │
    ├─ HTTP REST ───→ Python FastAPI (localhost:8000)
    │                    ├─ SQLite (SQLAlchemy)
    │                    ├─ pymupdf / bs4 (文档解析)
    │                    ├─ IOC Extractor (正则提取)
    │                    └─ DeepSeek-v4 API (httpx 直调)
    │
    └─ 本地文件系统 (uploads/ 目录)
```

## 项目结构

```
├── backend/                  # Python FastAPI 后端
│   ├── main.py               # 入口, CORS, 路由注册
│   ├── config.py             # 环境变量配置
│   ├── database.py           # SQLAlchemy + SQLite
│   ├── models.py             # ORM 模型
│   ├── routers/              # API 路由
│   │   ├── upload.py         # 文件上传 + 解析
│   │   ├── analysis.py       # IOC提取 + RAG + LLM (SSE流式)
│   │   ├── reports.py        # 报告 CRUD
│   │   ├── iocs.py           # IOC 查询/搜索
│   │   ├── threat_groups.py  # 威胁组织目录
│   │   ├── kg.py             # 知识图谱 Mermaid
│   │   └── stats.py          # 仪表盘统计
│   └── services/             # 服务层
│       ├── ioc_extractor.py  # IOC 正则提取
│       ├── parser.py         # pymupdf/bs4 解析
│       ├── llm_client.py     # DeepSeek-v4 流式调用
│       ├── rag_service.py    # SQLite 历史关联
│       └── kg_service.py     # Mermaid 代码生成
├── frontend/                 # React + Vite + TypeScript + Ant Design
│   └── src/pages/            # 8 个页面
│   └── src/api/client.ts     # API 客户端
├── data/                     # 样本威胁报告
└── README.md
```

## 技术栈

| 层 | 技术 |
|---|---|
| 前端 | React 18 + TypeScript + Vite + Ant Design 5 |
| 后端 | Python FastAPI + uvicorn |
| 数据库 | SQLite + SQLAlchemy 2.0 |
| LLM | DeepSeek-v4 (OpenAI 兼容 API) |
| 文档解析 | pymupdf + BeautifulSoup4 |
| 知识图谱 | Mermaid |

## 快速开始

### 前置条件

- Python 3.10+
- Node.js 20+
- DeepSeek API Key (https://platform.deepseek.com)

### 1. 后端

```bash
cd backend

# 配置环境变量
cp .env.example .env
# 编辑 .env，填写 DEEPSEEK_API_KEY=sk-your-key

# 安装依赖
pip install -r requirements.txt

# 启动服务
python main.py
# 或: uvicorn main:app --reload --port 8000
```

### 2. 前端

```bash
cd frontend

npm install
npm run dev  # http://localhost:5173
```

### 3. 使用

1. 打开 http://localhost:5173
2. 上传 PDF/HTML/TXT 威胁报告或粘贴文本
3. 点击"开始分析"，观察 SSE 实时进度
4. 查看 IOC 提取结果、LLM 分析报告、知识图谱

## API 接口

| Method | Path | 说明 |
|--------|------|------|
| GET | /api/health | 健康检查 |
| POST | /api/upload | 文件上传 + 解析 |
| POST | /api/analyze | 流式分析 (SSE) |
| GET | /api/reports | 报告列表 |
| GET | /api/reports/:id | 报告详情 |
| DELETE | /api/reports/:id | 删除报告 |
| GET | /api/iocs | IOC 查询 |
| GET | /api/threat-groups | 威胁组织列表 |
| GET | /api/knowledge-graph | 知识图谱 |
| GET | /api/stats | 仪表盘统计 |

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| DEEPSEEK_API_KEY | DeepSeek API 密钥 | (必填) |
| DEEPSEEK_BASE_URL | API 地址 | https://api.deepseek.com/v1 |
| DATABASE_URL | SQLite 路径 | sqlite:///./threat_intel.db |
| PORT | 服务端口 | 8000 |
| UPLOAD_DIR | 上传目录 | ./uploads |

Key 仅在服务端使用，不会暴露给浏览器。
