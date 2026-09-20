# 威胁情报自动化提取与分析平台

## 项目概述

仿绿盟威胁情报中心 (NSFOCUS NTI) 架构的全栈威胁情报平台。从安全报告/APT分析文章中自动提取 IOC（失陷指标），利用 DeepSeek 大模型进行深度分析，以可视化方式呈现威胁全貌。

- **开发周期**：2025年3月-6月，独立完成
- **代码规模**：后端 ~1500行 Python，前端 ~2000行 TypeScript/TSX
- **测试数据**：4份真实APT报告，127个IOC，提取准确率 >99%

## 技术栈

| 层次 | 技术 | 说明 |
|------|------|------|
| 前端 | React 18 + TypeScript + Vite | SPA |
| UI | Ant Design 5 | 企业级组件 |
| 图表 | Recharts + 纯SVG | Dashboard图表 + 交互式知识图谱 |
| 后端 | Python FastAPI + Uvicorn | 异步高性能，端口8000 |
| ORM | SQLAlchemy 2.0 | 声明式模型 |
| 数据库 | SQLite | 单文件，零配置 |
| AI | DeepSeek API (OpenAI兼容) | httpx异步调用，SSE流式 |
| 包管理 | pip (后端) / npm (前端) | — |

## 项目结构

```
E:\agent\
├── CLAUDE.md              # 本文件
├── README.md              # 项目说明
├── start.bat / start.sh   # 一键启动脚本
├── backend/
│   ├── main.py            # FastAPI入口，CORS配置
│   ├── database.py        # SQLAlchemy引擎+Session工厂
│   ├── models.py          # 5个ORM模型
│   ├── routers/
│   │   ├── analysis.py    # POST /api/analyze (SSE流式核心)
│   │   ├── reports.py     # CRUD /api/reports
│   │   ├── iocs.py        # IOC详情+全局搜索
│   │   ├── stats.py       # Dashboard统计
│   │   └── threat_groups.py
│   └── services/
│       ├── ioc_extractor.py  # IOC提取引擎（~500行）
│       ├── llm_client.py     # DeepSeek API客户端
│       ├── rag_service.py    # RAG关联+全局IOC
│       └── kg_service.py     # Mermaid知识图谱生成
├── frontend/
│   ├── vite.config.ts     # 代理 :9000→:8000
│   └── src/
│       ├── api/client.ts  # API类型+请求函数
│       ├── pages/
│       │   ├── Dashboard.tsx            # 仪表盘+统计图表
│       │   ├── ReportList.tsx           # 报告列表
│       │   ├── ReportDetail.tsx         # 报告详情(3Tab)
│       │   ├── UploadPage.tsx           # 文件上传+结果
│       │   ├── IOCBrowser.tsx           # IOC浏览器(9标签页)
│       │   └── KnowledgeGraphPage.tsx   # 全局知识图谱
│       └── components/
│           ├── charts/StatCharts.tsx        # Recharts图表
│           ├── kg/KnowledgeGraphVis.tsx     # SVG知识图谱
│           ├── common/IOCDetailPanel.tsx    # IOC详情抽屉
│           └── report/IOCGroupTable.tsx     # 分类IOC表格
└── data/                   # 测试用APT报告
```

## 启动方式

```bash
# 后端 (终端1)
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# 前端 (终端2)
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173

# 或一键启动
./start.sh   # Git Bash
start.bat    # Windows CMD
```

## 数据库模型（5张表）

| 表 | 关键字段 | 说明 |
|----|---------|------|
| `reports` | id, title, markdown_report, threat_groups_found(JSON), created_at | 报告元数据 |
| `iocs` | id, report_id(FK→reports, CASCADE), ioc_type, value, confidence, context | IOC指标 |
| `threat_groups` | id, name(unique), aliases(JSON), threat_level, origin | 威胁组织 |
| `kg_edges` | id, report_id(FK), source_label/type, target_label/type, relation | 图谱边 |
| `ioc_global` | id, ioc_type, value, occurrence_count, associated_groups(JSON) | IOC全局聚合 |

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/analyze` | 分析文本（SSE流式，6阶段） |
| GET | `/api/reports` | 报告列表 |
| GET | `/api/reports/{id}` | 报告详情（含IOC和KG边） |
| DELETE | `/api/reports/{id}` | 删除报告 |
| GET | `/api/stats` | Dashboard统计（含iocsByType/reportsByMonth） |
| GET | `/api/iocs/{id}` | IOC详情+关联IOC |
| GET | `/api/threat-search?q=` | 跨类型IOC模糊搜索 |
| GET | `/api/threat-groups` | 威胁组织查询 |

## SSE 分析管道（6阶段）

```
提取(extracting, 20-35%) → 分类(enriching, 42-48%) → 关联(rag, 50-60%)
→ 分析(analyzing, 65-85%) → 图谱(kg, 90%) → 存储(saving, 95-100%)
```

每阶段独立 try/except 容错，单阶段失败不影响后续。LLM 阶段逐 token 流式推送到前端。

## IOC提取引擎

### 支持的8种IOC类型

ip, domain, url, hash, cve, attack_technique, threat_group, email

分为6类：network(ip/domain/url), file(hash), vuln(cve), technique(attack_technique), actor(threat_group), identity(email)

### 三重策略
1. **正则匹配**（占90%）：8个专用提取器，每个独立 try/except
2. **关键词上下文**（占5%）：威胁组织/ATT&CK技术需要上下文关键词验证
3. **LLM后验证**（占5%）：enrich_iocs 修正类型分类错误

### 文本预处理（在提取前执行）
- `[.]` → `.`
- `hxxp://`/`hxxps://` → `http://`/`https://`
- `[at]`/`[@]` → `@`
- `\n[.]` 模式修复（PDF换行切割）：`194.87.189\n[.]171` → `194.87.189.171`
- `IP.TLD` 表格拼接修复：在IP后的 `.` 前插入空格

## ⚠️ 重要约定（不要重复踩坑）

### 域名过滤规则（6层）
1. 每段 ≥2 字符
2. 总长 ≥6 字符
3. 80+文件扩展名黑名单（exe/dll/pdf/doc/zip/png/jpg等不作为TLD）
4. 短子域名(<10字符)需要威胁关键词：c2/phish/beacon/malware/backdoor等30+词
5. 恶意软件检测名前缀过滤：Win64/Trojan/JS/Exploit/HEUR模式
6. **`.com` 绝对不在黑名单中！** 它是全球最常见TLD，不是DOS .com可执行文件

### Mermaid v11 兼容规则
- 使用 `flowchart TB` 而非 `graph TB`
- 类分配用独立的 `class nodeId className` 指令，**禁止** `:::className` 语法（v11废弃）
- `_safe_label()` 必须转义：`"`→`'`, `#`→`&num;`, 截断到35字符
- 标签中**禁止 emoji**（v11渲染报错）
- 修改 kg_service.py 后**必须清除 `__pycache__`**（Python字节码缓存不会自动更新）

### 时间处理
- **全部使用 `datetime.now`**，禁止 `datetime.utcnow`（中国时区UTC+8差8小时）
- 涉及位置：models.py 中所有 Column 的 default 参数

### 威胁组织显示
- `threat_groups_found` 必须合并两个来源：
  1. RAG历史关联的 `relatedGroups`
  2. 当前报告IOC中 `ioc_type == 'threat_group'` 的 `value` 字段

### 知识图谱（SVG）
- 首次打开空白：使用 `useLayoutEffect` + `requestAnimationFrame` + `ready` 状态
- 不使用 vis-network（npm安装不稳定）
- 不使用 Mermaid 渲染（v11兼容性问题太多）
- `contains` 边做浅色背景线（opacity 0.15, stroke 0.5px）
- `uses` 边仅连接基础设施IOC（IP/domain/url/hash），每个组织最多3条

### 前端类型声明
- `Record<string, string>` 类型必须显式声明（如 IOC_COLORS, PIE_COLORS）
- API 返回类型在 `client.ts` 中统一定义，禁止在各页面重复声明
- **禁止 `any` 类型**

### 编辑前端文件后
```bash
cd frontend && npx tsc --noEmit  # 检查TypeScript编译
npm run build                      # 确保能构建成功
```

### 编辑后端文件后
```bash
cd backend && python -c "from main import app; print('OK')"  # 检查导入
# 如果修改了 services/ 下的文件：
find backend -name "__pycache__" -type d -exec rm -rf {} +
```

## 历史Bug修复记录

| # | 症状 | 根因 | 修复 |
|---|------|------|------|
| 1 | Mermaid始终报 "Syntax error v11.15.0" | `:::` 语法v11废弃 + pyc缓存 | 改为独立class指令，清除__pycache__ |
| 2 | .com域名全部被过滤 | `com` 在 NON_TLD_EXTENSIONS 黑名单中 | 从黑名单移除 |
| 3 | waterforvoiceless.org 被误过滤 | 短子域名无威胁词时被丢弃 | 仅对<10字符子域名要求威胁词 |
| 4 | 威胁组织在KG中不显示 | threat_groups_found 仅从RAG获取 | 合并当前报告IOC中的threat_group值 |
| 5 | 报告时间差8小时 | datetime.utcnow | 全改为 datetime.now |
| 6 | 知识图谱首次打开空白 | useEffect在DOM就绪前执行 | useLayoutEffect + requestAnimationFrame |
| 7 | vis-network安装后不可用 | npm包未正确落地node_modules | 改用纯SVG实现 |
| 8 | PDF提取IOC不完整 | 换行符切割 + 表格拼接 | 添加文本预处理修复 |
| 9 | SSE JSON序列化异常 | 用户数据含不可序列化对象 | json.dumps(default=str) |
| 10 | 域名 s.sv/x.gq/v.vz 频繁误提取 | 无段长和总长限制 | 6层过滤规则 |
| 11 | TypeScript PALETTE 编译错误 | 动态key类型未声明 | 添加 Record<string, {...}> |
| 12 | Edit工具多次操作无效 | 未确认文件已修改 | 改用Write重写整个文件 |
