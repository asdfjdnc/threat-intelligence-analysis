/** API 客户端 — 与 FastAPI 后端通信 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const isGet = !options?.method || options.method === "GET";
  // GET 请求不设 Content-Type，避免触发不必要的 CORS 预检
  const headers: Record<string, string> = isGet
    ? { ...(options?.headers as Record<string, string> || {}) }
    : { "Content-Type": "application/json", ...(options?.headers as Record<string, string> || {}) };
  const res = await fetch(url, { ...options, headers });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`HTTP ${res.status}: ${body}`);
  }

  return res.json();
}

/** 文件上传 */
export async function uploadFile(file: File): Promise<UploadResult> {
  const form = new FormData();
  form.append("file", file);
  const url = `${BASE_URL}/api/upload`;
  const res = await fetch(url, { method: "POST", body: form });
  if (!res.ok) throw new Error(`上传失败: HTTP ${res.status}`);
  return res.json();
}

/** 提交文本上传 */
export async function uploadText(text: string): Promise<UploadResult> {
  const form = new FormData();
  form.append("text", text);
  const url = `${BASE_URL}/api/upload`;
  const res = await fetch(url, { method: "POST", body: form });
  if (!res.ok) throw new Error(`上传失败: HTTP ${res.status}`);
  return res.json();
}

/** SSE 流式分析 */
export function analyzeStream(
  rawText: string,
  fileName: string,
  fileType: string,
  callbacks: {
    onProgress?: (data: ProgressData) => void;
    onIOCs?: (data: { iocs: IOCItem[]; statistics: Record<string, number>; categories?: Record<string, {label: string; count: number}> }) => void;
    onIOCsEnriched?: (data: { iocs: IOCItem[] }) => void;
    onCorrelations?: (data: { known: number; unknown: number; groups: string[] }) => void;
    onLLMChunk?: (chunk: string) => void;
    onResult?: (data: AnalysisResult) => void;
    onError?: (error: string) => void;
  }
): AbortController {
  const controller = new AbortController();
  const url = `${BASE_URL}/api/analyze`;

  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rawText, fileName, fileType }),
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok) {
        callbacks.onError?.(`HTTP ${res.status}`);
        return;
      }
      const reader = res.body?.getReader();
      if (!reader) { callbacks.onError?.("无法读取响应"); return; }

      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // 解析 SSE 事件（按 \n\n 分隔）
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";

        for (const part of parts) {
          if (!part.trim()) continue;
          const lines = part.split("\n");
          let event = "";
          let data = "";

          for (const line of lines) {
            if (line.startsWith("event: ")) event = line.slice(7);
            else if (line.startsWith("data: ")) data = line.slice(6);
          }

          if (!data) continue;

          try {
            const parsed = JSON.parse(data);
            switch (event) {
              case "progress":
                callbacks.onProgress?.(parsed);
                break;
              case "iocs":
                callbacks.onIOCs?.(parsed);
                break;
              case "iocs_enriched":
                callbacks.onIOCsEnriched?.(parsed);
                break;
              case "correlations":
                callbacks.onCorrelations?.(parsed);
                break;
              case "llm_chunk":
                callbacks.onLLMChunk?.(parsed.content);
                break;
              case "result":
                callbacks.onResult?.(parsed);
                break;
              case "error":
                callbacks.onError?.(parsed.message);
                break;
            }
          } catch (e) {
            console.warn("[SSE] JSON parse error:", e, "data:", data.slice(0, 200));
          }
        }
      }
    })
    .catch((err) => {
      if (err.name !== "AbortError") {
        callbacks.onError?.(err.message);
      }
    });

  return controller;
}

/** 获取报告列表 */
export function getReports() {
  return request<ReportItem[]>("/api/reports");
}

/** 获取报告详情 */
export function getReport(id: number) {
  return request<ReportDetail>(`/api/reports/${id}`);
}

/** 删除报告 */
export function deleteReport(id: number) {
  return request<{ ok: boolean }>(`/api/reports/${id}`, { method: "DELETE" });
}

/** 获取 IOC 列表 */
export function getIOCs(params?: { type?: string; search?: string; limit?: number }) {
  const sp = new URLSearchParams();
  if (params?.type) sp.set("type", params.type);
  if (params?.search) sp.set("search", params.search);
  if (params?.limit) sp.set("limit", String(params.limit));
  const qs = sp.toString();
  return request<{ total: number; items: IOCGlobalItem[] }>(`/api/iocs${qs ? `?${qs}` : ""}`);
}

/** 获取威胁组织列表 */
export function getThreatGroups(search?: string) {
  const qs = search ? `?search=${encodeURIComponent(search)}` : "";
  return request<ThreatGroupItem[]>(`/api/threat-groups${qs}`);
}

/** 获取知识图谱 */
export function getKnowledgeGraph(reportId?: number) {
  const qs = reportId ? `?report_id=${reportId}` : "";
  return request<KnowledgeGraphData>(`/api/knowledge-graph${qs}`);
}

/** 获取统计 */
export function getStats() {
  return request<DashboardData>("/api/stats");
}

/** 统一威胁搜索 */
export function threatSearch(q: string) {
  return request<ThreatSearchResult>(`/api/threat-search?q=${encodeURIComponent(q)}`);
}

/** 获取 IOC 详情（含关联 IOC） */
export function getIOCDetail(id: number) {
  return request<IOCDetailData>(`/api/iocs/${id}`);
}

/** 清空所有分析结果 */
export function clearAllData() {
  return request<{ ok: boolean; rowsDeleted: Record<string, number>; filesDeleted: number; message: string }>(
    "/api/admin/clear-all",
    { method: "DELETE" }
  );
}

/** 健康检查 */
export function healthCheck() {
  return request<{ status: string; version: string }>("/api/health");
}

/** 获取运行配置（模型名、Base URL 等） */
export function getConfig() {
  return request<{
    deepseek_configured: boolean;
    model: { name: string; base_url: string };
  }>("/api/config");
}

// ─── 类型定义 ────────────────────────────────────────

export interface UploadResult {
  fileName: string;
  fileType: string;
  rawText: string;
  charCount: number;
}

export interface ProgressData {
  stage: string;
  message: string;
  percent: number;
}

export interface IOCItem {
  ioc_type: string;
  value: string;
  context: string;
  confidence: number;
  category?: string;
  type_label?: string;
  subtype?: string;
  role?: string;
  risk_level?: string;
  riskLevel?: string;
  description?: string;
}

export interface AnalysisResult {
  reportId: number;
  status: string;
  iocCount: number;
  knownIOCCount: number;
  unknownIOCCount: number;
  threatGroupsFound: string[];
  overallRiskLevel: string;
  mermaid: string;
  analysisParsed: {
    summary: string;
    attackChain: string;
    correlationReasoning: string;
    impactAssessment: string;
    defenseSuggestions: string;
    attributedGroup: string;
    overallRiskLevel: string;
  };
}

export interface ReportItem {
  id: number;
  title: string;
  source: string;
  status: string;
  iocCount: number;
  knownIOCCount?: number;
  unknownIOCCount?: number;
  threatGroupsFound?: string[];
  overallRiskLevel?: string;
  createdAt: string;
}

export interface ReportDetail extends ReportItem {
  fileName: string;
  attributedGroup: string;
  markdownReport: string;
  mermaidCode: string;
  rawText: string;
  updatedAt: string;
  iocs: IOCItem[];
  kgEdges: {
    sourceLabel: string;
    sourceType: string;
    targetLabel: string;
    targetType: string;
    relation: string;
    confidence: number;
  }[];
}

export interface IOCGlobalItem {
  id: number;
  type: string;
  value: string;
  firstSeen: string;
  lastSeen: string;
  occurrenceCount: number;
  associatedGroups: string[];
}

export interface ThreatGroupItem {
  id: number;
  name: string;
  aliases: string[];
  description: string;
  origin: string;
  threatLevel: string;
  firstActive: string;
  targetedSectors: string[];
}

export interface KnowledgeGraphData {
  mermaid: string;
  reportId?: number;
  reportTitle?: string;
  reportCount?: number;
  groupCount?: number;
}

export interface DashboardData {
  totalIOCs: number;
  totalReports: number;
  totalGroups: number;
  totalKGEdges: number;
  iocsByType: Record<string, number>;
  reportsByMonth: { month: string; count: number }[];
  recentReports: ReportItem[];
}

export interface ThreatSearchResult {
  query: string;
  total: number;
  items: {
    id: number;
    type: string;
    value: string;
    firstSeen: string;
    lastSeen: string;
    occurrenceCount: number;
    associatedGroups: string[];
  }[];
}

export interface IOCDetailData {
  id: number;
  reportId: number;
  iocType: string;
  value: string;
  context: string;
  confidence: number;
  isKnown: boolean;
  firstSeen: string;
  lastSeen: string;
  occurrenceCount: number;
  relatedIOCs: {
    id: number;
    reportId: number;
    iocType: string;
    value: string;
    confidence: number;
    isKnown: boolean;
  }[];
}
