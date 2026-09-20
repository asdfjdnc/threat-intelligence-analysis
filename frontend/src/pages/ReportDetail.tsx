/** 报告详情页 — 分类 IOC + Markdown 报告 + 知识图谱 */

import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card, Tabs, Tag, Button, Spin, Alert, Space } from "antd";
import { ArrowLeftOutlined } from "@ant-design/icons";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { getReport, getThreatGroups, ReportDetail as ReportDetailType, ThreatGroupItem } from "../api/client";
import IOCGroupTable from "../components/report/IOCGroupTable";
import KnowledgeGraphVis, { KGNode, KGEdge } from "../components/kg/KnowledgeGraphVis";

const IOC_COLORS: Record<string, string> = {
  ip: "blue", domain: "green", url: "cyan", hash: "orange",
  cve: "red", attack_technique: "purple", threat_group: "magenta", email: "geekblue",
};

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<ReportDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { if (id) fetchDetail(); }, [id]);

  async function fetchDetail() {
    setLoading(true);
    setError(null);
    try {
      const detail = await getReport(Number(id));
      setData(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />;
  if (error) return <Alert message="加载失败" description={error} type="error" showIcon />;
  if (!data) return <Alert message="报告不存在" type="warning" showIcon />;

  const riskColors: Record<string, string> = { critical: "red", high: "orange", medium: "blue", low: "green" };

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between" }}>
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/reports")}>返回</Button>
          <h2>{data.title}</h2>
        </Space>
        <Space>
          {data.overallRiskLevel && (
            <Tag color={riskColors[data.overallRiskLevel] || "default"}>
              风险: {data.overallRiskLevel}
            </Tag>
          )}
          <Tag color="green">✅ 分析完成</Tag>
        </Space>
      </div>

      <Tabs defaultActiveKey="iocs" items={[
        {
          key: "iocs", label: `IOC (${data.iocs?.length || 0})`,
          children: <IOCGroupTable iocs={data.iocs || []} />,
        },
        {
          key: "report", label: "分析报告",
          children: (
            <Card>
              <div className="markdown-body" style={{ maxWidth: 900 }}>
                {data.markdownReport ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{data.markdownReport}</ReactMarkdown>
                ) : (
                  <Alert message="暂无分析报告" type="info" showIcon />
                )}
              </div>
            </Card>
          ),
        },
        {
          key: "kg", label: "知识图谱",
          children: (() => {
            const graphNodes: KGNode[] = [];
            const graphEdges: KGEdge[] = [];
            const nodeIds = new Set<string>();

            const addNode = (id: string, label: string, type: string, iocType?: string) => {
              if (!nodeIds.has(id)) { nodeIds.add(id); graphNodes.push({ id, label, type, iocType }); }
            };

            // Report
            const rid = `r_${data.id}`;
            addNode(rid, data.title || "报告", "report");

            // All IOCs — report contains them
            const iocList = data.iocs || [];
            const iocIds: string[] = [];
            const infraIocIds: string[] = []; // IP/domain/url/hash = infrastructure
            for (let i = 0; i < iocList.length; i++) {
              const ioc = iocList[i];
              const nid = `i_${data.id}_${i}`;
              const ntype = ioc.ioc_type === "attack_technique" ? "technique"
                : ioc.ioc_type === "cve" ? "cve" : "ioc";
              addNode(nid, ioc.value, ntype, ioc.ioc_type);
              iocIds.push(nid);
              if (["ip", "domain", "url", "hash"].includes(ioc.ioc_type)) {
                infraIocIds.push(nid);
              }
              // Report contains IOC (light structural edge)
              graphEdges.push({ from: rid, to: nid, relation: "contains" });
            }

            // Groups: from threatGroupsFound + threat_group type IOCs
            const groupNames = new Set(data.threatGroupsFound || []);
            for (const ioc of iocList) {
              if (ioc.ioc_type === "threat_group") groupNames.add(ioc.value);
            }
            const groupIds: string[] = [];
            for (const gName of groupNames) {
              const gid = `g_${data.id}_${gName.replace(/[^a-zA-Z0-9_]/g, "_")}`;
              addNode(gid, gName, "group");
              groupIds.push(gid);
              // Group → Report (key attribution edge)
              graphEdges.push({ from: gid, to: rid, relation: "attributed_to" });
              // Group → 3 infra IOCs (only connect to IP/domain/url/hash, not TTPs)
              for (let j = 0; j < Math.min(3, infraIocIds.length); j++) {
                graphEdges.push({ from: gid, to: infraIocIds[j], relation: "uses" });
              }
            }

            // DB edges: deduplicated, only meaningful relations
            const dbEdgeSeen = new Set<string>();
            for (const e of (data.kgEdges || [])) {
              const s = `x_${e.sourceType}_${e.sourceLabel}`.replace(/[^a-zA-Z0-9_]/g, "_");
              const t = `x_${e.targetType}_${e.targetLabel}`.replace(/[^a-zA-Z0-9_]/g, "_");
              const ek = `${s}|${t}`;
              if (dbEdgeSeen.has(ek)) continue;
              dbEdgeSeen.add(ek);
              addNode(s, e.sourceLabel, e.sourceType === "threat_group" ? "group" : "ioc");
              addNode(t, e.targetLabel, e.targetType === "threat_group" ? "group" : "ioc");
              graphEdges.push({ from: s, to: t, relation: e.relation });
            }

            // Group click → fetch threat group details
            const handleGroupClick = async (name: string): Promise<ThreatGroupItem | null> => {
              try {
                const result = await getThreatGroups(name);
                const found = result.find((g) =>
                  g.name.toLowerCase() === name.toLowerCase() ||
                  (g.aliases || []).some((a: string) => a.toLowerCase() === name.toLowerCase())
                );
                return found || null;
              } catch {
                return null;
              }
            };

            return (
              <KnowledgeGraphVis
                nodes={graphNodes}
                edges={graphEdges}
                title={data.title}
                onGroupClick={handleGroupClick}
              />
            );
          })(),
        },
        ...(data.threatGroupsFound?.length ? [{
          key: "groups", label: "威胁组织",
          children: (
            <Card>
              <Space wrap>
                {data.threatGroupsFound.map((g: string) => (
                  <Tag key={g} color="magenta" style={{ fontSize: 14, padding: "4px 12px" }}>{g}</Tag>
                ))}
              </Space>
            </Card>
          ),
        }] : []),
      ]} />
    </div>
  );
}
