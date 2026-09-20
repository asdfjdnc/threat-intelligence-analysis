/** 知识图谱页面 — 交互式全局图谱 */

import { useState, useEffect } from "react";
import { Card, Space, Button, Tag, Spin, Alert } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { getKnowledgeGraph, getReports, getThreatGroups, ReportItem, ThreatGroupItem } from "../api/client";
import KnowledgeGraphVis, { KGNode, KGEdge } from "../components/kg/KnowledgeGraphVis";

export default function KnowledgeGraphPage() {
  const [nodes, setNodes] = useState<KGNode[]>([]);
  const [edges, setEdges] = useState<KGEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState({ reports: 0, groups: 0 });

  useEffect(() => { fetchGraph(); }, []);

  async function fetchGraph() {
    setLoading(true);
    setError(null);
    try {
      const [kgData, reports, groups] = await Promise.all([
        getKnowledgeGraph(),
        getReports(),
        getThreatGroups(),
      ]);

      setStats({ reports: kgData.reportCount || reports.length, groups: kgData.groupCount || groups.length });

      const nodeIds = new Set<string>();
      const graphNodes: KGNode[] = [];
      const graphEdges: KGEdge[] = [];

      // Report nodes
      for (const r of reports.slice(0, 15)) {
        const id = `rep_${r.id}`;
        if (nodeIds.has(id)) continue;
        nodeIds.add(id);
        graphNodes.push({ id, label: r.title || `报告 #${r.id}`, type: "report" });
      }

      // Threat group nodes
      for (const g of groups.slice(0, 10)) {
        const id = `grp_${g.id}`;
        if (nodeIds.has(id)) continue;
        nodeIds.add(id);
        graphNodes.push({ id, label: g.name, type: "group" });
      }

      // Connect groups to reports they're found in (by name matching)
      for (const r of reports.slice(0, 15)) {
        const foundGroups = (r as any).threatGroupsFound || [];
        for (const gName of foundGroups) {
          const gNode = graphNodes.find((n) => n.type === "group" && n.label === gName);
          if (gNode) {
            graphEdges.push({ from: gNode.id, to: `rep_${r.id}`, relation: "found_in" });
          }
        }
      }

      setNodes(graphNodes);
      setEdges(graphEdges);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />;

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between" }}>
        <h2>知识图谱</h2>
        <Space>
          <span style={{ color: "#999", fontSize: 12 }}>
            报告: {stats.reports} | 组织: {stats.groups}
          </span>
          <Button icon={<ReloadOutlined />} onClick={fetchGraph}>刷新</Button>
        </Space>
      </div>

      {error && <Alert message={error} type="error" showIcon closable style={{ marginBottom: 16 }} />}

      <Card>
        <KnowledgeGraphVis
          nodes={nodes}
          edges={edges}
          title="全局威胁情报图谱"
          onGroupClick={async (name) => {
            try {
              const result = await getThreatGroups(name);
              return result.find((g) =>
                g.name.toLowerCase() === name.toLowerCase() ||
                (g.aliases || []).some((a: string) => a.toLowerCase() === name.toLowerCase())
              ) || null;
            } catch { return null; }
          }}
        />
      </Card>
    </div>
  );
}
