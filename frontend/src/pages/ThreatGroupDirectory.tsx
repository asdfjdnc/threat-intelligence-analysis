/** 威胁组织目录 */

import { useState, useEffect } from "react";
import { Row, Col, Card, Tag, Modal, Descriptions, Input, Spin, Alert } from "antd";
import { SearchOutlined, TeamOutlined } from "@ant-design/icons";
import { getThreatGroups, ThreatGroupItem } from "../api/client";

const levelColors: Record<string, string> = { high: "red", medium: "orange", low: "green" };

export default function ThreatGroupDirectory() {
  const [search, setSearch] = useState("");
  const [groups, setGroups] = useState<ThreatGroupItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ThreatGroupItem | null>(null);

  useEffect(() => { fetchGroups(); }, []);

  async function fetchGroups() {
    setLoading(true);
    setError(null);
    try {
      const data = await getThreatGroups();
      setGroups(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  const filtered = groups.filter((g) =>
    g.name.toLowerCase().includes(search.toLowerCase()) ||
    g.aliases.some((a) => a.toLowerCase().includes(search.toLowerCase()))
  );

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />;
  if (error) return <Alert message="加载失败" description={error} type="error" showIcon />;

  return (
    <div>
      <div className="page-header"><h2>威胁组织</h2></div>

      <Input placeholder="搜索组织名称或别名..." prefix={<SearchOutlined />}
        style={{ marginBottom: 16, maxWidth: 400 }}
        value={search} onChange={(e) => setSearch(e.target.value)} />

      <Row gutter={[16, 16]}>
        {filtered.map((group) => (
          <Col xs={24} sm={12} lg={8} xl={6} key={group.id}>
            <Card hoverable onClick={() => setSelected(group)}>
              <Card.Meta
                avatar={<TeamOutlined style={{ fontSize: 32, color: "#1677ff" }} />}
                title={group.name}
                description={
                  <>
                    <Tag color={levelColors[group.threatLevel]}>
                      {group.threatLevel === "high" ? "🔴 高" : group.threatLevel === "medium" ? "🟡 中" : "🟢 低"}
                    </Tag>
                    <Tag>{group.origin}</Tag>
                    <div style={{ marginTop: 8, fontSize: 12, color: "#666" }}>
                      别名: {group.aliases.slice(0, 3).join(", ")}
                      {group.aliases.length > 3 ? ` +${group.aliases.length - 3}` : ""}
                    </div>
                  </>
                }
              />
            </Card>
          </Col>
        ))}
      </Row>

      <Modal title={selected?.name} open={!!selected} onCancel={() => setSelected(null)}
        footer={null} width={600}>
        {selected && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="名称">{selected.name}</Descriptions.Item>
            <Descriptions.Item label="别名">
              {selected.aliases.map((a) => <Tag key={a}>{a}</Tag>)}
            </Descriptions.Item>
            <Descriptions.Item label="来源">{selected.origin}</Descriptions.Item>
            <Descriptions.Item label="威胁等级">
              <Tag color={levelColors[selected.threatLevel]}>
                {selected.threatLevel === "high" ? "高" : selected.threatLevel === "medium" ? "中" : "低"}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="首次活跃">{selected.firstActive}</Descriptions.Item>
            <Descriptions.Item label="目标行业">{selected.targetedSectors.join(", ")}</Descriptions.Item>
            <Descriptions.Item label="描述">{selected.description}</Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
}
