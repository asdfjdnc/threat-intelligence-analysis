/** 报告列表页 */

import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Table, Tag, Button, Space, Input, Spin, Alert, Popconfirm } from "antd";
import { FileTextOutlined, SearchOutlined, EyeOutlined, DeleteOutlined } from "@ant-design/icons";
import { getReports, deleteReport, ReportItem } from "../api/client";

const statusColors: Record<string, string> = {
  completed: "green", analyzing: "blue", parsing: "orange",
  pending: "default", error: "red",
};

const riskColors: Record<string, string> = {
  critical: "red", high: "orange", medium: "blue", low: "green",
};

export default function ReportList() {
  const navigate = useNavigate();
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { fetchReports(); }, []);

  async function fetchReports() {
    setLoading(true);
    setError(null);
    try {
      const data = await getReports();
      setReports(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(id: number) {
    try {
      await deleteReport(id);
      setReports((prev) => prev.filter((r) => r.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "删除失败");
    }
  }

  const filtered = reports.filter((r) =>
    r.title.toLowerCase().includes(search.toLowerCase())
  );

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />;

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between" }}>
        <h2>报告列表</h2>
        <Button type="primary" icon={<FileTextOutlined />} onClick={() => navigate("/upload")}>
          新建分析
        </Button>
      </div>

      {error && <Alert message={error} type="error" showIcon closable style={{ marginBottom: 16 }} />}

      <Input placeholder="搜索报告..." prefix={<SearchOutlined />}
        style={{ marginBottom: 16, maxWidth: 400 }}
        value={search} onChange={(e) => setSearch(e.target.value)} />

      <Table dataSource={filtered} rowKey="id"
        columns={[
          { title: "报告名称", dataIndex: "title", ellipsis: true },
          { title: "类型", dataIndex: "source", width: 80,
            render: (s: string) => <Tag>{s.toUpperCase()}</Tag> },
          { title: "状态", dataIndex: "status", width: 100,
            render: (s: string) => <Tag color={statusColors[s] || "default"}>{s}</Tag> },
          { title: "风险等级", dataIndex: "overallRiskLevel", width: 100,
            render: (r: string) => r ? <Tag color={riskColors[r] || "default"}>{r}</Tag> : "-" },
          { title: "IOC 数", dataIndex: "iocCount", width: 80 },
          { title: "时间", dataIndex: "createdAt", width: 180,
            render: (t: string) => new Date(t).toLocaleString("zh-CN") },
          { title: "操作", key: "actions", width: 150,
            render: (_: unknown, record: ReportItem) => (
              <Space>
                <Button type="link" icon={<EyeOutlined />} size="small"
                  onClick={() => navigate(`/reports/${record.id}`)}>查看</Button>
                <Popconfirm title="确认删除？" onConfirm={() => handleDelete(record.id)}>
                  <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
                </Popconfirm>
              </Space>
            )},
        ]}
      />
    </div>
  );
}
