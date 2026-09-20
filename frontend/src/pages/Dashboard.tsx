/** 仪表盘 — 统计概览 */

import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Row, Col, Card, Statistic, Table, Tag, Spin, Alert } from "antd";
import {
  BugOutlined, FileTextOutlined, TeamOutlined, ApartmentOutlined,
} from "@ant-design/icons";
import { getStats, DashboardData, ReportItem } from "../api/client";
import StatCharts from "../components/charts/StatCharts";

const statusColors: Record<string, string> = {
  completed: "green", analyzing: "blue", parsing: "orange",
  pending: "default", error: "red",
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { fetchData(); }, []);

  async function fetchData() {
    setLoading(true);
    setError(null);
    try {
      const stats = await getStats();
      setData(stats);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />;
  if (error) return <Alert message="加载失败" description={error} type="error" showIcon
    action={<a onClick={fetchData}>重试</a>} />;

  return (
    <div>
      <div className="page-header"><h2>仪表盘</h2></div>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="IOC 总数" value={data?.totalIOCs || 0}
              prefix={<BugOutlined />} valueStyle={{ color: "#1677ff" }} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="分析报告" value={data?.totalReports || 0}
              prefix={<FileTextOutlined />} valueStyle={{ color: "#52c41a" }} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="威胁组织" value={data?.totalGroups || 0}
              prefix={<TeamOutlined />} valueStyle={{ color: "#fa8c16" }} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="知识图谱边" value={data?.totalKGEdges || 0}
              prefix={<ApartmentOutlined />} valueStyle={{ color: "#722ed1" }} />
          </Card>
        </Col>
      </Row>

      <StatCharts
        iocsByType={data?.iocsByType || {}}
        reportsByMonth={data?.reportsByMonth || []}
      />

      <Card title="最近报告" style={{ marginTop: 24 }}>
        <Table
          dataSource={data?.recentReports || []}
          rowKey="id"
          pagination={false}
          size="middle"
          onRow={(r: ReportItem) => ({ onClick: () => navigate(`/reports/${r.id}`), style: { cursor: "pointer" } })}
          columns={[
            { title: "报告名称", dataIndex: "title", ellipsis: true },
            { title: "状态", dataIndex: "status", width: 100,
              render: (s: string) => <Tag color={statusColors[s] || "default"}>{s}</Tag> },
            { title: "IOC 数量", dataIndex: "iocCount", width: 100 },
            { title: "时间", dataIndex: "createdAt", width: 180,
              render: (t: string) => new Date(t).toLocaleString("zh-CN") },
          ]}
        />
      </Card>
    </div>
  );
}
