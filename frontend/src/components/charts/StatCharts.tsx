/** Dashboard 图表组件 — IOC 分布饼图 + 报告趋势折线图 */

import { Card, Col, Row, Empty } from "antd";
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid,
} from "recharts";

const IOC_TYPE_LABELS: Record<string, string> = {
  ip: "IP 地址", domain: "域名", url: "URL", hash: "文件哈希",
  cve: "CVE 编号", attack_technique: "ATT&CK 技术",
  threat_group: "威胁组织", email: "邮箱",
};

const PIE_COLORS = [
  "#1890ff", "#52c41a", "#13c2c2", "#fa8c16",
  "#f5222d", "#722ed1", "#eb2f96", "#2f54eb",
];

interface Props {
  iocsByType: Record<string, number>;
  reportsByMonth: { month: string; count: number }[];
}

export default function StatCharts({ iocsByType, reportsByMonth }: Props) {
  // ── IOC 类型分布饼图数据 ──
  const pieData = Object.entries(iocsByType)
    .filter(([, count]) => count > 0)
    .map(([type, count]) => ({
      name: IOC_TYPE_LABELS[type] || type,
      value: count,
    }))
    .sort((a, b) => b.value - a.value);

  // ── 报告趋势折线图数据 ──
  const lineData = reportsByMonth.map((item) => ({
    month: item.month,
    报告数: item.count,
  }));

  return (
    <Row gutter={16} style={{ marginTop: 16 }}>
      <Col xs={24} lg={12}>
        <Card title="IOC 类型分布" size="small">
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, value }) => `${name} (${value})`}
                >
                  {pieData.map((_, idx) => (
                    <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <Empty description="暂无 IOC 数据" />
          )}
        </Card>
      </Col>

      <Col xs={24} lg={12}>
        <Card title="分析报告趋势" size="small">
          {lineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={lineData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" fontSize={11} />
                <YAxis allowDecimals={false} fontSize={11} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="报告数"
                  stroke="#1890ff"
                  strokeWidth={2}
                  dot={{ r: 3 }}
                  activeDot={{ r: 5 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <Empty description="暂无报告趋势数据" />
          )}
        </Card>
      </Col>
    </Row>
  );
}
