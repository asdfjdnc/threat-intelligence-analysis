/** 分类 IOC 分组表格 — UploadPage / ReportDetail 复用 */

import { Table, Tag, Collapse, Typography, Space } from "antd";
import { IOCItem } from "../../api/client";

const { Text } = Typography;

const IOC_COLORS: Record<string, string> = {
  ip: "blue", domain: "green", url: "cyan", hash: "orange",
  cve: "red", attack_technique: "purple", threat_group: "magenta", email: "geekblue",
};

const RISK_COLORS: Record<string, string> = { high: "red", medium: "orange", low: "green" };

const TYPE_TO_CATEGORY: Record<string, string> = {
  ip: "network", domain: "network", url: "network",
  hash: "file",
  cve: "vuln",
  attack_technique: "technique",
  threat_group: "actor",
  email: "identity",
};

const CATEGORY_CONFIG: Record<string, { label: string; icon: string }> = {
  network:   { label: "网络指标",     icon: "🌐" },
  file:      { label: "文件哈希",     icon: "🔑" },
  vuln:      { label: "CVE 编号",     icon: "🪲" },
  technique: { label: "ATT&CK 技术",  icon: "⚔️" },
  actor:     { label: "威胁组织",     icon: "🎯" },
  identity:  { label: "邮箱",         icon: "📧" },
};

const CATEGORY_ORDER = ["network", "file", "vuln", "technique", "actor", "identity"];

interface Props {
  iocs: IOCItem[];
  enriched?: boolean;
}

export default function IOCGroupTable({ iocs, enriched }: Props) {
  const grouped: Record<string, IOCItem[]> = {};
  for (const ioc of iocs) {
    const cat = ioc.category || TYPE_TO_CATEGORY[ioc.ioc_type] || "other";
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(ioc);
  }

  const hasEnriched = enriched ?? iocs.some((i: IOCItem) => i.role || i.risk_level);

  return (
    <Collapse
      defaultActiveKey={CATEGORY_ORDER.filter((c) => grouped[c]?.length)}
      size="small"
      items={CATEGORY_ORDER
        .filter((cat) => grouped[cat]?.length)
        .map((cat) => {
          const config = CATEGORY_CONFIG[cat] || { label: cat, icon: "📌" };
          const items = grouped[cat];
          return {
            key: cat,
            label: (
              <span>{config.icon} {config.label} <Tag>{items.length}</Tag></span>
            ),
            children: (
              <Table
                dataSource={items.map((ioc, idx) => ({ ...ioc, key: idx }))}
                size="small"
                pagination={false}
                columns={[
                  {
                    title: "类型", dataIndex: "ioc_type", width: 110,
                    render: (t: string) => <Tag color={IOC_COLORS[t] || "default"}>{t}</Tag>,
                  },
                  {
                    title: "值", dataIndex: "value", ellipsis: true,
                    render: (v: string) => <code style={{ fontSize: 12 }}>{v}</code>,
                  },
                  ...(hasEnriched
                    ? [
                        {
                          title: "角色", dataIndex: "role", width: 140, ellipsis: true,
                          render: (r: string) => r ? <Text style={{ fontSize: 12 }}>{r}</Text> : "-",
                        } as any,
                        {
                          title: "风险", dataIndex: "risk_level", width: 70,
                          render: (r: string) =>
                            r ? <Tag color={RISK_COLORS[r] || "default"} style={{ fontSize: 11 }}>{r}</Tag> : "-",
                        } as any,
                      ]
                    : []),
                  {
                    title: "置信度", dataIndex: "confidence", width: 70,
                    render: (c: number) => `${(c * 100).toFixed(0)}%`,
                  },
                  {
                    title: "上下文", dataIndex: "context", width: 200, ellipsis: true,
                  },
                ]}
              />
            ),
          };
        })}
    />
  );
}
