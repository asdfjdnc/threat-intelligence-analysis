/** IOC 详情抽屉面板 */

import { Drawer, Descriptions, Tag, Table, Progress, Space, Typography } from "antd";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getIOCDetail, IOCDetailData } from "../../api/client";

const { Text } = Typography;

const IOC_COLORS: Record<string, string> = {
  ip: "blue", domain: "green", url: "cyan", hash: "orange",
  cve: "red", attack_technique: "purple", threat_group: "magenta", email: "geekblue",
};

interface Props {
  iocId: number | null;
  open: boolean;
  onClose: () => void;
}

export default function IOCDetailPanel({ iocId, open, onClose }: Props) {
  const navigate = useNavigate();
  const [data, setData] = useState<IOCDetailData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (iocId != null && open) {
      setLoading(true);
      setError("");
      getIOCDetail(iocId)
        .then(setData)
        .catch((e) => setError(e.message))
        .finally(() => setLoading(false));
    }
  }, [iocId, open]);

  if (!iocId) return null;

  return (
    <Drawer
      title="IOC 详情"
      open={open}
      onClose={onClose}
      width={520}
      loading={loading}
    >
      {error && <Text type="danger">{error}</Text>}

      {data && (
        <>
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="类型">
              <Tag color={IOC_COLORS[data.iocType] || "default"}>{data.iocType}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="值">
              <code style={{ fontSize: 13, wordBreak: "break-all" }}>{data.value}</code>
            </Descriptions.Item>
            <Descriptions.Item label="置信度">
              <Progress
                percent={Math.round(data.confidence * 100)}
                size="small"
                status={data.confidence >= 0.8 ? "success" : data.confidence >= 0.5 ? "active" : "exception"}
              />
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={data.isKnown ? "green" : "orange"}>
                {data.isKnown ? "已知威胁" : "新发现"}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="首次出现">{data.firstSeen || "-"}</Descriptions.Item>
            <Descriptions.Item label="最近出现">{data.lastSeen || "-"}</Descriptions.Item>
            <Descriptions.Item label="出现次数">{data.occurrenceCount}</Descriptions.Item>
            {data.context && (
              <Descriptions.Item label="上下文">
                <Text style={{ fontSize: 12 }}>{data.context}</Text>
              </Descriptions.Item>
            )}
          </Descriptions>

          {data.relatedIOCs && data.relatedIOCs.length > 0 && (
            <div style={{ marginTop: 24 }}>
              <Text strong style={{ marginBottom: 8, display: "block" }}>
                关联 IOC ({data.relatedIOCs.length})
              </Text>
              <Table
                dataSource={data.relatedIOCs.map((r, idx) => ({ ...r, key: idx }))}
                size="small"
                pagination={false}
                scroll={{ y: 300 }}
                onRow={(record) => ({
                  onClick: () => {
                    onClose();
                    navigate(`/reports/${record.reportId}`);
                  },
                  style: { cursor: "pointer" },
                })}
                columns={[
                  {
                    title: "类型", dataIndex: "iocType", width: 100,
                    render: (t: string) => (
                      <Tag color={IOC_COLORS[t] || "default"} style={{ fontSize: 11 }}>{t}</Tag>
                    ),
                  },
                  {
                    title: "值", dataIndex: "value", ellipsis: true,
                    render: (v: string) => <code style={{ fontSize: 11 }}>{v}</code>,
                  },
                  {
                    title: "置信度", dataIndex: "confidence", width: 70,
                    render: (c: number) => `${Math.round(c * 100)}%`,
                  },
                ]}
              />
            </div>
          )}
        </>
      )}
    </Drawer>
  );
}
