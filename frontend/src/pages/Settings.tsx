/** 设置页面 — 本地环境状态和 API 配置 */

import { useState, useEffect } from "react";
import { Card, Descriptions, Tag, Alert, Space, Button, Typography, Spin, Modal, message } from "antd";
import {
  CheckCircleOutlined, WarningOutlined, CopyOutlined, ReloadOutlined,
  DeleteOutlined, ExclamationCircleOutlined,
} from "@ant-design/icons";
import { healthCheck, getConfig, clearAllData } from "../api/client";

const { Text } = Typography;

export default function Settings() {
  const [status, setStatus] = useState<{
    ok: boolean; deepseek: boolean; version: string;
    modelName: string; baseUrl: string;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);

  useEffect(() => { checkHealth(); }, []);

  async function checkHealth() {
    setLoading(true);
    try {
      const [health, config] = await Promise.all([healthCheck(), getConfig()]);
      console.log("[Settings] health:", health, "config:", config);
      setStatus({
        ok: health.status === "ok",
        deepseek: Boolean(config.deepseek_configured),
        version: String(health.version || "2.0.0"),
        modelName: String(config.model?.name || "unknown"),
        baseUrl: String(config.model?.base_url || "unknown"),
      });
    } catch (err) {
      console.error("[Settings] checkHealth failed:", err);
      setStatus({ ok: false, deepseek: false, version: "?", modelName: "?", baseUrl: "?" });
    } finally {
      setLoading(false);
    }
  }

  function handleClearAll() {
    Modal.confirm({
      title: "确认清空所有数据？",
      icon: <ExclamationCircleOutlined />,
      content: (
        <div>
          <p>此操作将<strong>永久删除</strong>以下数据：</p>
          <ul>
            <li>所有分析报告</li>
            <li>所有提取的 IOC 记录</li>
            <li>知识图谱边数据</li>
            <li>全局 IOC 视图</li>
            <li>上传的文件</li>
          </ul>
          <p style={{ color: "#ff4d4f" }}>威胁组织目录将被保留。此操作不可恢复！</p>
        </div>
      ),
      okText: "确认清空",
      okType: "danger",
      cancelText: "取消",
      width: 500,
      onOk: async () => {
        setClearing(true);
        try {
          const result = await clearAllData();
          if (result.ok) {
            message.success(result.message || "数据已清空");
          } else {
            message.error(result.message || "清空失败");
          }
        } catch (err) {
          message.error(err instanceof Error ? err.message : "清空请求失败");
        } finally {
          setClearing(false);
        }
      },
    });
  }

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />;

  return (
    <div>
      <div className="page-header"><h2>系统设置</h2></div>

      <Space direction="vertical" style={{ width: "100%" }} size={16}>
        <Card title="服务状态" extra={<Button icon={<ReloadOutlined />} size="small" onClick={checkHealth}>刷新</Button>}>
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="后端 API">
              {status?.ok
                ? <Tag icon={<CheckCircleOutlined />} color="green">运行中</Tag>
                : <Tag icon={<WarningOutlined />} color="red">未连接</Tag>}
            </Descriptions.Item>
            <Descriptions.Item label="DeepSeek-v4 API">
              {status?.deepseek
                ? <Tag icon={<CheckCircleOutlined />} color="green">已配置</Tag>
                : <Tag icon={<WarningOutlined />} color="orange">未配置 API Key</Tag>}
            </Descriptions.Item>
            <Descriptions.Item label="版本">
              <Text code>v{status?.version || "?"}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="API 地址">
              <Space>
                <Text code>{import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"}</Text>
                <Button size="small" icon={<CopyOutlined />} type="link"
                  onClick={() => navigator.clipboard.writeText(import.meta.env.VITE_API_BASE_URL || "http://localhost:8000")}>
                  复制
                </Button>
              </Space>
            </Descriptions.Item>
          </Descriptions>
        </Card>

        <Card title="DeepSeek API 配置">
          <Alert
            message={status?.deepseek ? "✅ DeepSeek API Key 已配置" : "⚠️ 未配置 API Key"}
            type={status?.deepseek ? "success" : "warning"}
            showIcon
            style={{ marginBottom: 16 }}
          />
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="调用方式">直接 API（服务端调用）</Descriptions.Item>
            <Descriptions.Item label="模型">
              <Text code>{status?.modelName || "..."}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Base URL">
              <Text code>{status?.baseUrl || "..."}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="API Key">
              <Text code>****（配置在 backend/.env 中）</Text>
            </Descriptions.Item>
          </Descriptions>

          <Alert
            message="如何配置"
            type="info"
            showIcon
            style={{ marginTop: 16 }}
            description={
              <div>
                <p>1. 在 <Text code>backend/</Text> 目录下复制 <Text code>.env.example</Text> 为 <Text code>.env</Text></p>
                <p>2. 填写 <Text code>DEEPSEEK_API_KEY=sk-your-key</Text></p>
                <p>3. 重启后端服务</p>
                <p>Key 仅在服务端使用，不会暴露给浏览器。</p>
              </div>
            }
          />
        </Card>

        <Card title="数据库">
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="数据库类型">SQLite</Descriptions.Item>
            <Descriptions.Item label="存储位置">
              <Text code>backend/threat_intel.db</Text>
            </Descriptions.Item>
            <Descriptions.Item label="ORM">SQLAlchemy 2.0</Descriptions.Item>
          </Descriptions>
        </Card>

        {/* 数据管理 */}
        <Card title="数据管理">
          <Alert
            message="危险操作区域"
            description="以下操作将永久删除数据，请谨慎操作。威胁组织目录数据将被保留。"
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
          />
          <Button
            danger
            type="primary"
            icon={<DeleteOutlined />}
            loading={clearing}
            onClick={handleClearAll}
          >
            清空所有分析结果
          </Button>
        </Card>
      </Space>
    </div>
  );
}
