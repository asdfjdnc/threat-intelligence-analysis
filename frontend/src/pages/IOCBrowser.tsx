/** IOC 浏览器 — 标签页 + 搜索 + 详情抽屉 */

import { useState, useEffect, useMemo } from "react";
import { Table, Tag, Input, Tabs, Card, Spin, Alert, Space } from "antd";
import { SearchOutlined } from "@ant-design/icons";
import { getIOCs, threatSearch, IOCGlobalItem, ThreatSearchResult } from "../api/client";
import IOCDetailPanel from "../components/common/IOCDetailPanel";

const IOC_COLORS: Record<string, string> = {
  ip: "blue", domain: "green", url: "cyan", hash: "orange",
  cve: "red", attack_technique: "purple", threat_group: "magenta", email: "geekblue",
};

const TAB_KEYS = [
  "all", "ip", "domain", "url", "hash",
  "cve", "attack_technique", "threat_group", "email",
] as const;

const TAB_LABELS: Record<string, string> = {
  all: "全部", ip: "IP", domain: "域名", url: "URL",
  hash: "Hash", cve: "CVE", attack_technique: "ATT&CK", threat_group: "威胁组织", email: "邮箱",
};

type TabKey = (typeof TAB_KEYS)[number];

export default function IOCBrowser() {
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState<TabKey>("all");
  const [items, setItems] = useState<IOCGlobalItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [detailIocId, setDetailIocId] = useState<number | null>(null);

  useEffect(() => { fetchData(); }, []);

  async function fetchData() {
    setLoading(true);
    setError(null);
    try {
      const data = await getIOCs({ limit: 500 });
      setItems(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  // ── 搜索处理：输入后触发远程搜索（防抖） ──
  const [searchResult, setSearchResult] = useState<ThreatSearchResult | null>(null);
  const [searching, setSearching] = useState(false);

  const handleSearch = async (value: string) => {
    setSearch(value);
    if (!value.trim()) {
      setSearchResult(null);
      return;
    }
    setSearching(true);
    try {
      const result = await threatSearch(value.trim());
      setSearchResult(result);
    } catch {
      // fallback to local filter
      setSearchResult(null);
    } finally {
      setSearching(false);
    }
  };

  // ── 当前显示的数据 ──
  const displayItems = useMemo(() => {
    // 如果有远程搜索结果，优先使用
    const source = searchResult ? searchResult.items : items;

    return source.filter((ioc) => {
      // 标签页筛选
      if (activeTab !== "all" && ioc.type !== activeTab) return false;
      // 本地关键词回退（远程搜索未触发时）
      if (!searchResult && search) {
        return ioc.value.toLowerCase().includes(search.toLowerCase());
      }
      return true;
    });
  }, [items, searchResult, search, activeTab]);

  // ── 各标签页计数 ──
  const tabCounts = useMemo(() => {
    const source = searchResult ? searchResult.items : items;
    const counts: Record<string, number> = { all: source.length };
    for (const ioc of source) {
      counts[ioc.type] = (counts[ioc.type] || 0) + 1;
    }
    return counts;
  }, [items, searchResult]);

  if (loading) return <Spin size="large" style={{ display: "block", margin: "100px auto" }} />;
  if (error) return <Alert message="加载失败" description={error} type="error" showIcon />;

  return (
    <div>
      <div className="page-header"><h2>IOC 浏览器</h2></div>

      <Card>
        {/* 搜索框 */}
        <Input.Search
          placeholder="搜索 IP / 域名 / Hash / CVE / URL ..."
          prefix={<SearchOutlined />}
          allowClear
          enterButton="搜索"
          size="large"
          style={{ marginBottom: 16 }}
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            if (!e.target.value) setSearchResult(null);
          }}
          onSearch={handleSearch}
          loading={searching}
        />

        {/* 标签页 */}
        <Tabs
          activeKey={activeTab}
          onChange={(key) => setActiveTab(key as TabKey)}
          size="small"
          items={TAB_KEYS.map((key) => ({
            key,
            label: (
              <span>
                {TAB_LABELS[key]}
                {tabCounts[key] != null && (
                  <Tag style={{ marginLeft: 4, fontSize: 10 }}>{tabCounts[key]}</Tag>
                )}
              </span>
            ),
          }))}
        />

        {/* 表格 */}
        <Table
          dataSource={displayItems}
          rowKey="id"
          size="middle"
          pagination={{ pageSize: 30, showSizeChanger: true, showTotal: (t) => `共 ${t} 条` }}
          onRow={(record) => ({
            onClick: () => setDetailIocId(record.id),
            style: { cursor: "pointer" },
          })}
          columns={[
            {
              title: "类型", dataIndex: "type", width: 120,
              render: (t: string) => <Tag color={IOC_COLORS[t] || "default"}>{t}</Tag>,
            },
            {
              title: "值", dataIndex: "value", ellipsis: true,
              render: (v: string) => <code style={{ fontSize: 12 }}>{v}</code>,
            },
            {
              title: "出现次数", dataIndex: "occurrenceCount", width: 90,
              sorter: (a: IOCGlobalItem, b: IOCGlobalItem) => a.occurrenceCount - b.occurrenceCount,
            },
            {
              title: "关联组织", dataIndex: "associatedGroups", width: 250,
              render: (groups: string[]) =>
                groups?.length ? (
                  <Space wrap>
                    {groups.map((g) => (
                      <Tag key={g} color="magenta" style={{ fontSize: 11 }}>{g}</Tag>
                    ))}
                  </Space>
                ) : "-",
            },
            {
              title: "首次发现", dataIndex: "firstSeen", width: 130,
              render: (t: string) => (t ? new Date(t).toLocaleDateString("zh-CN") : "-"),
            },
            {
              title: "最近发现", dataIndex: "lastSeen", width: 130,
              render: (t: string) => (t ? new Date(t).toLocaleDateString("zh-CN") : "-"),
              defaultSortOrder: "descend",
              sorter: (a: IOCGlobalItem, b: IOCGlobalItem) =>
                new Date(a.lastSeen).getTime() - new Date(b.lastSeen).getTime(),
            },
          ]}
        />
      </Card>

      {/* 详情抽屉 */}
      <IOCDetailPanel
        iocId={detailIocId}
        open={detailIocId != null}
        onClose={() => setDetailIocId(null)}
      />
    </div>
  );
}
