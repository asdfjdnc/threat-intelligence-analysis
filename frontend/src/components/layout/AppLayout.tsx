import { useState, type ReactNode } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Layout, Menu, Button } from "antd";
import {
  DashboardOutlined,
  UploadOutlined,
  FileTextOutlined,
  BugOutlined,
  TeamOutlined,
  ApartmentOutlined,
  SettingOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
} from "@ant-design/icons";

const { Header, Sider, Content } = Layout;

const menuItems = [
  { key: "/", icon: <DashboardOutlined />, label: "仪表盘" },
  { key: "/upload", icon: <UploadOutlined />, label: "上传分析" },
  { key: "/reports", icon: <FileTextOutlined />, label: "报告列表" },
  { key: "/iocs", icon: <BugOutlined />, label: "IOC 浏览器" },
  { key: "/threat-groups", icon: <TeamOutlined />, label: "威胁组织" },
  { key: "/knowledge-graph", icon: <ApartmentOutlined />, label: "知识图谱" },
  { key: "/settings", icon: <SettingOutlined />, label: "设置" },
];

export default function AppLayout({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <Layout>
      <Sider trigger={null} collapsible collapsed={collapsed} breakpoint="lg"
        style={{ background: "#001529" }}>
        <div className={`logo ${collapsed ? "logo-collapsed" : ""}`}>
          {collapsed ? "🛡️" : "🛡️ 威胁情报分析"}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname === "/" ? "/" : location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header style={{ padding: "0 24px", background: "#fff", display: "flex",
          alignItems: "center", borderBottom: "1px solid #f0f0f0" }}>
          <Button type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            onClick={() => setCollapsed(!collapsed)} />
          <span style={{ marginLeft: 16, fontSize: 16, fontWeight: 500 }}>
            威胁情报自动化提取与分析平台
          </span>
        </Header>
        <Content className="site-layout-content">
          {children}
        </Content>
      </Layout>
    </Layout>
  );
}
