/** 交互式知识图谱 — SVG 实现，精致视觉风格 */

import { useState, useCallback, useRef, useLayoutEffect } from "react";
import { Button, Space, Tag, Empty, Modal, Descriptions, Spin } from "antd";
import { ReloadOutlined, FullscreenOutlined, FullscreenExitOutlined } from "@ant-design/icons";
import type { ThreatGroupItem } from "../../api/client";

// ── 类型 ──
export interface KGNode {
  id: string; label: string; type: string; iocType?: string;
  meta?: Record<string, unknown>;
}
export interface KGEdge {
  from: string; to: string; relation?: string;
}
interface Props {
  nodes: KGNode[];
  edges: KGEdge[];
  title?: string;
  onGroupClick?: (groupName: string) => Promise<ThreatGroupItem | null>;
}

// ── 精致配色 ──
const PALETTE: Record<string, { fill: string; stroke: string; badge: string; text: string; grad: string }> = {
  ioc:       { fill: "#FFF8E1", stroke: "#FF8F00", badge: "#FF6D00", text: "#5D4037", grad: "#FFE082" },
  group:     { fill: "#FCE4EC", stroke: "#E53935", badge: "#C62828", text: "#4E342E", grad: "#EF9A9A" },
  report:    { fill: "#E8F5E9", stroke: "#43A047", badge: "#2E7D32", text: "#1B5E20", grad: "#A5D6A7" },
  technique: { fill: "#E3F2FD", stroke: "#1E88E5", badge: "#1565C0", text: "#263238", grad: "#90CAF9" },
  cve:       { fill: "#F3E5F5", stroke: "#8E24AA", badge: "#6A1B9A", text: "#311B92", grad: "#CE93D8" },
};

const ICONS: Record<string, string> = {
  ip: "IP", domain: "DN", url: "URL", hash: "#",
  cve: "CVE", attack_technique: "T", threat_group: "G", email: "@",
};

// ── 布局: 网格扇区 ──
function computeLayout(nodes: KGNode[]): { positions: Map<string, { x: number; y: number }>; size: number } {
  const pos = new Map<string, { x: number; y: number }>();
  const grouped: Record<string, KGNode[]> = {};
  for (const n of nodes) {
    if (!grouped[n.type]) grouped[n.type] = [];
    grouped[n.type].push(n);
  }

  const cfg: Record<string, { a: number; s: number; r: number; c: number }> = {
    report:    { a: -Math.PI/2, s: 0.4,  r: 60,  c: 1 },
    group:     { a:  Math.PI/2, s: 1.2,  r: 230, c: 3 },
    ioc:       { a: -Math.PI/2, s: 2,    r: 400, c: 8 },
    technique: { a:  Math.PI,   s: 0.7,  r: 560, c: 4 },
    cve:       { a:  0,         s: 0.7,  r: 560, c: 4 },
  };

  let maxE = 600;

  for (const [t, items] of Object.entries(grouped)) {
    const c = cfg[t] || { a: 0, s: 2, r: 650, c: 5 };
    const { a, s, r, c: cols } = c;
    const rows = Math.ceil(items.length / cols);
    const step = s / cols;
    const start = a - s/2 + step/2;

    for (let i = 0; i < items.length; i++) {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const aa = start + col * step + (row % 2) * (step * 0.25); // alternate rows slight offset
      const rr = r + (row - rows/2 + 0.5) * 60;
      const x = Math.cos(aa) * rr + (Math.random() - 0.5) * 15;
      const y = Math.sin(aa) * rr + (Math.random() - 0.5) * 15;
      pos.set(items[i].id, { x, y });
      maxE = Math.max(maxE, Math.abs(x) + 140, Math.abs(y) + 140);
    }
  }

  return { positions: pos, size: Math.max(800, maxE * 2) };
}

const NODE_H = 42;
const NODE_RX = 10;

// ── 组件 ──
export default function KnowledgeGraphVis({ nodes, edges, title, onGroupClick }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [viewBox, setViewBox] = useState("0 0 800 600");
  const [dragging, setDragging] = useState<{ id: string; sx: number; sy: number } | null>(null);
  const [panning, setPanning] = useState<{ sx: number; sy: number; vx: number; vy: number } | null>(null);
  const [positions, setPositions] = useState<Map<string, { x: number; y: number }>>(new Map());
  const [ready, setReady] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);

  const [groupModal, setGroupModal] = useState<{ open: boolean; name: string; loading: boolean; data: ThreatGroupItem | null }>({
    open: false, name: "", loading: false, data: null,
  });

  useLayoutEffect(() => {
    setReady(false);
    if (nodes.length === 0) return;
    const raf = requestAnimationFrame(() => {
      const { positions: pos, size } = computeLayout(nodes);
      setPositions(pos);
      setViewBox(`${-size/2} ${-size/2} ${size} ${size}`);
      setReady(true);
    });
    return () => cancelAnimationFrame(raf);
  }, [nodes]);

  const resetView = useCallback(() => {
    if (nodes.length === 0) return;
    const { positions: pos, size } = computeLayout(nodes);
    setPositions(pos);
    setViewBox(`${-size/2} ${-size/2} ${size} ${size}`);
    setReady(true);
  }, [nodes]);

  // ── 交互 ──
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const [vx, vy, vw, vh] = viewBox.split(" ").map(Number);
    const s = e.deltaY > 0 ? 1.12 : 0.88;
    const nw = Math.max(200, vw * s);
    const nh = Math.max(150, vh * s);
    const r = svgRef.current?.getBoundingClientRect();
    const mx = r ? (e.clientX - r.left) / r.width : 0.5;
    const my = r ? (e.clientY - r.top) / r.height : 0.5;
    setViewBox(`${vx + (vw - nw) * mx} ${vy + (vh - nh) * my} ${nw} ${nh}`);
  }, [viewBox]);

  const handleMouseDown = useCallback((e: React.MouseEvent, nid?: string) => {
    e.stopPropagation();
    if (nid) { setDragging({ id: nid, sx: e.clientX, sy: e.clientY }); }
    else { const p = viewBox.split(" ").map(Number); setPanning({ sx: e.clientX, sy: e.clientY, vx: p[0], vy: p[1] }); }
  }, [viewBox]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    const p = viewBox.split(" ").map(Number);
    const r = svgRef.current?.getBoundingClientRect();
    const cw = r?.width || 800; const ch = r?.height || 600;
    if (dragging) {
      const dx = (e.clientX - dragging.sx) * (p[2] / cw);
      const dy = (e.clientY - dragging.sy) * (p[3] / ch);
      setPositions((prev) => { const n = new Map(prev); const o = n.get(dragging.id) || { x: 0, y: 0 }; n.set(dragging.id, { x: o.x + dx, y: o.y + dy }); return n; });
      setDragging({ id: dragging.id, sx: e.clientX, sy: e.clientY });
    }
    if (panning) {
      setViewBox(`${panning.vx - (e.clientX - panning.sx) * (p[2] / cw)} ${panning.vy - (e.clientY - panning.sy) * (p[3] / ch)} ${p[2]} ${p[3]}`);
    }
  }, [dragging, panning, viewBox]);

  const handleMouseUp = useCallback(() => { setDragging(null); setPanning(null); }, []);

  const handleNodeClick = useCallback(async (node: KGNode) => {
    if (node.type !== "group" || !onGroupClick) return;
    setGroupModal({ open: true, name: node.label, loading: true, data: null });
    try { const d = await onGroupClick(node.label); setGroupModal((p) => ({ ...p, loading: false, data: d })); }
    catch { setGroupModal((p) => ({ ...p, loading: false })); }
  }, [onGroupClick]);

  // ── 渲染节点 ──
  const getXY = (id: string) => positions.get(id) || { x: 0, y: 0 };
  const connectedNodes = new Set<string>();
  if (hovered) {
    for (const e of edges) {
      if (e.from === hovered) connectedNodes.add(e.to);
      if (e.to === hovered) connectedNodes.add(e.from);
    }
  }

  const renderNode = (node: KGNode) => {
    const c = PALETTE[node.type] || PALETTE.ioc;
    const { x, y } = getXY(node.id);
    const icon = node.iocType ? (ICONS[node.iocType] || "") : "";
    const label = (icon ? icon + " " : "") + node.label;
    const short = label.length > 22 ? label.slice(0, 20) + "…" : label;
    const isGroup = node.type === "group";
    const isHovered = hovered === node.id;
    const isConnected = connectedNodes.has(node.id);
    const opacity = hovered ? (isHovered || isConnected ? 1 : 0.35) : 1;
    const scale = isHovered ? 1.08 : 1;

    // Estimate label width for node sizing
    const estW = Math.max(70, Math.min(200, short.length * 7.2 + 32));

    // Edge highlight: number of connected edges
    const connCount = edges.filter((e) => e.from === node.id || e.to === node.id).length;
    const strokeW = isHovered ? 3 : isGroup ? 2.5 : connCount > 3 ? 2 : 1.5;
    const highlight = isHovered || (hovered && isConnected);

    return (
      <g key={node.id} opacity={opacity} transform={`translate(${x},${y}) scale(${scale})`}
        style={{ transition: "opacity 0.2s, transform 0.15s" }}
        cursor={isGroup ? "pointer" : "grab"}
        onMouseDown={(e) => handleMouseDown(e, node.id)}
        onMouseEnter={() => setHovered(node.id)}
        onMouseLeave={() => setHovered(null)}
        onClick={() => handleNodeClick(node)}>

        {/* Shadow */}
        <rect x={-estW/2 + 2} y={-NODE_H/2 + 2} width={estW} height={NODE_H} rx={NODE_RX}
          fill="rgba(0,0,0,0.08)" filter="url(#blur)" />

        {/* Main body with gradient */}
        <defs>
          <linearGradient id={`g_${node.id}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={c.grad} stopOpacity={0.9} />
            <stop offset="100%" stopColor={c.fill} stopOpacity={1} />
          </linearGradient>
        </defs>
        <rect x={-estW/2} y={-NODE_H/2} width={estW} height={NODE_H} rx={NODE_RX}
          fill={`url(#g_${node.id})`}
          stroke={highlight ? c.badge : c.stroke}
          strokeWidth={strokeW}
          filter={highlight ? "url(#glow)" : undefined} />

        {/* Left badge (type indicator) */}
        {icon && (
          <>
            <rect x={-estW/2} y={-NODE_H/2} width={32} height={NODE_H} rx={NODE_RX}
              fill={c.badge} opacity={0.85} />
            <rect x={-estW/2 + 32} y={-NODE_H/2} width={NODE_RX} height={NODE_H}
              fill={c.badge} opacity={0.85} />
            <text x={-estW/2 + 16} y={4} textAnchor="middle" fill="#fff" fontSize={10} fontWeight="bold"
              fontFamily="system-ui, sans-serif">{icon}</text>
          </>
        )}

        {/* Label */}
        <text x={icon ? (-estW/2 + 38) : 0} y={4.5} textAnchor={icon ? "start" : "middle"}
          fill={c.text} fontSize={11.5} fontWeight={600}
          fontFamily="system-ui, -apple-system, sans-serif"
          letterSpacing={0.3}>{short}</text>
      </g>
    );
  };

  // ── 渲染边 ──
  const renderEdge = (edge: KGEdge) => {
    const fr = getXY(edge.from);
    const to = getXY(edge.to);
    const dx = to.x - fr.x; const dy = to.y - fr.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < 5) return null;

    const midX = (fr.x + to.x) / 2;
    const midY = (fr.y + to.y) / 2;

    const isHighlighted = hovered && (edge.from === hovered || edge.to === hovered);

    // Relation color & weight — "contains" edges are very light structural background
    const relColors: Record<string, string> = {
      contains: "#BDBDBD", attributed_to: "#E53935", uses: "#FF8F00",
      resolves_to: "#1E88E5",
    };
    const isContains = edge.relation === "contains";
    const stroke = isHighlighted ? "#333" : (relColors[edge.relation || ""] || "#BDBDBD");
    const edgeOpacity = isContains ? (isHighlighted ? 0.7 : 0.15) : (isHighlighted ? 0.9 : 0.5);
    const strokeW = isContains ? (isHighlighted ? 1.2 : 0.5) : (isHighlighted ? 2.2 : 1.3);

    // Curved path
    const cx = midX + dy * 0.15;
    const cy = midY - dx * 0.15;

    return (
      <g key={`e_${edge.from}_${edge.to}_${edge.relation || ""}`} opacity={edgeOpacity}
        style={{ transition: "opacity 0.25s" }}>
        <path d={`M${fr.x},${fr.y} Q${cx},${cy} ${to.x},${to.y}`}
          fill="none" stroke={stroke} strokeWidth={strokeW}
          markerEnd="url(#arrowhead)" />
        {edge.relation && dist > 60 && (
          <text x={cx} y={cy - 7} textAnchor="middle" fill={stroke} fontSize={8.5}
            fontWeight={500} fontFamily="system-ui, sans-serif"
            opacity={0.8}>{edge.relation}</text>
        )}
      </g>
    );
  };

  if (nodes.length === 0 || !ready) {
    return (
      <div style={{ textAlign: "center", padding: 60 }}>
        {nodes.length === 0
          ? <Empty description="暂无图谱数据，请先上传并分析威胁报告" />
          : <Spin tip="渲染知识图谱..." />}
      </div>
    );
  }

  const counts: Record<string, number> = { ioc: 0, group: 0, report: 0, technique: 0, cve: 0 };
  for (const n of nodes) { if (n.type in counts) counts[n.type]++; }

  return (
    <div>
      {/* Toolbar */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        marginBottom: 8, flexWrap: "wrap", gap: 6,
        padding: "6px 12px", background: "#f8f9fa", borderRadius: 8, border: "1px solid #eee",
      }}>
        <Space wrap size={[6, 6]}>
          {title && <strong style={{ fontSize: 13 }}>{title}</strong>}
          <Tag color="processing" style={{ margin: 0 }}>IOC {counts.ioc}</Tag>
          <Tag color="error" style={{ margin: 0 }}>威胁组织 {counts.group}</Tag>
          <Tag color="success" style={{ margin: 0 }}>报告 {counts.report}</Tag>
          <Tag color="blue" style={{ margin: 0 }}>ATT&CK {counts.technique}</Tag>
          <Tag color="purple" style={{ margin: 0 }}>CVE {counts.cve}</Tag>
          <span style={{ color: "#aaa", fontSize: 10 }}>{nodes.length} 节点 · {edges.length} 关联</span>
        </Space>
        <Space>
          <Button size="small" icon={<ReloadOutlined />} onClick={resetView}>重置</Button>
          <Button size="small" icon={expanded ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
            onClick={() => setExpanded(!expanded)}>
            {expanded ? "退出" : "全屏"}
          </Button>
        </Space>
      </div>

      {/* Canvas */}
      <div style={{
        border: "1px solid #e8e8e8", borderRadius: 10,
        background: "#F5F6FA",
        backgroundImage: "radial-gradient(circle, #dcdcdc 1px, transparent 1px)",
        backgroundSize: "24px 24px",
        height: expanded ? "85vh" : 540,
        overflow: "hidden",
        cursor: panning ? "grabbing" : "default",
      }}>
        <svg ref={svgRef} viewBox={viewBox} width="100%" height="100%"
          onWheel={handleWheel}
          onMouseDown={(e) => { if ((e.target as Element).tagName === "svg") handleMouseDown(e); }}
          onMouseMove={handleMouseMove} onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}>
          <defs>
            <filter id="blur"><feGaussianBlur stdDeviation="2.5" /></filter>
            <filter id="glow"><feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#333" floodOpacity="0.25" /></filter>
            <marker id="arrowhead" viewBox="0 0 10 7" refX={9} refY={3.5} markerWidth={5} markerHeight={4} orient="auto-start-reverse">
              <polygon points="0 0, 10 3.5, 0 7" fill="#9E9E9E" />
            </marker>
          </defs>
          <g>{edges.map(renderEdge)}</g>
          <g>{nodes.map(renderNode)}</g>
        </svg>
      </div>

      <div style={{ color: "#bbb", fontSize: 9, textAlign: "center", marginTop: 4 }}>
        滚轮缩放 · 拖拽节点 · 拖拽背景平移 · 悬停高亮关联 · 点击威胁组织查看详情
      </div>

      {/* Group detail modal */}
      <Modal
        title={groupModal.name ? `\u{1F3AF} 威胁组织: ${groupModal.name}` : "威胁组织详情"}
        open={groupModal.open}
        onCancel={() => setGroupModal((p) => ({ ...p, open: false }))}
        footer={null} width={520} destroyOnClose>
        {groupModal.loading ? <div style={{ textAlign: "center", padding: 24 }}><Spin /></div>
          : groupModal.data ? (
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="名称"><strong>{groupModal.data.name}</strong></Descriptions.Item>
              {(groupModal.data.aliases || []).length > 0 && (
                <Descriptions.Item label="别名">
                  <Space wrap>{(groupModal.data.aliases || []).map((a: string) => <Tag key={a} color="magenta">{a}</Tag>)}</Space>
                </Descriptions.Item>
              )}
              <Descriptions.Item label="威胁等级">
                <Tag color={groupModal.data.threatLevel === "high" ? "red" : groupModal.data.threatLevel === "medium" ? "orange" : "green"}>
                  {groupModal.data.threatLevel || "unknown"}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="来源地区">{groupModal.data.origin || "未知"}</Descriptions.Item>
              <Descriptions.Item label="首次活跃">{groupModal.data.firstActive || "未知"}</Descriptions.Item>
              {(groupModal.data.targetedSectors || []).length > 0 && (
                <Descriptions.Item label="目标行业">
                  <Space wrap>{(groupModal.data.targetedSectors || []).map((s: string) => <Tag key={s}>{s}</Tag>)}</Space>
                </Descriptions.Item>
              )}
              {groupModal.data.description && (
                <Descriptions.Item label="描述">{groupModal.data.description}</Descriptions.Item>
              )}
            </Descriptions>
          ) : <Empty description="未找到该组织详情" />}
      </Modal>
    </div>
  );
}
