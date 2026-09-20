/** Mermaid 知识图谱渲染组件 — v11 兼容 */

import { useEffect, useRef, useState, useCallback } from "react";
import { Alert, Button, Space, Spin } from "antd";
import { FullscreenOutlined, FullscreenExitOutlined } from "@ant-design/icons";
import mermaid from "mermaid";

let _ready = false;
function ensureMermaid() {
  if (_ready) return;
  mermaid.initialize({
    startOnLoad: false,
    theme: "default",
    securityLevel: "loose",
    flowchart: { useMaxWidth: true, htmlLabels: false },
    // htmlLabels:false avoids Mermaid HTML-parsing bugs with &<> characters in labels
  });
  _ready = true;
}

interface Props {
  mermaidCode: string;
  height?: number | string;
}

export default function KnowledgeGraph({ mermaidCode, height }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const render = useCallback(async () => {
    let cancelled = false;

    setSvg("");
    setError("");
    setLoading(false);

    const code = (mermaidCode || "").trim();
    if (!code) {
      setSvg("");
      return;
    }

    ensureMermaid();
    setLoading(true);

    try {
      // Mermaid v11: validate first, then render
      await mermaid.parse(code);

      const id = `kg-${Math.random().toString(36).slice(2, 10)}`;
      const { svg: output } = await mermaid.render(id, code);

      if (cancelled) return;

      // Detect error text inside SVG
      if (
        output.includes("Syntax error") ||
        output.includes("Parse error") ||
        output.includes("Error:")
      ) {
        setError("图谱语法错误");
        setLoading(false);
        return;
      }

      setSvg(output);
      setError("");
    } catch (e: any) {
      if (cancelled) return;
      const msg =
        e?.message || (typeof e === "string" ? e : "图谱渲染失败");
      console.warn("Mermaid error:", msg);
      setError(msg);
    } finally {
      if (!cancelled) setLoading(false);
    }

    return () => {
      cancelled = true;
    };
  }, [mermaidCode]);

  useEffect(() => {
    render();
  }, [render]);

  // --- Loading ---
  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: 40 }}>
        <Spin tip="渲染知识图谱..." />
      </div>
    );
  }

  // --- Error ---
  if (error) {
    return (
      <div>
        <Alert
          message="知识图谱渲染失败"
          description={error}
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
        />
        <div style={{
          background: "#f6f8fa",
          borderRadius: 8,
          padding: 12,
          maxHeight: 200,
          overflow: "auto",
        }}>
          <pre style={{
            fontSize: 10,
            fontFamily: "monospace",
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
            margin: 0,
          }}>
            {mermaidCode}
          </pre>
        </div>
      </div>
    );
  }

  // --- Empty ---
  if (!svg) {
    return (
      <Alert
        message="知识图谱"
        description="暂无数据，请先上传并分析威胁报告"
        type="info"
        showIcon
      />
    );
  }

  // --- Rendered ---
  return (
    <div>
      <div style={{ marginBottom: 8, textAlign: "right" }}>
        <Space>
          <Button
            size="small"
            icon={expanded ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? "收起" : "全屏"}
          </Button>
        </Space>
      </div>
      <div
        ref={containerRef}
        style={{
          background: "#fafafa",
          borderRadius: 8,
          overflow: "auto",
          minHeight: 200,
          maxHeight: expanded ? "85vh" : (height as number) || 500,
          transition: "max-height 0.3s",
          display: "flex",
          justifyContent: "center",
        }}
        dangerouslySetInnerHTML={{ __html: svg }}
      />
    </div>
  );
}
