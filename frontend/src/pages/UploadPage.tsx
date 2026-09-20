/** 上传分析页面 — 文件上传 + SSE 实时分析进度 + 分类 IOC 展示 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Upload, Button, Card, Input, Radio, Steps, Alert, Typography,
  Space, Tag, Table, Progress, Collapse,
} from "antd";
import {
  InboxOutlined, FileTextOutlined, LoadingOutlined,
} from "@ant-design/icons";
import type { UploadProps } from "antd";
import { analyzeStream, IOCItem, AnalysisResult } from "../api/client";
import IOCGroupTable from "../components/report/IOCGroupTable";

const { Dragger } = Upload;
const { TextArea } = Input;
const { Title, Text } = Typography;

type ProcessingStage = "idle" | "uploading" | "parsing" | "extracting" | "analyzing" | "completed" | "error";

export default function UploadPage() {
  const navigate = useNavigate();
  const [inputMode, setInputMode] = useState<"file" | "text">("file");
  const [fileContent, setFileContent] = useState<string>("");
  const [fileName, setFileName] = useState<string>("");
  const [fileType, setFileType] = useState<string>("txt");
  const [stage, setStage] = useState<ProcessingStage>("idle");
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [iocs, setIOCs] = useState<IOCItem[]>([]);
  const [reportMarkdown, setReportMarkdown] = useState("");
  const [kgMermaid, setKGMermaid] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const [iocsEnriched, setIOCsEnriched] = useState(false);

  const handleFileUpload: UploadProps["customRequest"] = (options: any) => {
    const { file, onSuccess } = options;
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      setFileContent(text);
      setFileName(file.name);
      setFileType(file.name.endsWith(".pdf") ? "pdf"
        : file.name.endsWith(".html") || file.name.endsWith(".htm") ? "html" : "txt");
      onSuccess?.({}, file);
    };
    reader.readAsText(file);
  };

  const handleStartAnalysis = async () => {
    if (!fileContent.trim()) { setError("请先上传文件或输入文本内容"); return; }
    if (!fileName) { setError("请先上传文件"); return; }

    setError("");
    setIOCs([]);
    setReportMarkdown("");
    setKGMermaid("");
    setResult(null);
    setIOCsEnriched(false);
    setStage("uploading");
    setProgress(10);
    setProgressMsg("正在上传...");

    try {
      analyzeStream(fileContent, fileName, fileType, {
        onProgress: (data) => {
          if (["extracting", "uploading", "parsing"].includes(data.stage)) setStage("extracting");
          else if (data.stage === "enriching") setStage("extracting");
          else if (["rag", "analyzing", "kg"].includes(data.stage)) setStage("analyzing");
          else if (data.stage === "completed") { setStage("completed"); setProgress(100); }
          setProgress(data.percent);
          setProgressMsg(data.message);
        },
        onIOCs: (data) => { setIOCs(data.iocs); },
        onIOCsEnriched: (data) => { setIOCs(data.iocs); setIOCsEnriched(true); },
        onLLMChunk: (chunk) => { setReportMarkdown((prev) => prev + chunk); },
        onResult: (data) => {
          setResult(data);
          setStage("completed");
          setProgress(100);
          setKGMermaid(data.mermaid);
          setProgressMsg("分析完成！");
        },
        onError: (msg) => { setStage("error"); setError(msg); },
      });
    } catch (err) {
      setStage("error");
      setError(err instanceof Error ? err.message : "分析失败");
    }
  };

  const stageStep = ["idle", "uploading", "parsing", "extracting", "analyzing", "completed"].indexOf(stage);

  return (
    <div>
      <div className="page-header"><h2>上传分析</h2></div>

      <Card style={{ marginBottom: 16 }}>
        <Radio.Group value={inputMode} onChange={(e) => {
          setInputMode(e.target.value);
          setFileContent(""); setFileName(""); setError("");
        }} buttonStyle="solid" style={{ marginBottom: 16 }}>
          <Radio.Button value="file"><FileTextOutlined /> 上传文件</Radio.Button>
          <Radio.Button value="text"><FileTextOutlined /> 粘贴文本</Radio.Button>
        </Radio.Group>

        {inputMode === "file" && (
          <Dragger customRequest={handleFileUpload} showUploadList={true}
            maxCount={1} accept=".pdf,.html,.htm,.txt"
            onChange={(info) => { if (info.file.status === "done") setError(""); }}>
            <p className="ant-upload-drag-icon"><InboxOutlined /></p>
            <p className="ant-upload-text">点击或拖拽文件到此区域上传</p>
            <p className="ant-upload-hint">支持 PDF、HTML、TXT 格式的威胁情报报告</p>
          </Dragger>
        )}

        {inputMode === "text" && (
          <TextArea rows={14} placeholder="粘贴威胁情报报告文本内容..."
            onChange={(e) => {
              setFileContent(e.target.value);
              setFileName("手动输入");
              setFileType("txt");
            }} />
        )}

        <div style={{ marginTop: 16, textAlign: "right" }}>
          <Space>
            {fileName && <Tag color="blue">{fileName}</Tag>}
            <Button type="primary" size="large" icon={<LoadingOutlined />}
              onClick={handleStartAnalysis}
              loading={stage !== "idle" && stage !== "completed" && stage !== "error"}
              disabled={!fileContent.trim()}>
              开始分析
            </Button>
          </Space>
        </div>
      </Card>

      {/* 处理进度 */}
      {stage !== "idle" && (
        <Card title="处理进度" style={{ marginBottom: 16 }}>
          <Steps current={stageStep} size="small" status={stage === "error" ? "error" : "process"}
            items={[
              { title: "上传" }, { title: "解析" },
              { title: "提取IOC" }, { title: "AI分类" },
              { title: "关联分析" }, { title: "生成报告" }, { title: "完成" },
            ]} />
          <div style={{ marginTop: 16 }}>
            <Progress percent={progress} status={stage === "error" ? "exception"
              : stage === "completed" ? "success" : "active"} />
            <Text type="secondary">{progressMsg}</Text>
            {stage === "extracting" && iocs.length > 0 && !iocsEnriched && (
              <Tag color="processing" style={{ marginLeft: 8 }}>AI 分类中...</Tag>
            )}
            {iocsEnriched && <Tag color="success" style={{ marginLeft: 8 }}>AI 分类完成</Tag>}
          </div>
          {error && <Alert message="分析失败" description={error} type="error" showIcon style={{ marginTop: 16 }} />}
        </Card>
      )}

      {/* IOC 分类面板 */}
      {iocs.length > 0 && (
        <Card
          title={
            <Space>
              <span>IOC 提取结果 ({iocs.length})</span>
              {iocsEnriched && <Tag color="blue">AI 已分类</Tag>}
            </Space>
          }
          style={{ marginBottom: 16 }}
        >
          <IOCGroupTable iocs={iocs} enriched={iocsEnriched} />
        </Card>
      )}

      {/* 流式报告 */}
      {reportMarkdown && (
        <Card title="AI 分析报告（流式生成中...）" style={{ marginBottom: 16 }}>
          <pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit", fontSize: 14, lineHeight: 1.8, maxHeight: 400, overflow: "auto" }}>
            {reportMarkdown}
          </pre>
        </Card>
      )}

      {/* 完成后 */}
      {stage === "completed" && result && (
        <Card title="分析完成">
          <Space direction="vertical" style={{ width: "100%" }}>
            <Alert message="✅ 威胁情报分析已完成" type="success" showIcon
              description={`从报告中提取了 ${result.iocCount} 个 IOC（${result.knownIOCCount} 已知 + ${result.unknownIOCCount} 新发现）`} />
            <Space>
              <Button type="primary" onClick={() => navigate(`/reports/${result.reportId}`)}>查看报告详情</Button>
              <Button onClick={() => navigate("/reports")}>报告列表</Button>
              <Button onClick={() => navigate("/knowledge-graph")}>查看知识图谱</Button>
            </Space>
          </Space>
        </Card>
      )}
    </div>
  );
}
