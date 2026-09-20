/** 前端类型定义 */

export interface ExtractedIOC {
  ioc_type: string;
  value: string;
  context: string;
  confidence: number;
}

export interface ExtractionResult {
  source: string;
  iocs: ExtractedIOC[];
  statistics: Record<string, number>;
}

export interface RAGCorrelation {
  iocType: string;
  iocValue: string;
  isKnown: boolean;
  matchedReportId?: string;
  matchConfidence: number;
  relatedGroups: string[];
}

export interface AnalysisReport {
  _id: string;
  reportId: string;
  summary: string;
  attackChain: string;
  impactAssessment: string;
  defenseSuggestions: string;
  attributedGroupName: string;
  overallRiskLevel: "critical" | "high" | "medium" | "low";
  fullMarkdown: string;
  generatedAt: number;
  modelUsed: string;
}

export interface ReportDoc {
  _id: string;
  title: string;
  source: string;
  status: string;
  iocCount?: number;
  knownIOCCount?: number;
  unknownIOCCount?: number;
  threatGroupsFound?: string[];
  createdAt: number;
  updatedAt: number;
}

export interface ThreatGroup {
  _id: string;
  name: string;
  aliases: string[];
  description: string;
  targetedSectors: string[];
  threatLevel: "high" | "medium" | "low";
  firstActive: string;
  origin: string;
}

export interface IOCDoc {
  _id: string;
  type: string;
  value: string;
  context: string;
  reportId: string;
  isKnown: boolean;
  firstSeen: number;
  lastSeen: number;
  occurrenceCount: number;
}

export interface KGEdge {
  _id: string;
  source: string;
  sourceType: string;
  target: string;
  targetType: string;
  relation: string;
  confidence: number;
}

export interface DashboardStats {
  totalIOCs: number;
  totalReports: number;
  totalGroups: number;
  totalKGEdges: number;
}
