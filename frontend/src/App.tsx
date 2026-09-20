import { Routes, Route } from "react-router-dom";
import AppLayout from "./components/layout/AppLayout";
import Dashboard from "./pages/Dashboard";
import UploadPage from "./pages/UploadPage";
import ReportList from "./pages/ReportList";
import ReportDetail from "./pages/ReportDetail";
import IOCBrowser from "./pages/IOCBrowser";
import ThreatGroupDirectory from "./pages/ThreatGroupDirectory";
import KnowledgeGraphPage from "./pages/KnowledgeGraphPage";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/reports" element={<ReportList />} />
        <Route path="/reports/:id" element={<ReportDetail />} />
        <Route path="/iocs" element={<IOCBrowser />} />
        <Route path="/threat-groups" element={<ThreatGroupDirectory />} />
        <Route path="/knowledge-graph" element={<KnowledgeGraphPage />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </AppLayout>
  );
}
