import { Navigate, Route, Routes } from "react-router-dom";
import { MainLayout } from "./layout/MainLayout";
import { AnalysisJobStatusPage } from "./pages/AnalysisJobStatusPage";
import { CaseCreatePage } from "./pages/CaseCreatePage";
import { CaseDetailPage } from "./pages/CaseDetailPage";
import { CasesPage } from "./pages/CasesPage";
import { DashboardPage } from "./pages/DashboardPage";
import { EvidenceUploadPage } from "./pages/EvidenceUploadPage";

export function App() {
  return (
    <MainLayout>
      <Routes>
        <Route element={<DashboardPage />} path="/" />
        <Route element={<CasesPage />} path="/cases" />
        <Route element={<CaseCreatePage />} path="/cases/new" />
        <Route element={<CaseDetailPage />} path="/cases/:caseId" />
        <Route element={<EvidenceUploadPage />} path="/cases/:caseId/evidence/upload" />
        <Route element={<AnalysisJobStatusPage />} path="/cases/:caseId/jobs/:jobId" />
        <Route element={<Navigate replace to="/" />} path="*" />
      </Routes>
    </MainLayout>
  );
}
