
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Campaigns from "./pages/Campaigns";
import Agents from "./pages/Agents";
import Techniques from "./pages/Techniques";
import Wazuh from "./pages/Wazuh";
import Snort from "./pages/Snort";
import Suricata from "./pages/Suricata";
import ThreatIntel from "./pages/ThreatIntel";
import MicrosoftThreatIntel from "./pages/MicrosoftThreatIntel";
import AwsThreatIntel from "./pages/AwsThreatIntel";
import Network from "./pages/Network";
import Alerts from "./pages/Alerts";
import Settings from "./pages/Settings";
import InfoSecAudits from "./pages/InfoSecAudits";
import ComplianceReporting from "./pages/ComplianceReporting";
import Contact from "./pages/Contact";
import NotFound from "./pages/NotFound";
import Elasticsearch from "./pages/Elasticsearch";
import Opensearch from "./pages/Opensearch";
import AiInsights from "./pages/AiInsights";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/campaigns" element={<Campaigns />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/techniques" element={<Techniques />} />
          <Route path="/network" element={<Network />} />
          <Route path="/wazuh" element={<Wazuh />} />
          <Route path="/snort" element={<Snort />} />
          <Route path="/suricata" element={<Suricata />} />
          <Route path="/elasticsearch" element={<Elasticsearch />} />
          <Route path="/opensearch" element={<Opensearch />} />
          <Route path="/threat-intel" element={<ThreatIntel />} />
          <Route path="/microsoft-threat-intel" element={<MicrosoftThreatIntel />} />
          <Route path="/aws-threat-intel" element={<AwsThreatIntel />} />
          <Route path="/infosec-audits" element={<InfoSecAudits />} />
          <Route path="/compliance-reporting" element={<ComplianceReporting />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/ai-insights" element={<AiInsights />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
