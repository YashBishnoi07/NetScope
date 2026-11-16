import { useEffect, useMemo, useState, type ChangeEvent } from 'react';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js';
import { BrowserRouter, NavLink, Navigate, Route, Routes } from 'react-router-dom';
import StatusPanel from './components/StatusPanel';
import type { Alert, FlowRecord, Overview, PacketSummary } from './types';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Filler, Tooltip, Legend);

const API_URL =
  (import.meta as unknown as { env: Record<string, string | undefined> }).env.VITE_API_URL ??
  'http://localhost:8000';
const originalFetch = window.fetch.bind(window);
window.fetch = (input: RequestInfo | URL, init?: RequestInit) =>
  originalFetch(
    typeof input === 'string' ? input.replace('http://localhost:8000', API_URL) : input,
    init,
  );
type AlertSummary = {
  by_severity: Record<string, number>;
  timeline: Array<{ bucket: string; count: number }>;
};

type ThreatSummary = {
  by_type: Record<string, number>;
  top_sources: Array<{ source: string; count: number }>;
  total: number;
};

type PacketActivity = { protocol: string; count: number; bytes: number };

type HostSummary = { host: string; packet_count?: number; bytes_total?: number; protocols?: Record<string, number> };

function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}

function AppShell() {
  const [health, setHealth] = useState<{ ok: boolean; status: string } | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [protocols, setProtocols] = useState<Record<string, number>>({});
  const [bandwidthHistory, setBandwidthHistory] = useState<Array<{ time: number; bytes: number }>>([]);
  const [alertSummary, setAlertSummary] = useState<AlertSummary>({
    by_severity: { low: 0, medium: 0, high: 0, critical: 0 },
    timeline: [],
  });
  const [threatSummary, setThreatSummary] = useState<ThreatSummary>({
    by_type: {},
    top_sources: [],
    total: 0,
  });
  const [protocolActivity, setProtocolActivity] = useState<PacketActivity[]>([]);
  const [suspiciousSources, setSuspiciousSources] = useState<Array<{ source: string; count: number; severity: string }>>([]);
  const [suspiciousDestinations, setSuspiciousDestinations] = useState<Array<{ destination: string; count: number; severity: string }>>([]);
  const [topTalkers, setTopTalkers] = useState<Array<{ host: string; packets: number; bytes: number }>>([]);
  const [portStats, setPortStats] = useState<Array<{ port: number; count: number; service: string }>>([]);
  const [dnsStats, setDnsStats] = useState<{ queries: number; responses: number; top_domains: Array<{ domain: string; count: number }> } | null>(null);
  const [httpStats, setHttpStats] = useState<{ requests: number; responses: number; tls_handshakes: number; top_paths: Array<{ path: string; count: number }>; top_tls_versions: Array<{ version: string; count: number }> } | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [sessions, setSessions] = useState<Array<{ session_id: string; state: string; source: string }>>([]);
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<PacketSummary | null>(null);
  const [packetSearch, setPacketSearch] = useState('');
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('simulator');
  const [captureStatus, setCaptureStatus] = useState<{
    state: string;
    source: string;
    last_error?: string | null;
    interface?: string | null;
    started_at?: number | null;
    packets_seen?: number | null;
    packets_per_second?: number | null;
    queue_depth?: number | null;
    drops?: number | null;
  } | null>(null);
  const [uploadedPcapPath, setUploadedPcapPath] = useState<string | null>(null);
  const [uploadMessage, setUploadMessage] = useState<string | null>(null);
  const [settings, setSettings] = useState<Record<string, number | string>>({
    detector_port_scan_threshold: 3,
    detector_syn_flood_threshold: 20,
    detector_arp_spoof_threshold: 2,
    detector_icmp_flood_threshold: 15,
    detector_dns_tunnel_threshold: 0.7,
    alert_severity_filter: 'all',
    alert_retention_hours: 24,
    capture_queue_limit: 500,
  });
  const [timeWindow, setTimeWindow] = useState<number>(12);
  const [running, setRunning] = useState(false);

  const packetRate = Math.round(overview?.packet_rate ?? 0);
  const bandwidth = overview?.bandwidth_bps ? `${(overview.bandwidth_bps / 1000).toFixed(1)} KB/s` : '0 KB/s';
  const filteredPackets = packets.filter((packet) => {
    const haystack = `${packet.src} ${packet.dst} ${packet.protocol} ${packet.info}`.toLowerCase();
    return haystack.includes(packetSearch.toLowerCase());
  });
  const chosenSeverityFilter = String(settings.alert_severity_filter ?? 'all').toLowerCase();
  const visibleAlerts = alerts.filter((alert) => chosenSeverityFilter === 'all' || alert.severity.toLowerCase() === chosenSeverityFilter);
  const selectedPacketDetails = selectedPacket?.details ? Object.entries(selectedPacket.details) : [];

  const protocolChartData = useMemo(
    () => ({
      labels: Object.keys(protocols),
      datasets: [
        {
          data: Object.values(protocols),
          backgroundColor: ['#1e3a5f', '#3b6fb6', '#8ca9d1', '#d6dce8', '#b73f45', '#a86a16', '#1d7a56'],
          borderColor: '#ffffff',
          borderWidth: 1,
        },
      ],
    }),
    [protocols],
  );

  const bandwidthChartData = useMemo(
    () => ({
      labels: bandwidthHistory.map((point) => `${point.time}`),
      datasets: [
        {
          label: 'Bandwidth',
          data: bandwidthHistory.map((point) => Number(point.bytes)),
          borderColor: '#1e3a5f',
          backgroundColor: 'rgba(30, 58, 95, 0.12)',
          borderWidth: 2,
          tension: 0.35,
          fill: true,
        },
      ],
    }),
    [bandwidthHistory],
  );

  const alertChartData = useMemo(
    () => ({
      labels: alertSummary.timeline.map((entry) => entry.bucket),
      datasets: [
        {
          label: 'Alerts',
          data: alertSummary.timeline.map((entry) => entry.count),
          backgroundColor: '#3b6fb6',
          borderRadius: 8,
        },
      ],
    }),
    [alertSummary],
  );

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false } },
      y: { beginAtZero: true, grid: { color: 'rgba(15, 23, 42, 0.06)' } },
    },
  };

  const donutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: { usePointStyle: true, boxWidth: 8 },
      },
    },
  };

  const fetchSnapshot = async () => {
    const windowParam = `?window_hours=${timeWindow}`;
    try {
      const [
        healthResponse,
        overviewResponse,
        protocolsResponse,
        protocolActivityResponse,
        bandwidthResponse,
        alertSummaryResponse,
        threatSummaryResponse,
        suspiciousSourcesResponse,
        suspiciousDestinationsResponse,
        topTalkersResponse,
        portSummaryResponse,
        dnsResponse,
        httpResponse,
        alertsResponse,
        packetsResponse,
        flowsResponse,
        sessionsResponse,
        hostsResponse,
        interfacesResponse,
        settingsResponse,
        captureStatusResponse,
      ] = await Promise.all([
        fetch('http://localhost:8000/api/v1/health'),
        fetch('http://localhost:8000/api/v1/stats/overview'),
        fetch('http://localhost:8000/api/v1/stats/protocols'),
        fetch(`http://localhost:8000/api/v1/stats/protocol-activity${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/bandwidth${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/alerts${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/threats${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/suspicious-sources${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/suspicious-destinations${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/top-talkers${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/ports${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/dns${windowParam}`),
        fetch(`http://localhost:8000/api/v1/stats/http${windowParam}`),
        fetch('http://localhost:8000/api/v1/alerts'),
        fetch('http://localhost:8000/api/v1/packets?limit=7'),
        fetch('http://localhost:8000/api/v1/flows'),
        fetch('http://localhost:8000/api/v1/sessions'),
        fetch('http://localhost:8000/api/v1/hosts'),
        fetch('http://localhost:8000/api/v1/interfaces'),
        fetch('http://localhost:8000/api/v1/settings'),
        fetch('http://localhost:8000/api/v1/capture/status'),
      ]);

      const healthData = await healthResponse.json();
      const overviewData = await overviewResponse.json();
      const protocolsData = await protocolsResponse.json();
      const protocolActivityData = await protocolActivityResponse.json();
      const bandwidthData = await bandwidthResponse.json();
      const alertSummaryData = await alertSummaryResponse.json();
      const threatSummaryData = await threatSummaryResponse.json();
      const suspiciousSourcesData = await suspiciousSourcesResponse.json();
      const suspiciousDestinationsData = await suspiciousDestinationsResponse.json();
      const topTalkersData = await topTalkersResponse.json();
      const portSummaryData = await portSummaryResponse.json();
      const dnsData = await dnsResponse.json();
      const httpData = await httpResponse.json();
      const alertsData = await alertsResponse.json();
      const packetsData = await packetsResponse.json();
      const flowsData = await flowsResponse.json();
      const sessionsData = await sessionsResponse.json();
      const hostsData = await hostsResponse.json();
      const interfacesData = await interfacesResponse.json();
      const settingsData = await settingsResponse.json();
      const captureStatusData = await captureStatusResponse.json();

      setHealth({ ok: Boolean(healthData.ok), status: healthData.status ?? 'idle' });
      setCaptureStatus({
        state: captureStatusData.state ?? 'idle',
        source: captureStatusData.source ?? 'simulator',
        last_error: captureStatusData.last_error ?? null,
        interface: captureStatusData.interface ?? null,
        started_at: captureStatusData.started_at ?? null,
        packets_seen: captureStatusData.packets_seen ?? 0,
        packets_per_second: captureStatusData.packets_per_second ?? 0,
        queue_depth: captureStatusData.queue_depth ?? 0,
        drops: captureStatusData.drops ?? 0,
      });
      setOverview(overviewData);
      setProtocols(protocolsData || {});
      setProtocolActivity(Array.isArray(protocolActivityData) ? protocolActivityData : []);
      setBandwidthHistory(Array.isArray(bandwidthData) ? bandwidthData : []);
      setAlertSummary(alertSummaryData || { by_severity: { low: 0, medium: 0, high: 0, critical: 0 }, timeline: [] });
      setThreatSummary(threatSummaryData || { by_type: {}, top_sources: [], total: 0 });
      setSuspiciousSources(Array.isArray(suspiciousSourcesData) ? suspiciousSourcesData : []);
      setSuspiciousDestinations(Array.isArray(suspiciousDestinationsData) ? suspiciousDestinationsData : []);
      setTopTalkers(Array.isArray(topTalkersData) ? topTalkersData : []);
      setPortStats(Array.isArray(portSummaryData) ? portSummaryData : []);
      setDnsStats(dnsData || null);
      setHttpStats(httpData || null);
      setAlerts(Array.isArray(alertsData) ? alertsData : []);
      setPackets(Array.isArray(packetsData.items) ? packetsData.items : []);
      setFlows(Array.isArray(flowsData) ? flowsData : []);
      setSessions(Array.isArray(sessionsData) ? sessionsData : []);
      setHosts(Array.isArray(hostsData) ? hostsData : []);
      setInterfaces(Array.isArray(interfacesData) ? interfacesData : []);
      setSettings((previous) => ({
        ...previous,
        ...((settingsData || {}) as Record<string, number | string>),
      }));
      if (Array.isArray(interfacesData) && interfacesData.length > 0 && !interfacesData.includes(selectedInterface)) {
        setSelectedInterface(interfacesData[0]);
      }
      setRunning(healthData.status === 'running');
    } catch {
      setHealth({ ok: false, status: 'offline' });
      setRunning(false);
    }
  };

  useEffect(() => {
    void fetchSnapshot();
    const timer = window.setInterval(() => {
      void fetchSnapshot();
    }, 2000);
    return () => window.clearInterval(timer);
  }, [timeWindow]);

  useEffect(() => {
    if (selectedPacketId === null) {
      setSelectedPacket(null);
      return;
    }

    const loadSelectedPacket = async () => {
      try {
        const response = await fetch(`http://localhost:8000/api/v1/packets/${selectedPacketId}`);
        const data = await response.json();
        setSelectedPacket(data && data.id ? data : null);
      } catch {
        setSelectedPacket(null);
      }
    };

    void loadSelectedPacket();
  }, [selectedPacketId]);

  const handleCaptureToggle = async () => {
    const endpoint = running ? 'http://localhost:8000/api/v1/capture/stop' : 'http://localhost:8000/api/v1/capture/start';
    const payload = uploadedPcapPath ? { source: 'pcap', interface: uploadedPcapPath } : { source: 'live', interface: selectedInterface || 'simulator' };

    await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: running ? undefined : JSON.stringify(payload),
    });
    await fetchSnapshot();
  };

  const handleReplayDemo = async () => {
    await fetch('http://localhost:8000/api/v1/capture/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'pcap', interface: 'data/demo_capture.pcap' }),
    });
    await fetchSnapshot();
  };

  const handleSaveSettings = async () => {
    await fetch('http://localhost:8000/api/v1/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings),
    });
    await fetchSnapshot();
  };

  const handleClearAlerts = async () => {
    await fetch('http://localhost:8000/api/v1/alerts/clear', { method: 'POST' });
    await fetchSnapshot();
  };

  const handleExport = async (format: 'json' | 'csv') => {
    const response = await fetch(`http://localhost:8000/api/v1/export/packets?format=${format}`);
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `netscope_packets.${format}`;
    link.click();
    window.URL.revokeObjectURL(url);
  };

  const handleUploadPcap = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    if (!file.name.toLowerCase().endsWith('.pcap')) {
      setUploadMessage('Please select a valid .pcap file.');
      event.target.value = '';
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:8000/api/v1/capture/upload-pcap', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setUploadMessage(data?.detail || 'Upload failed. Please try another PCAP file.');
        event.target.value = '';
        return;
      }

      if (!data.path) {
        setUploadMessage('Upload completed but the server did not return a valid path.');
        event.target.value = '';
        return;
      }

      setUploadedPcapPath(data.path);
      setSelectedInterface(data.path);
      setUploadMessage(`Loaded ${file.name} and starting capture...`);
      await fetchSnapshot();

      const startResponse = await fetch('http://localhost:8000/api/v1/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: 'pcap', interface: data.path }),
      });

      const startData = await startResponse.json().catch(() => ({}));
      if (!startResponse.ok) {
        setUploadMessage(startData?.detail || 'PCAP file uploaded, but capture could not be started.');
      } else {
        setRunning(true);
        setUploadMessage(`Loaded ${file.name} and capture is running.`);
      }
      await fetchSnapshot();
    } catch (error) {
      setUploadMessage(error instanceof Error ? error.message : 'Upload failed.');
    } finally {
      event.target.value = '';
    }
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">N</div>
          <div className="brand-copy">
            <span className="brand-name">NetScope</span>
            <span className="brand-subtitle">Network insight console</span>
          </div>
        </div>
        <nav>
          {[
            { to: '/overview', label: 'Overview' },
            { to: '/packets', label: 'Packets' },
            { to: '/flows', label: 'Flows' },
            { to: '/alerts', label: 'Alerts' },
            { to: '/settings', label: 'Settings' },
          ].map((item) => (
            <NavLink key={item.to} to={item.to} className={({ isActive }) => `nav-button ${isActive ? 'active' : ''}`}>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="content">
        <header className="topbar panel">
          <div>
            <p className="eyebrow">Capture status</p>
            <strong className="status-title">{health?.status ?? 'idle'}</strong>
            {captureStatus?.last_error && <div className="upload-tag error-tag">Error: {captureStatus.last_error}</div>}
            {captureStatus?.interface && !captureStatus.last_error && <div className="upload-tag">Interface: {captureStatus.interface}</div>}
            {uploadedPcapPath && <div className="upload-tag">Loaded: {uploadedPcapPath.split(/[\\/]/).pop()}</div>}
            {uploadMessage && <div className="upload-tag">{uploadMessage}</div>}
          </div>

          <div className="topbar-actions">
            <select className="interface-select" value={String(timeWindow)} onChange={(event) => setTimeWindow(Number(event.target.value))}>
              <option value={1}>1h</option>
              <option value={6}>6h</option>
              <option value={12}>12h</option>
              <option value={24}>24h</option>
              <option value={72}>72h</option>
            </select>

            <select className="interface-select" value={selectedInterface} onChange={(event) => setSelectedInterface(event.target.value)}>
              {interfaces.length === 0 ? (
                <option value="simulator">simulator</option>
              ) : (
                interfaces.map((iface) => (
                  <option key={iface} value={iface}>{iface}</option>
                ))
              )}
            </select>

            <input id="pcap-upload" type="file" accept=".pcap" hidden onChange={handleUploadPcap} />
            <button type="button" className="secondary-btn accent-btn" onClick={() => document.getElementById('pcap-upload')?.click()}>Upload PCAP</button>
            <button type="button" className="secondary-btn accent-btn subtle" onClick={() => void handleReplayDemo()}>Replay demo pcap</button>
            <button type="button" className="secondary-btn" onClick={() => void handleExport('json')}>Export JSON</button>
            <button type="button" className="secondary-btn" onClick={() => void handleExport('csv')}>Export CSV</button>
            <button type="button" className="primary-btn accent-primary" onClick={() => void handleCaptureToggle()}>{running ? 'Stop' : 'Start'}</button>
          </div>
        </header>

        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route
            path="/overview"
            element={
              <OverviewPage
                overview={overview}
                alerts={alerts}
                packetRate={packetRate}
                bandwidth={bandwidth}
                protocols={protocols}
                protocolActivity={protocolActivity}
                bandwidthHistory={bandwidthHistory}
                alertSummary={alertSummary}
                dnsStats={dnsStats}
                httpStats={httpStats}
                captureStatus={captureStatus}
                protocolChartData={protocolChartData}
                bandwidthChartData={bandwidthChartData}
                alertChartData={alertChartData}
                chartOptions={chartOptions}
                donutOptions={donutOptions}
              />
            }
          />
          <Route
            path="/packets"
            element={
              <PacketsPage
                packets={filteredPackets}
                packetSearch={packetSearch}
                setPacketSearch={setPacketSearch}
                selectedPacket={selectedPacket}
                selectedPacketId={selectedPacketId}
                setSelectedPacketId={setSelectedPacketId}
                selectedPacketDetails={selectedPacketDetails}
              />
            }
          />
          <Route
            path="/flows"
            element={
              <FlowsPage
                flows={flows}
                sessions={sessions}
                hosts={hosts}
                topTalkers={topTalkers}
                portStats={portStats}
              />
            }
          />
          <Route
            path="/alerts"
            element={
              <AlertsPage
                alerts={visibleAlerts}
                threatSummary={threatSummary}
                suspiciousSources={suspiciousSources}
                suspiciousDestinations={suspiciousDestinations}
                alertSummary={alertSummary}
                alertChartData={alertChartData}
                chartOptions={chartOptions}
              />
            }
          />
          <Route
            path="/settings"
            element={
              <SettingsPage
                settings={settings}
                setSettings={setSettings}
                onSave={handleSaveSettings}
                onClearAlerts={handleClearAlerts}
              />
            }
          />
        </Routes>
      </main>
    </div>
  );
}

function OverviewPage({
  overview,
  alerts,
  packetRate,
  bandwidth,
  protocols,
  protocolActivity,
  bandwidthHistory,
  alertSummary,
  dnsStats,
  httpStats,
  captureStatus,
  protocolChartData,
  bandwidthChartData,
  alertChartData,
  chartOptions,
  donutOptions,
}: {
  overview: Overview | null;
  alerts: Alert[];
  packetRate: number;
  bandwidth: string;
  protocols: Record<string, number>;
  protocolActivity: PacketActivity[];
  bandwidthHistory: Array<{ time: number; bytes: number }>;
  alertSummary: AlertSummary;
  dnsStats: { queries: number; responses: number; top_domains: Array<{ domain: string; count: number }> } | null;
  httpStats: { requests: number; responses: number; tls_handshakes: number; top_paths: Array<{ path: string; count: number }>; top_tls_versions: Array<{ version: string; count: number }> } | null;
  captureStatus: { state: string; source: string; last_error?: string | null; interface?: string | null; started_at?: number | null; packets_seen?: number | null; packets_per_second?: number | null; queue_depth?: number | null; drops?: number | null; } | null;
  protocolChartData: { labels: string[]; datasets: Array<{ data: number[]; backgroundColor: string[]; borderColor: string; borderWidth: number }> };
  bandwidthChartData: { labels: string[]; datasets: Array<{ label: string; data: number[]; borderColor: string; backgroundColor: string; borderWidth: number; tension: number; fill: boolean }> };
  alertChartData: { labels: string[]; datasets: Array<{ label: string; data: number[]; backgroundColor: string; borderRadius: number }> };
  chartOptions: Record<string, unknown>;
  donutOptions: Record<string, unknown>;
}) {
  return (
    <div className="route-page">
      <div className="stats-grid">
        <StatusPanel label="Packets/s" value={packetRate.toLocaleString()} />
        <StatusPanel label="Bandwidth" value={bandwidth} />
        <StatusPanel label="Active flows" value={String(overview?.active_flows ?? 0)} />
        <StatusPanel label="Alerts" value={String(alerts.length)} />
        <StatusPanel label="Hosts" value={String(overview?.unique_hosts ?? 0)} />
        <StatusPanel label="Drops" value={String(overview?.dropped_packets ?? 0)} />
      </div>

      <div className="page-grid two-col">
        <div className="panel">
          <div className="panel-header">
            <h2>Capture overview</h2>
          </div>
          <div className="metric-row"><span>Source</span><strong>{captureStatus?.source ?? 'simulator'}</strong></div>
          <div className="metric-row"><span>Interface</span><strong>{captureStatus?.interface ?? '—'}</strong></div>
          <div className="metric-row"><span>Packets seen</span><strong>{captureStatus?.packets_seen ?? 0}</strong></div>
          <div className="metric-row"><span>Rate</span><strong>{Number(captureStatus?.packets_per_second ?? 0).toFixed(1)}/s</strong></div>
          <div className="metric-row"><span>Drop count</span><strong>{captureStatus?.drops ?? 0}</strong></div>
          <div className="metric-row"><span>Uptime</span><strong>{captureStatus?.started_at ? `${Math.max(0, Math.floor((Date.now() / 1000 - captureStatus.started_at) / 60))}m` : '0m'}</strong></div>
        </div>

        <div className="panel chart-panel">
          <div className="panel-header">
            <h2>Protocol mix</h2>
          </div>
          <div className="chart-box mini-chart">
            {Object.keys(protocols).length === 0 ? (
              <span className="muted">No protocol data yet.</span>
            ) : (
              <Doughnut data={protocolChartData} options={donutOptions} />
            )}
          </div>
        </div>
      </div>

      <div className="page-grid three-col">
        <div className="panel chart-panel">
          <div className="panel-header">
            <h2>Traffic trend</h2>
          </div>
          <div className="chart-box tall-chart">
            {bandwidthHistory.length === 0 ? (
              <span className="muted">No historical data yet.</span>
            ) : (
              <Line data={bandwidthChartData} options={chartOptions} />
            )}
          </div>
        </div>

        <div className="panel chart-panel">
          <div className="panel-header">
            <h2>Alert volume</h2>
          </div>
          <div className="chart-box tall-chart">
            {alertSummary.timeline.length === 0 ? (
              <span className="muted">No alert history yet.</span>
            ) : (
              <Bar data={alertChartData} options={chartOptions} />
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Protocol activity</h2>
          </div>
          <div className="mini-list">
            {protocolActivity.length === 0 ? (
              <span className="muted">No protocol activity yet.</span>
            ) : (
              protocolActivity.slice(0, 6).map((entry) => (
                <div key={entry.protocol} className="mini-item">
                  <span>{entry.protocol}</span>
                  <span>{entry.count} pkts</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="page-grid two-col">
        <div className="panel">
          <div className="panel-header"><h2>DNS insight</h2></div>
          <div className="metric-row"><span>Queries</span><strong>{dnsStats?.queries ?? 0}</strong></div>
          <div className="metric-row"><span>Responses</span><strong>{dnsStats?.responses ?? 0}</strong></div>
          <div className="mini-list">
            {(dnsStats?.top_domains?.length ?? 0) === 0 ? (
              <span className="muted">No DNS traffic yet.</span>
            ) : (
              dnsStats?.top_domains.slice(0, 4).map((entry) => (
                <div key={entry.domain} className="mini-item">
                  <span>{entry.domain}</span>
                  <span>{entry.count}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>HTTP & TLS</h2></div>
          <div className="metric-row"><span>Requests</span><strong>{httpStats?.requests ?? 0}</strong></div>
          <div className="metric-row"><span>Responses</span><strong>{httpStats?.responses ?? 0}</strong></div>
          <div className="metric-row"><span>TLS handshakes</span><strong>{httpStats?.tls_handshakes ?? 0}</strong></div>
          <div className="mini-list">
            {(httpStats?.top_paths?.length ?? 0) === 0 && (httpStats?.top_tls_versions?.length ?? 0) === 0 ? (
              <span className="muted">No app-layer traffic yet.</span>
            ) : (
              <>
                {httpStats?.top_paths?.slice(0, 2).map((entry) => (
                  <div key={entry.path} className="mini-item">
                    <span>{entry.path}</span>
                    <span>{entry.count}</span>
                  </div>
                ))}
                {httpStats?.top_tls_versions?.slice(0, 2).map((entry) => (
                  <div key={entry.version} className="mini-item">
                    <span>{entry.version}</span>
                    <span>{entry.count}</span>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function PacketsPage({
  packets,
  packetSearch,
  setPacketSearch,
  selectedPacket,
  selectedPacketId,
  setSelectedPacketId,
  selectedPacketDetails,
}: {
  packets: PacketSummary[];
  packetSearch: string;
  setPacketSearch: (value: string) => void;
  selectedPacket: PacketSummary | null;
  selectedPacketId: number | null;
  setSelectedPacketId: (value: number | null) => void;
  selectedPacketDetails: Array<[string, unknown]>;
}) {
  return (
    <div className="route-page">
      <div className="page-grid two-col large-grid">
        <div className="panel">
          <div className="panel-header">
            <h2>Packet stream</h2>
          </div>
          <div className="search-box-wrap">
            <input className="search-box" value={packetSearch} onChange={(event) => setPacketSearch(event.target.value)} placeholder="Search src, dst, protocol, info" />
          </div>
          <div className="packet-list">
            {packets.length === 0 ? (
              <div className="packet-row muted-row">No packets available.</div>
            ) : (
              packets.map((packet) => (
                <button
                  key={packet.id}
                  type="button"
                  className={`packet-row compact-row packet-button ${selectedPacketId === packet.id ? 'selected' : ''}`}
                  onClick={() => setSelectedPacketId(packet.id)}
                >
                  <span className={`badge ${packet.protocol.toLowerCase()}`}>{packet.protocol}</span>
                  <span>{packet.src}</span>
                  <span>→</span>
                  <span>{packet.dst}</span>
                  <span>{packet.length}B</span>
                </button>
              ))
            )}
          </div>
        </div>

        <div className="panel packet-detail-panel">
          <div className="panel-header"><h2>Packet detail</h2></div>
          {selectedPacket ? (
            <div className="packet-detail">
              <p><strong>ID:</strong> {selectedPacket.id}</p>
              <p><strong>Flow:</strong> {selectedPacket.flow_key ?? 'n/a'}</p>
              <p><strong>Protocol:</strong> {selectedPacket.protocol}</p>
              <p><strong>Src/Dst:</strong> {selectedPacket.src} → {selectedPacket.dst}</p>
              <p><strong>Ports:</strong> {selectedPacket.src_port ?? '—'} / {selectedPacket.dst_port ?? '—'}</p>
              <p><strong>Info:</strong> {selectedPacket.info}</p>
              {selectedPacketDetails.length > 0 && (
                <div className="detail-stack">
                  {selectedPacketDetails.map(([label, value]) => (
                    <div key={label} className="detail-item">
                      <strong>{label}:</strong>{' '}
                      {typeof value === 'object' && value !== null ? <span>{JSON.stringify(value)}</span> : <span>{String(value)}</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="muted">Select a packet to inspect details.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function FlowsPage({
  flows,
  sessions,
  hosts,
  topTalkers,
  portStats,
}: {
  flows: FlowRecord[];
  sessions: Array<{ session_id: string; state: string; source: string }>;
  hosts: HostSummary[];
  topTalkers: Array<{ host: string; packets: number; bytes: number }>;
  portStats: Array<{ port: number; count: number; service: string }>;
}) {
  return (
    <div className="route-page">
      <div className="page-grid three-col">
        <div className="panel">
          <div className="panel-header"><h2>Top flows</h2></div>
          <div className="mini-list">
            {flows.length === 0 ? (
              <span className="muted">No active flows.</span>
            ) : (
              flows.slice(0, 8).map((flow) => (
                <div key={flow.key} className="mini-item">
                  <span>{flow.protocol}</span>
                  <span>{flow.src}:{flow.src_port ?? '—'} → {flow.dst}:{flow.dst_port ?? '—'}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>Sessions</h2></div>
          <div className="mini-list">
            {sessions.length === 0 ? (
              <span className="muted">No sessions yet.</span>
            ) : (
              sessions.map((session) => (
                <div key={session.session_id} className="mini-item">
                  <span>{session.session_id}</span>
                  <span className="badge low">{session.state}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>Port activity</h2></div>
          <div className="mini-list">
            {portStats.length === 0 ? (
              <span className="muted">No port activity yet.</span>
            ) : (
              portStats.slice(0, 8).map((entry) => (
                <div key={entry.port} className="mini-item">
                  <span>{entry.service || `port ${entry.port}`}</span>
                  <span>{entry.count}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="page-grid two-col">
        <div className="panel">
          <div className="panel-header"><h2>Host activity</h2></div>
          <div className="mini-list">
            {hosts.length === 0 ? (
              <span className="muted">No host activity.</span>
            ) : (
              hosts.slice(0, 8).map((host) => (
                <div key={host.host} className="mini-item">
                  <span>{host.host}</span>
                  <span>{host.packet_count ?? 0} pkts</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>Top talkers</h2></div>
          <div className="mini-list">
            {topTalkers.length === 0 ? (
              <span className="muted">No host traffic yet.</span>
            ) : (
              topTalkers.slice(0, 8).map((talker) => (
                <div key={talker.host} className="mini-item">
                  <span>{talker.host}</span>
                  <span>{talker.packets} pkts / {talker.bytes}B</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function AlertsPage({
  alerts,
  threatSummary,
  suspiciousSources,
  suspiciousDestinations,
  alertSummary,
  alertChartData,
  chartOptions,
}: {
  alerts: Alert[];
  threatSummary: ThreatSummary;
  suspiciousSources: Array<{ source: string; count: number; severity: string }>;
  suspiciousDestinations: Array<{ destination: string; count: number; severity: string }>;
  alertSummary: AlertSummary;
  alertChartData: { labels: string[]; datasets: Array<{ label: string; data: number[]; backgroundColor: string; borderRadius: number }> };
  chartOptions: Record<string, unknown>;
}) {
  return (
    <div className="route-page">
      <div className="page-grid two-col">
        <div className="panel chart-panel">
          <div className="panel-header"><h2>Alert volume</h2></div>
          <div className="chart-box tall-chart">
            {alertSummary.timeline.length === 0 ? (
              <span className="muted">No alert history yet.</span>
            ) : (
              <Bar data={alertChartData} options={chartOptions} />
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>Severity totals</h2></div>
          <div className="metric-row"><span>Low</span><strong>{alertSummary.by_severity.low ?? 0}</strong></div>
          <div className="metric-row"><span>Medium</span><strong>{alertSummary.by_severity.medium ?? 0}</strong></div>
          <div className="metric-row"><span>High</span><strong>{alertSummary.by_severity.high ?? 0}</strong></div>
          <div className="metric-row"><span>Critical</span><strong>{alertSummary.by_severity.critical ?? 0}</strong></div>
        </div>
      </div>

      <div className="page-grid two-col">
        <div className="panel">
          <div className="panel-header"><h2>Threat summary</h2></div>
          <div className="metric-row"><span>Total alerts</span><strong>{threatSummary.total ?? 0}</strong></div>
          <div className="mini-list">
            {Object.keys(threatSummary.by_type || {}).length === 0 ? (
              <span className="muted">No suspicious activity yet.</span>
            ) : (
              Object.entries(threatSummary.by_type).slice(0, 6).map(([type, count]) => (
                <div key={type} className="mini-item"><span>{type}</span><span>{count}</span></div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>Top sources</h2></div>
          <div className="mini-list">
            {(threatSummary.top_sources || []).length === 0 ? (
              <span className="muted">No top sources yet.</span>
            ) : (
              threatSummary.top_sources.slice(0, 6).map((entry) => (
                <div key={entry.source} className="mini-item"><span>{entry.source}</span><span>{entry.count}</span></div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="page-grid two-col">
        <div className="panel">
          <div className="panel-header"><h2>Suspicious sources</h2></div>
          <div className="mini-list">
            {suspiciousSources.length === 0 ? (
              <span className="muted">No suspicious source activity.</span>
            ) : (
              suspiciousSources.map((entry) => (
                <div key={entry.source} className="mini-item">
                  <span>{entry.source}</span>
                  <span className={`badge ${entry.severity}`}>{entry.severity}</span>
                  <span>{entry.count}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>Suspicious destinations</h2></div>
          <div className="mini-list">
            {suspiciousDestinations.length === 0 ? (
              <span className="muted">No suspicious destination activity.</span>
            ) : (
              suspiciousDestinations.map((entry) => (
                <div key={entry.destination} className="mini-item">
                  <span>{entry.destination}</span>
                  <span className={`badge ${entry.severity}`}>{entry.severity}</span>
                  <span>{entry.count}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header"><h2>Recent alerts</h2></div>
        <div className="packet-list">
          {alerts.length === 0 ? (
            <div className="packet-row muted-row">No alerts in the selected window.</div>
          ) : (
            alerts.slice(0, 10).map((alert) => (
              <div key={alert.id} className="packet-row compact-row">
                <span>{alert.type}</span>
                <span className={`badge ${alert.severity}`}>{alert.severity}</span>
                <span>{alert.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function SettingsPage({
  settings,
  setSettings,
  onSave,
  onClearAlerts,
}: {
  settings: Record<string, number | string>;
  setSettings: React.Dispatch<React.SetStateAction<Record<string, number | string>>>;
  onSave: () => Promise<void>;
  onClearAlerts: () => Promise<void>;
}) {
  return (
    <div className="route-page">
      <div className="panel">
        <div className="panel-header"><h2>System settings</h2></div>
        <div className="settings-grid">
          {Object.entries(settings).map(([key, value]) => {
            const isTextSetting = key === 'alert_severity_filter';
            const inputValue = typeof value === 'string' ? value : Number(value);
            return (
              <label key={key} className="setting-field">
                <span>{key}</span>
                {isTextSetting ? (
                  <select value={String(value)} onChange={(event) => setSettings((current) => ({ ...current, [key]: event.target.value }))}>
                    <option value="all">all</option>
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                  </select>
                ) : (
                  <input
                    type="number"
                    step={key.includes('threshold') && !key.includes('dns') ? '1' : '0.1'}
                    value={inputValue}
                    onChange={(event) => setSettings((current) => ({ ...current, [key]: Number(event.target.value) }))}
                  />
                )}
              </label>
            );
          })}
        </div>
        <div className="action-row">
          <button type="button" className="secondary-btn accent-btn" onClick={() => void onSave()}>Save settings</button>
          <button type="button" className="secondary-btn" onClick={() => void onClearAlerts()}>Clear alerts</button>
        </div>
      </div>
    </div>
  );
}

export default App;
