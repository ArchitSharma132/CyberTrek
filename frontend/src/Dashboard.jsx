import { useEffect, useState } from "react"

const API = "http://localhost:8000"

function Dashboard() {
  const [activeTab, setActiveTab] = useState("live")
  const [traffic, setTraffic] = useState([])
  const [alerts, setAlerts] = useState([])
  const [report, setReport] = useState({
    total_packets: 0,
    total_alerts: 0,
    recent_alerts: [],
    generated_at: ""
  })
  const [simulationType, setSimulationType] = useState("port_scan")
  const [simulationResult, setSimulationResult] = useState(null)

  useEffect(() => {
    let mounted = true

    const fetchData = async () => {
      try {
        const [trafficResponse, alertResponse, reportResponse] = await Promise.all([
          fetch(`${API}/traffic`),
          fetch(`${API}/alerts`),
          fetch(`${API}/report`)
        ])

        if (!trafficResponse.ok || !alertResponse.ok || !reportResponse.ok) {
          throw new Error("One or more dashboard API requests failed")
        }

        const [trafficData, alertData, reportData] = await Promise.all([
          trafficResponse.json(),
          alertResponse.json(),
          reportResponse.json()
        ])

        if (mounted) {
          setTraffic(Array.isArray(trafficData) ? trafficData : [])
          setAlerts(Array.isArray(alertData) ? alertData : [])
          setReport({
            total_packets: reportData.total_packets ?? reportData.summary?.total_packets ?? 0,
            total_alerts: reportData.total_alerts ?? reportData.summary?.total_alerts ?? 0,
            recent_alerts: reportData.recent_alerts ?? [],
            generated_at: reportData.generated_at ?? ""
          })
        }
      } catch (error) {
        console.error("Dashboard data fetch failed:", error)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 2000)

    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [])

  const generateReport = async () => {
    try {
      const response = await fetch(`${API}/report/download`)
      if (!response.ok) throw new Error("Failed to generate PDF report")

      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement("a")
      const disposition = response.headers.get("Content-Disposition")
      const match = disposition?.match(/filename="?([^"]+)"?/)

      link.href = url
      link.download = match?.[1] || "cyber_trek_report.pdf"
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error("PDF report download failed:", error)
      alert("Could not download the PDF report. Check that the backend is running.")
    }
  }

  const runSimulation = () => {
    const examples = {
      port_scan: {
        title: "TCP Port Scan",
        severity: "HIGH",
        source: "192.168.1.105",
        destination: "192.168.1.1",
        description: "One source contacted multiple destination ports within a short time window.",
        packets: [
          ["10:42:01", "192.168.1.105", "192.168.1.1", "TCP", "21"],
          ["10:42:02", "192.168.1.105", "192.168.1.1", "TCP", "22"],
          ["10:42:02", "192.168.1.105", "192.168.1.1", "TCP", "23"],
          ["10:42:03", "192.168.1.105", "192.168.1.1", "TCP", "80"],
          ["10:42:03", "192.168.1.105", "192.168.1.1", "TCP", "443"]
        ],
        explanation: "The detector tracks unique destination ports per source IP over a time window. Crossing the configured threshold raises a port-scan alert."
      },
      syn_flood: {
        title: "SYN Flood Indicator",
        severity: "HIGH",
        source: "192.168.1.77",
        destination: "192.168.1.10",
        description: "An unusually high number of TCP SYN packets was observed in the configured time window.",
        packets: [
          ["10:43:01", "192.168.1.77", "192.168.1.10", "TCP SYN", "443"],
          ["10:43:01", "192.168.1.77", "192.168.1.10", "TCP SYN", "443"],
          ["10:43:02", "192.168.1.77", "192.168.1.10", "TCP SYN", "443"],
          ["10:43:02", "192.168.1.77", "192.168.1.10", "TCP SYN", "443"],
          ["10:43:03", "192.168.1.77", "192.168.1.10", "TCP SYN", "443"]
        ],
        explanation: "The detector counts TCP SYN packets from a source within a rolling time window. A sustained rate above the configured threshold raises a SYN-flood indicator."
      },
      icmp_flood: {
        title: "ICMP Flood Indicator",
        severity: "MEDIUM",
        source: "192.168.1.88",
        destination: "192.168.1.10",
        description: "An unusually high ICMP packet rate was observed during the configured time window.",
        packets: [
          ["10:44:01", "192.168.1.88", "192.168.1.10", "ICMP", "—"],
          ["10:44:01", "192.168.1.88", "192.168.1.10", "ICMP", "—"],
          ["10:44:02", "192.168.1.88", "192.168.1.10", "ICMP", "—"],
          ["10:44:02", "192.168.1.88", "192.168.1.10", "ICMP", "—"],
          ["10:44:03", "192.168.1.88", "192.168.1.10", "ICMP", "—"]
        ],
        explanation: "The detector monitors ICMP packet frequency from each source. A rate above the configured threshold produces an ICMP-flood indicator."
      }
,
      udp_flood: {
        title: "UDP Flood Indicator",
        severity: "HIGH",
        source: "192.168.1.120",
        destination: "192.168.1.10",
        description: "A source is sending a high volume of UDP packets or bytes to one destination within a short time window.",
        packets: [
          ["10:45:01", "192.168.1.120", "192.168.1.10", "UDP", "53"],
          ["10:45:01", "192.168.1.120", "192.168.1.10", "UDP", "53"],
          ["10:45:02", "192.168.1.120", "192.168.1.10", "UDP", "123"],
          ["10:45:02", "192.168.1.120", "192.168.1.10", "UDP", "53"],
          ["10:45:03", "192.168.1.120", "192.168.1.10", "UDP", "500"]
        ],
        explanation: "The detector counts UDP packets and captured bytes for each source-destination pair over a rolling time window. Crossing either configured threshold raises a possible UDP-flood alert."
      },
      ping_sweep: {
        title: "ICMP Ping Sweep",
        severity: "MEDIUM",
        source: "192.168.1.50",
        destination: "Multiple hosts",
        description: "One source sends ICMP echo requests to multiple distinct destination IP addresses.",
        packets: [
          ["10:46:01", "192.168.1.50", "192.168.1.11", "ICMP Echo Request", "—"],
          ["10:46:02", "192.168.1.50", "192.168.1.12", "ICMP Echo Request", "—"],
          ["10:46:03", "192.168.1.50", "192.168.1.13", "ICMP Echo Request", "—"],
          ["10:46:04", "192.168.1.50", "192.168.1.14", "ICMP Echo Request", "—"],
          ["10:46:05", "192.168.1.50", "192.168.1.15", "ICMP Echo Request", "—"]
        ],
        explanation: "The detector tracks ICMP echo requests (type 8) from each source and counts unique destination IPs in a time window. Reaching the configured unique-target threshold raises a possible ping-sweep alert."
      },
      arp_spoofing: {
        title: "ARP Spoofing Indicator",
        severity: "HIGH",
        source: "AA:BB:CC:DD:EE:99",
        destination: "192.168.1.1",
        description: "An ARP announcement claims an IP address that was previously associated with a different MAC address.",
        packets: [
          ["10:47:01", "00:11:22:33:44:55", "192.168.1.1", "ARP Reply", "N/A"],
          ["10:47:02", "AA:BB:CC:DD:EE:99", "192.168.1.1", "ARP Reply", "N/A"],
          ["10:47:03", "AA:BB:CC:DD:EE:99", "192.168.1.1", "ARP Announcement", "N/A"]
        ],
        explanation: "The detector builds an observed IP-to-MAC mapping from ARP packets. If the same sender IP is later advertised by a different MAC address, it raises a possible ARP-spoofing alert. A trusted baseline is important because the first observed mapping is treated as known."
      },
      dns_tunneling: {
        title: "DNS Tunneling Indicator",
        severity: "HIGH",
        source: "192.168.1.75",
        destination: "192.168.1.1",
        description: "A DNS query contains an unusually long or high-entropy label, or the source sends an unusually high number of DNS queries.",
        packets: [
          ["10:48:01", "192.168.1.75", "192.168.1.1", "DNS Query", "53"],
          ["10:48:02", "192.168.1.75", "192.168.1.1", "DNS Query", "53"],
          ["10:48:03", "192.168.1.75", "192.168.1.1", "DNS Query", "53"],
          ["10:48:04", "192.168.1.75", "192.168.1.1", "DNS Query", "53"],
          ["10:48:05", "192.168.1.75", "192.168.1.1", "DNS Query", "53"]
        ],
        explanation: "The detector examines visible UDP DNS queries for long labels, high-entropy first labels, and query volume within a time window. These are heuristic indicators; encrypted DNS traffic is not inspected by this rule."
      },
      malformed_fragments: {
        title: "Malformed IP Fragment Indicator",
        severity: "HIGH",
        source: "192.168.1.90",
        destination: "192.168.1.10",
        description: "IPv4 fragments with the same source, destination, identification and protocol contain overlapping byte ranges or imply an invalid datagram size.",
        packets: [
          ["10:49:01", "192.168.1.90", "192.168.1.10", "IPv4 Fragment", "Offset 0"],
          ["10:49:02", "192.168.1.90", "192.168.1.10", "IPv4 Fragment", "Offset 2"],
          ["10:49:03", "192.168.1.90", "192.168.1.10", "IPv4 Fragment", "Overlapping range"]
        ],
        explanation: "The detector groups IPv4 fragments using source, destination, identification and protocol. It checks for overlapping fragment ranges and sequences that exceed the maximum legal IPv4 datagram size. This flags suspicious fragmentation, not proof of a successful attack."
      }
    }

    setSimulationResult(examples[simulationType])
  }

  return (
    <main style={pageStyle}>
      <div style={contentStyle}>
        <header style={headerStyle}>
          <div>
            <h1 style={logoStyle}>Cyber Trek</h1>
            <p style={taglineStyle}>Real-Time Network Traffic Monitoring and Threat Detection</p>
          </div>
          <div style={onlinePill}>
            <span style={onlineDot} />
            <span style={onlineText}>SYSTEM ONLINE</span>
          </div>
        </header>

        <nav style={tabBarStyle} aria-label="Cyber Trek sections">
          <TabButton active={activeTab === "live"} onClick={() => setActiveTab("live")}>
            <span>◉</span> Live Tracking
          </TabButton>
          <TabButton active={activeTab === "simulation"} onClick={() => setActiveTab("simulation")}>
            <span>⌁</span> Simulation
          </TabButton>
          <TabButton active={activeTab === "visualization"} onClick={() => setActiveTab("visualization")}>
            <span>⌘</span> Working / Visualization
          </TabButton>
        </nav>

        {activeTab === "live" && (
          <section>
            <div style={statsGrid}>
              <StatCard title="Packets Captured" value={report.total_packets} />
              <StatCard title="Alerts Generated" value={report.total_alerts} />
              <StatCard title="Detection Engine" value="ONLINE" />
            </div>

            <div style={liveGrid}>
              <Panel>
                <div style={panelHeading}>
                  <h2 style={sectionTitle}>Live Traffic</h2>
                  <span style={liveLabel}>LIVE</span>
                </div>
                <div style={tableScroll}>
                  <table style={tableStyle}>
                    <thead>
                      <tr>
                        {["Time", "Source", "Destination", "Protocol", "Port"].map(item =>
                          <th key={item} style={headerCell}>{item}</th>
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      {traffic.length === 0 ? (
                        <tr><td colSpan="5" style={emptyCell}>Waiting for network traffic...</td></tr>
                      ) : traffic.map((item, index) => (
                        <tr key={item.id ?? `${item.timestamp}-${index}`} style={tableRow}>
                          <td style={cellStyle}>{item.timestamp ?? "—"}</td>
                          <td style={cellStyle}>{item.source ?? "—"}</td>
                          <td style={cellStyle}>{item.destination ?? "—"}</td>
                          <td style={cellStyle}>{item.protocol ?? "—"}</td>
                          <td style={cellStyle}>{item.port ?? item.destination_port ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>

              <Panel>
                <div style={panelHeading}>
                  <h2 style={sectionTitle}>Threat Alerts</h2>
                  <span style={{
                    ...threatLabel,
                    color: report.total_alerts > 0 ? "#c0392b" : "#27ae60"
                  }}>
                    {report.total_alerts > 0 ? "THREATS DETECTED" : "NO THREATS"}
                  </span>
                </div>
                <div style={alertList}>
                  {alerts.length === 0 ? (
                    <div style={noThreats}>
                      <div style={checkMark}>✓</div>
                      <strong style={{ fontSize: 18, color: "#222" }}>No Threats Detected</strong>
                      <span style={{ marginTop: 6, fontSize: 14 }}>Network activity is being monitored.</span>
                    </div>
                  ) : alerts.map((alert, index) => (
                    <div key={alert.id ?? index} style={alertCard}>
                      <div style={panelHeading}>
                        <strong style={{ fontSize: 16 }}>{alert.type ?? "Security Alert"}</strong>
                        <span style={severityPill(alert.severity)}>{alert.severity ?? "INFO"}</span>
                      </div>
                      <p style={alertMeta}>Source: {alert.source ?? "N/A"}</p>
                      <p style={alertMeta}>Detected: {alert.timestamp ?? "N/A"}</p>
                      {alert.description && <p style={alertDescription}>{alert.description}</p>}
                    </div>
                  ))}
                </div>
              </Panel>
            </div>

            <div style={bottomGrid}>
              <Panel>
                <h2 style={sectionTitle}>System Status</h2>
                <div style={{ display: "flex", flexDirection: "column", gap: 20, marginTop: 24 }}>
                  <StatusRow color="#27ae60" title="Detection Engine" value="Online" />
                  <StatusRow color="#3498db" title="Traffic Capture" value="Active" />
                  <StatusRow color={report.total_alerts > 0 ? "#e67e22" : "#27ae60"} title="Threat Events" value={report.total_alerts} />
                  <StatusRow color="#777" title="Packets in Feed" value={traffic.length} />
                </div>
              </Panel>

              <Panel>
                <h2 style={sectionTitle}>Report Generator</h2>
                <div style={miniStatsGrid}>
                  <MiniStat title="Packets" value={report.total_packets} />
                  <MiniStat title="Alerts" value={report.total_alerts} />
                </div>
                <p style={reportDescription}>
                  Generate a PDF security report from network activity captured by Cyber Trek.
                </p>
                <button onClick={generateReport} style={primaryButton}>Generate Security Report</button>
              </Panel>
            </div>
          </section>
        )}

        {activeTab === "simulation" && (
          <section>
            <Panel>
              <div style={panelHeading}>
                <div>
                  <h2 style={sectionTitle}>Detection Simulation</h2>
                  <p style={mutedParagraph}>Explore how Cyber Trek's detection rules identify suspicious traffic patterns.</p>
                </div>
                <span style={demoBadge}>DEMO MODE</span>
              </div>

              <div style={simulationControls}>
                <label style={fieldLabel} htmlFor="simulation-type">Select a scenario</label>
                <select
                  id="simulation-type"
                  value={simulationType}
                  onChange={event => {
                    setSimulationType(event.target.value)
                    setSimulationResult(null)
                  }}
                  style={selectStyle}
                >
                  <option value="port_scan">TCP Port Scan</option>
                  <option value="syn_flood">SYN Flood</option>
                  <option value="icmp_flood">ICMP Flood</option>
                  <option value="udp_flood">UDP Flood</option>
                  <option value="ping_sweep">ICMP Ping Sweep</option>
                  <option value="arp_spoofing">ARP Spoofing</option>
                  <option value="dns_tunneling">DNS Tunneling</option>
                  <option value="malformed_fragments">Malformed IP Fragments</option>
                </select>
                <button onClick={runSimulation} style={primaryButton}>Run Simulation</button>
              </div>
              <p style={simulationNote}>
                This is a visual demonstration using illustrative sample packets. It does not send packets,
                attack a device, or modify live network traffic.
              </p>
            </Panel>

            {simulationResult && (
              <>
                <Panel>
                  <div style={panelHeading}>
                    <h2 style={sectionTitle}>{simulationResult.title}</h2>
                    <span style={severityPill(simulationResult.severity)}>{simulationResult.severity} INDICATOR</span>
                  </div>
                  <div style={simulationSummary}>
                    <div><span style={fieldLabel}>Source IP</span><strong>{simulationResult.source}</strong></div>
                    <div><span style={fieldLabel}>Destination IP</span><strong>{simulationResult.destination}</strong></div>
                    <div><span style={fieldLabel}>Observed packets</span><strong>{simulationResult.packets.length}</strong></div>
                  </div>
                  <div style={alertCard}>
                    <strong>{simulationResult.title} detected</strong>
                    <p style={alertDescription}>{simulationResult.description}</p>
                  </div>
                  <h3 style={subheading}>Detection explanation</h3>
                  <p style={mutedParagraph}>{simulationResult.explanation}</p>
                </Panel>

                <Panel>
                  <h2 style={sectionTitle}>Illustrative packet sequence</h2>
                  <div style={tableScroll}>
                    <table style={tableStyle}>
                      <thead>
                        <tr>{["Time", "Source", "Destination", "Protocol", "Port"].map(item =>
                          <th key={item} style={headerCell}>{item}</th>
                        )}</tr>
                      </thead>
                      <tbody>
                        {simulationResult.packets.map((packet, index) => (
                          <tr key={index} style={tableRow}>
                            {packet.map((value, cellIndex) => <td key={cellIndex} style={cellStyle}>{value}</td>)}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </>
            )}
          </section>
        )}

        {activeTab === "visualization" && (
          <section>
            <Panel>
              <h2 style={sectionTitle}>How Cyber Trek Works</h2>
              <p style={mutedParagraph}>A high-level view of the live packet-monitoring and threat-detection pipeline.</p>
              <div style={flowGrid}>
                <FlowStep number="01" title="Network Interface" detail="Traffic visible to the monitored host is received through the selected network interface." />
                <FlowStep number="02" title="Npcap + Scapy" detail="Npcap provides packet capture access; Scapy reads and extracts packet fields." />
                <FlowStep number="03" title="Packet Processing" detail="Source, destination, protocol, ports and timestamps are normalized." />
                <FlowStep number="04" title="Detection Engine" detail="Eight detection modules evaluate packet rates, destination patterns, ARP mappings, DNS queries and IPv4 fragmentation." />
                <FlowStep number="05" title="Alert Manager" detail="Potential threats are assigned severity and duplicate alerts are controlled." />
                <FlowStep number="06" title="Storage + API" detail="Traffic and alerts are stored in SQLite and exposed through FastAPI." />
                <FlowStep number="07" title="Dashboard" detail="React displays live traffic, alerts, statistics and downloadable reports." />
              </div>
            </Panel>

            <div style={vizGrid}>
              <Panel>
                <h2 style={sectionTitle}>Detection Modules</h2>
                <div style={{ display: "grid", gap: 14, marginTop: 20 }}>
                  <ModuleCard title="TCP Port Scan" tag="PORT BEHAVIOUR" detail="Tracks unique destination ports contacted by a source within a time window." />
                  <ModuleCard title="SYN Flood" tag="TCP RATE" detail="Counts TCP SYN packets from a source during a rolling time window." />
                  <ModuleCard title="ICMP Flood" tag="ICMP RATE" detail="Monitors ICMP packet frequency to identify unusually high traffic rates." />
                  <ModuleCard title="UDP Flood" tag="UDP RATE / VOLUME" detail="Tracks UDP packet count and captured byte volume for each source-destination pair." />
                  <ModuleCard title="ICMP Ping Sweep" tag="HOST DISCOVERY" detail="Counts distinct destination IPs receiving ICMP echo requests from one source." />
                  <ModuleCard title="ARP Spoofing" tag="ARP MAPPING" detail="Detects conflicting MAC addresses advertising the same sender IP address." />
                  <ModuleCard title="DNS Tunneling" tag="DNS HEURISTICS" detail="Flags long or high-entropy DNS labels and unusually frequent DNS queries." />
                  <ModuleCard title="Malformed IP Fragments" tag="IP FRAGMENTATION" detail="Checks IPv4 fragment sequences for overlapping ranges and oversized reconstructed datagrams." />
                </div>
              </Panel>
              <Panel>
                <h2 style={sectionTitle}>Data Flow</h2>
                <div style={dataFlow}>
                  <div style={flowNode}>Captured packets</div>
                  <div style={flowArrow}>↓</div>
                  <div style={flowNode}>Parsing and normalization</div>
                  <div style={flowArrow}>↓</div>
                  <div style={flowNode}>Detection rules</div>
                  <div style={flowArrow}>↓</div>
                  <div style={flowNode}>Alert manager + SQLite</div>
                  <div style={flowArrow}>↓</div>
                  <div style={flowNode}>FastAPI → React dashboard</div>
                </div>
              </Panel>
            </div>
            <div style={infoNote}>
              <strong>Monitoring limitation:</strong> Cyber Trek can only inspect traffic visible to its capture
              interface. On a switched network, it does not automatically see every device's unicast traffic.
              Detection results are heuristic indicators and may include false positives.
            </div>
          </section>
        )}
      </div>
    </main>
  )
}

function TabButton({ active, onClick, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      style={{
        ...tabButton,
        color: active ? "#111" : "#686868",
        borderBottom: active ? "3px solid #111" : "3px solid transparent",
        fontWeight: active ? 750 : 600,
        background: active ? "#fff" : "transparent"
      }}
    >
      {children}
    </button>
  )
}

function Panel({ children }) {
  return <div style={panelStyle}>{children}</div>
}

function StatCard({ title, value }) {
  return (
    <div style={statCardStyle}>
      <div style={statLabel}>{title}</div>
      <div style={statValue}>{value}</div>
    </div>
  )
}

function MiniStat({ title, value }) {
  return (
    <div style={miniStatStyle}>
      <div style={miniLabel}>{title}</div>
      <div style={miniValue}>{value}</div>
    </div>
  )
}

function StatusRow({ color, title, value }) {
  return (
    <div style={statusRow}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ width: 10, height: 10, borderRadius: "50%", background: color }} />
        <span style={{ fontWeight: 600 }}>{title}</span>
      </div>
      <span style={{ color: "#555", fontSize: 14 }}>{value}</span>
    </div>
  )
}

function FlowStep({ number, title, detail }) {
  return (
    <div style={flowStep}>
      <span style={stepNumber}>{number}</span>
      <div>
        <strong style={{ display: "block", color: "#111", marginBottom: 6 }}>{title}</strong>
        <span style={{ color: "#666", fontSize: 13, lineHeight: 1.55 }}>{detail}</span>
      </div>
    </div>
  )
}

function ModuleCard({ title, tag, detail }) {
  return (
    <div style={moduleCard}>
      <div style={panelHeading}>
        <strong style={{ color: "#111" }}>{title}</strong>
        <span style={moduleTag}>{tag}</span>
      </div>
      <p style={alertDescription}>{detail}</p>
    </div>
  )
}

const pageStyle = {
  minHeight: "100vh",
  width: "100%",
  boxSizing: "border-box",
  background: "#f3f5f8",
  padding: "24px",
  fontFamily: "Segoe UI, Arial, sans-serif",
  color: "#111"
}
const contentStyle = { width: "100%", maxWidth: 1600, margin: "0 auto" }
const headerStyle = {
  width: "100%", boxSizing: "border-box", background: "#fff", borderRadius: 24,
  padding: "28px 36px", marginBottom: 18,
  boxShadow: "8px 8px 18px rgba(0,0,0,0.07), -8px -8px 18px rgba(255,255,255,0.95)",
  display: "flex", justifyContent: "space-between", alignItems: "center", gap: 20
}
const logoStyle = { margin: 0, fontSize: 42, lineHeight: 1.1, fontWeight: 800, color: "#111" }
const taglineStyle = { margin: "9px 0 0", color: "#444", fontSize: 16 }
const onlinePill = {
  display: "flex", alignItems: "center", gap: 10, padding: "11px 18px",
  borderRadius: 14, background: "#f7f8fa",
  boxShadow: "inset 3px 3px 7px rgba(0,0,0,0.06), inset -3px -3px 7px white",
  whiteSpace: "nowrap"
}
const onlineDot = { width: 12, height: 12, borderRadius: "50%", background: "#27ae60" }
const onlineText = { fontSize: 14, fontWeight: 700, color: "#222" }
const tabBarStyle = {
  display: "flex", alignItems: "stretch", gap: 4, overflowX: "auto",
  background: "#fff", borderRadius: 16, padding: "0 12px",
  marginBottom: 26, boxShadow: "4px 4px 12px rgba(0,0,0,0.045)"
}
const tabButton = {
  border: 0, borderRadius: "10px 10px 0 0", padding: "17px 20px 14px",
  fontSize: 14, cursor: "pointer", whiteSpace: "nowrap",
  display: "flex", alignItems: "center", gap: 9, transition: "color 0.15s ease"
}
const statCardStyle = {
  background: "#fff",
  borderRadius: 24,
  padding: 26,
  boxShadow: "8px 8px 18px rgba(0,0,0,0.07), -8px -8px 18px rgba(255,255,255,0.95)"
}
const statLabel = {
  color: "#666",
  fontSize: 14,
  marginBottom: 12
}
const statValue = {
  color: "#111",
  fontSize: 30,
  fontWeight: 800
}
const statusRow = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: 12
}
const statsGrid = { display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 26, marginBottom: 26 }
const liveGrid = { display: "grid", gridTemplateColumns: "minmax(0, 3fr) minmax(320px, 2fr)", gap: 26 }
const bottomGrid = { display: "grid", gridTemplateColumns: "minmax(0, 1.2fr) minmax(0, 1fr)", gap: 26, marginTop: 26 }
const panelStyle = {
  width: "100%", minWidth: 0, boxSizing: "border-box", background: "#fff",
  borderRadius: 24, padding: 26,
  boxShadow: "8px 8px 18px rgba(0,0,0,0.07), -8px -8px 18px rgba(255,255,255,0.95)"
}
const sectionTitle = { margin: 0, color: "#111", fontSize: 23, lineHeight: 1.2, fontWeight: 700 }
const panelHeading = { display: "flex", justifyContent: "space-between", alignItems: "center", gap: 14, marginBottom: 18 }
const liveLabel = { color: "#27ae60", fontSize: 13, fontWeight: 700 }
const threatLabel = { fontSize: 12, fontWeight: 700, whiteSpace: "nowrap" }
const tableScroll = { width: "100%", overflowX: "auto", maxHeight: 560, overflowY: "auto" }
const tableStyle = { width: "100%", minWidth: 650, borderCollapse: "collapse", fontSize: 13 }
const headerCell = { textAlign: "left", padding: "12px 10px", color: "#111", fontWeight: 700, borderBottom: "2px solid #e5e7eb", whiteSpace: "nowrap" }
const cellStyle = { padding: "11px 10px", color: "#333", whiteSpace: "nowrap", borderBottom: "1px solid #ececec" }
const tableRow = { borderBottom: "1px solid #ececec" }
const emptyCell = { textAlign: "center", padding: 40, color: "#666" }
const alertList = { height: 560, overflowY: "auto" }
const noThreats = { minHeight: 400, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", textAlign: "center", color: "#555" }
const checkMark = { fontSize: 32, color: "#27ae60", marginBottom: 10 }
const alertCard = { background: "#fafbfc", border: "1px solid #dfe3e8", borderRadius: 16, padding: 17, marginBottom: 14 }
const alertMeta = { margin: "9px 0 0", color: "#555", fontSize: 13 }
const alertDescription = { margin: "10px 0 0", color: "#666", fontSize: 13, lineHeight: 1.55 }
const miniStatsGrid = { display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 15, marginTop: 20 }
const miniStatStyle = { background: "#f6f7f9", borderRadius: 14, padding: 15 }
const miniLabel = { color: "#666", fontSize: 12, marginBottom: 7 }
const miniValue = { color: "#111", fontSize: 24, fontWeight: 800 }
const reportDescription = { marginTop: 18, color: "#666", fontSize: 13, lineHeight: 1.5 }
const primaryButton = { width: "100%", marginTop: 18, padding: 14, border: 0, borderRadius: 14, background: "#111", color: "#fff", cursor: "pointer", fontSize: 14, fontWeight: 700 }
const mutedParagraph = { margin: "9px 0 0", color: "#666", fontSize: 14, lineHeight: 1.6 }
const demoBadge = { background: "#f1f2f4", color: "#444", borderRadius: 8, padding: "7px 10px", fontSize: 11, fontWeight: 800, letterSpacing: 0.5, whiteSpace: "nowrap" }
const simulationControls = { display: "grid", gridTemplateColumns: "1fr 2fr 1fr", alignItems: "end", gap: 16, marginTop: 24 }
const fieldLabel = { display: "block", color: "#555", fontSize: 12, fontWeight: 700, marginBottom: 8 }
const selectStyle = { width: "100%", boxSizing: "border-box", padding: 13, borderRadius: 12, border: "1px solid #dfe3e8", background: "#fafbfc", color: "#222", fontSize: 14 }
const simulationNote = { margin: "16px 0 0", color: "#777", fontSize: 12, lineHeight: 1.5 }
const simulationSummary = { display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 14, margin: "22px 0" }
const subheading = { margin: "22px 0 8px", color: "#111", fontSize: 16 }
const severityPill = severity => ({
  background: ["HIGH", "CRITICAL"].includes(String(severity).toUpperCase()) ? "#fbe9e7" : "#fff4df",
  color: ["HIGH", "CRITICAL"].includes(String(severity).toUpperCase()) ? "#b83227" : "#9a6700",
  borderRadius: 8, padding: "5px 9px", fontSize: 11, fontWeight: 800, whiteSpace: "nowrap"
})
const flowGrid = { display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 14, marginTop: 24 }
const flowStep = { display: "flex", gap: 14, padding: 18, borderRadius: 15, background: "#f8f9fb", border: "1px solid #e5e8ed" }
const stepNumber = { flex: "0 0 36px", height: 36, display: "grid", placeItems: "center", borderRadius: 10, background: "#111", color: "#fff", fontSize: 12, fontWeight: 800 }
const vizGrid = { display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", gap: 26, marginTop: 26 }
const moduleCard = { padding: 15, borderRadius: 14, background: "#fafbfc", border: "1px solid #e2e6eb" }
const moduleTag = { fontSize: 10, fontWeight: 800, color: "#777", letterSpacing: 0.5 }
const dataFlow = { display: "flex", flexDirection: "column", alignItems: "center", marginTop: 18 }
const flowNode = { width: "100%", boxSizing: "border-box", padding: 13, textAlign: "center", borderRadius: 12, background: "#f6f7f9", border: "1px solid #e0e4e9", color: "#222", fontSize: 13, fontWeight: 650 }
const flowArrow = { padding: "5px 0", color: "#888", fontSize: 19 }
const infoNote = { marginTop: 26, padding: 18, borderRadius: 14, background: "#fff", border: "1px solid #e2e6eb", color: "#666", fontSize: 13, lineHeight: 1.6 }

export default Dashboard
