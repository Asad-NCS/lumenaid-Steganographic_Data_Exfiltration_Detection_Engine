import React, { useState, useEffect, useCallback, useRef } from "react";
import "./index.css"
const API = "http://localhost:8000";

const css = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #060910; color: #c8d6e8; font-family: 'DM Sans', sans-serif; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: #0d1117; }
  ::-webkit-scrollbar-thumb { background: #1e2d40; border-radius: 2px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  @keyframes fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes scan { 0% { transform: translateY(-100%); } 100% { transform: translateY(400%); } }
  .fade-up { animation: fadeUp 0.35s ease forwards; }
  .row-hover:hover { background: rgba(245,158,11,0.04) !important; }
  .hex-dump { font-family: 'Space Mono', monospace; font-size: 11px; color: #6b8099; line-height: 1.4; white-space: pre; }
  .hex-dump b { color: #f59e0b; font-weight: normal; }
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 10000; backdrop-filter: blur(4px); }
  .modal-content { background: #0b1019; border: 1px solid #141f2e; border-radius: 12px; width: 800px; max-width: 95vw; max-height: 85vh; height: 600px; display: flex; flex-direction: column; animation: fadeUp 0.3s ease; overflow: hidden; }
  .login-input { width: 100%; background: #060910; border: 1px solid #141f2e; padding: 12px 16px; color: #c8d6e8; borderRadius: 8; outline: none; transition: border-color 0.2s; }
  .login-input:focus { border-color: #f59e0b; }
`;

function entropyToColor(entropy, mean, sigma) {
  const threshold = mean + 3.0 * sigma;
  const lerp = (a, b, t) => a + (b - a) * Math.max(0, Math.min(1, t));
  let h, s, l;
  if (entropy <= mean) {
    const t = mean === 0 ? 0 : entropy / mean;
    h = lerp(158, 43, t); s = lerp(64, 95, t); l = lerp(22, 55, t);
  } else {
    const t = threshold === mean ? 1 : (entropy - mean) / (threshold - mean);
    h = lerp(43, 0, t); s = lerp(95, 88, t); l = lerp(55, 52, t);
  }
  return `hsl(${h.toFixed(1)},${s.toFixed(1)}%,${l.toFixed(1)}%)`;
}

function Mono({ children, color, size = 12 }) {
  return (
    <span style={{ fontFamily: "'Space Mono', monospace", fontSize: size, color: color || "#6b8099" }}>
      {children}
    </span>
  );
}

function Tag({ children, color = "#f59e0b" }) {
  return (
    <span style={{
      fontFamily: "'Space Mono', monospace",
      fontSize: 10, fontWeight: 700, letterSpacing: 1,
      padding: "2px 8px", borderRadius: 3,
      background: color + "18", color, border: `1px solid ${color}30`,
      textTransform: "uppercase",
    }}>{children}</span>
  );
}

function StatusDot({ status }) {
  const map = {
    FLAGGED: "#ef4444", CLEAN: "#10b981", SUSPICIOUS: "#f59e0b",
    PENDING: "#6b8099", SCANNING: "#3b82f6", ERROR: "#f97316",
  };
  const color = map[status?.toUpperCase()] || "#6b8099";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span style={{
        width: 7, height: 7, borderRadius: "50%", background: color, flexShrink: 0,
        boxShadow: (status === "FLAGGED" || status === "SUSPICIOUS") ? `0 0 6px ${color}` : "none",
        animation: status === "SCANNING" ? "pulse 1.2s infinite" : "none",
      }} />
      <span style={{ fontSize: 12, color, fontWeight: 500 }}>{status}</span>
    </span>
  );
}

function MetricCard({ label, value, accent = "#f59e0b", sub }) {
  return (
    <div style={{
      background: "#0b1019", border: "1px solid #141f2e",
      borderRadius: 10, padding: "18px 20px",
      borderTop: `2px solid ${accent}40`,
    }}>
      <div style={{ fontSize: 11, color: "#4a6070", textTransform: "uppercase", letterSpacing: 1, marginBottom: 10, fontWeight: 500 }}>
        {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 600, color: "#e2eaf4", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: "#4a6070", marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function UploadZone({ onUploaded }) {
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const inputRef = useRef();

  const doUpload = useCallback(async (file) => {
    setLoading(true); setResult(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch(`${API}/upload`, { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Upload failed");
      setResult({ ok: data.status !== "FLAGGED", text: data.message, status: data.status });
      onUploaded();
    } catch (e) {
      setResult({ ok: false, text: e.message, status: "ERROR" });
    } finally { setLoading(false); }
  }, [onUploaded]);

  return (
    <div>
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) doUpload(f); }}
        onClick={() => !loading && inputRef.current.click()}
        style={{
          border: `1px dashed ${dragging ? "#f59e0b" : "#1e2d3d"}`,
          borderRadius: 10, padding: "32px 24px", textAlign: "center",
          cursor: loading ? "default" : "pointer",
          background: dragging ? "rgba(245,158,11,0.04)" : "#08101a",
          transition: "all 0.2s", position: "relative", overflow: "hidden",
        }}
      >
        <input ref={inputRef} type="file" style={{ display: "none" }}
          onChange={(e) => e.target.files[0] && doUpload(e.target.files[0])} />
        {loading ? (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
            <div style={{ width: 24, height: 24, border: "2px solid #1e2d3d", borderTop: "2px solid #f59e0b", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
            <Mono color="#4a6070">analyzing entropy...</Mono>
          </div>
        ) : (
          <>
            <div style={{ marginBottom: 10 }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#4a6070" strokeWidth="1.5" style={{ margin: "0 auto" }}>
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" />
              </svg>
            </div>
            <div style={{ fontSize: 13, color: "#6b8099", marginBottom: 4 }}>Drop file or click to browse</div>
            <Mono color="#2a3d50">PDF · JPG · PNG · TXT</Mono>
          </>
        )}
      </div>
      {result && (
        <div style={{
          marginTop: 10, padding: "10px 14px", borderRadius: 8,
          background: result.ok ? "rgba(16,185,129,0.06)" : "rgba(239,68,68,0.06)",
          border: `1px solid ${result.ok ? "#10b98130" : "#ef444430"}`,
          fontSize: 13, color: result.ok ? "#10b981" : "#ef4444",
        }}>
          {result.text}
        </div>
      )}
    </div>
  );
}

function FileTable({ files, selectedId, onSelect }) {
  if (!files.length) return (
    <div style={{ padding: "32px 0", textAlign: "center" }}>
      <Mono color="#2a3d50">no files scanned yet</Mono>
    </div>
  );
  return (
    <table style={{ width: "100%", borderCollapse: "collapse" }}>
      <thead>
        <tr style={{ borderBottom: "1px solid #141f2e" }}>
          {["Filename", "Type", "Threat", "Risk", "Submitted"].map(h => (
            <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 10, color: "#2e4257", fontWeight: 600, letterSpacing: 1, textTransform: "uppercase", fontFamily: "'Space Mono', monospace" }}>
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {files.map(f => (
          <tr key={f.file_id} className="row-hover" onClick={() => onSelect(f.file_id)}
            style={{ borderBottom: "1px solid #0d1520", cursor: "pointer", background: f.file_id === selectedId ? "rgba(245,158,11,0.06)" : "transparent", transition: "background 0.15s" }}>
            <td style={{ padding: "11px 12px", fontSize: 13, color: "#c8d6e8" }}>
              {f.file_name || `file_${f.file_id}`}
            </td>
            <td style={{ padding: "11px 12px" }}><Tag>{f.file_type}</Tag></td>
            <td style={{ padding: "11px 12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                {(() => {
                  const rawScore = Number(f.threat_score || 0);
                  const normalizedScore = Math.max(0, Math.min(rawScore, 10));
                  const danger = rawScore >= 6;
                  return (
                    <>
                <div style={{ width: 40, height: 4, background: "#141f2e", borderRadius: 2 }}>
                  <div style={{ height: "100%", width: `${normalizedScore * 10}%`, background: danger ? "#ef4444" : "#f59e0b", borderRadius: 2 }} />
                </div>
                <Mono color={danger ? "#ef4444" : "#f59e0b"}>{rawScore}/10</Mono>
                    </>
                  );
                })()}
              </div>
            </td>
            <td style={{ padding: "11px 12px" }}><StatusDot status={f.risk_level} /></td>
            <td style={{ padding: "11px 12px" }}><Mono>{new Date(f.submitted_at).toLocaleString()}</Mono></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EntropyHeatmap({ segments, baseline, onChunkClick }) {
  const [tooltip, setTooltip] = useState(null);
  const mean = baseline?.mean_entropy ?? 4.0;
  const sigma = baseline?.threshold_sigma ?? 1.0;
  if (!segments.length) return <Mono color="#2a3d50">no segments</Mono>;
  return (
    <div>
      <div style={{ display: "flex", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
        {[
          { color: "hsl(158,64%,22%)", label: "Low entropy" },
          { color: "hsl(43,95%,55%)", label: `Baseline (${mean.toFixed(2)})` },
          { color: "hsl(0,88%,52%)", label: `Anomaly (>${(mean + 3.0 * sigma).toFixed(2)})` },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 10, height: 10, borderRadius: 2, background: color }} />
            <span style={{ fontSize: 11, color: "#4a6070", fontFamily: "'Space Mono', monospace" }}>{label}</span>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
        {segments.map(seg => {
          const color = entropyToColor(seg.entropy_score, mean, sigma);
          const isAnom = seg.entropy_score > mean + sigma;
          return (
            <div key={seg.segment_id}
              onClick={() => onChunkClick(seg)}
              onMouseEnter={e => setTooltip({ x: e.clientX, y: e.clientY, seg, isAnom })}
              onMouseMove={e => setTooltip(t => t && { ...t, x: e.clientX, y: e.clientY })}
              onMouseLeave={() => setTooltip(null)}
              style={{
                width: 20, height: 20, borderRadius: 3, background: color,
                cursor: "zoom-in", transition: "transform 0.1s",
                outline: isAnom ? `1px solid ${color}80` : "none",
              }}
              onMouseOver={e => { e.currentTarget.style.transform = "scale(1.4)"; e.currentTarget.style.zIndex = 10; }}
              onMouseOut={e => { e.currentTarget.style.transform = "scale(1)"; e.currentTarget.style.zIndex = 1; }}
            />
          );
        })}
      </div>
      {tooltip && (
        <div style={{
          position: "fixed", left: tooltip.x + 12, top: tooltip.y + 12,
          background: "#0d1520", border: "1px solid #1e2d3d",
          borderRadius: 8, padding: "10px 14px", fontSize: 12,
          pointerEvents: "none", zIndex: 9999, minWidth: 160,
          fontFamily: "'Space Mono', monospace",
        }}>
          <div style={{ color: "#6b8099", marginBottom: 4 }}>seg #{tooltip.seg.segment_index}</div>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
            <div>
              <div style={{ fontSize: 9, color: "#4a6070", marginBottom: 2 }}>ENTROPY</div>
              <div style={{ color: tooltip.isAnom ? "#ef4444" : "#10b981", fontWeight: 700, fontSize: 13 }}>
                {tooltip.seg.entropy_score.toFixed(4)}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: "#4a6070", marginBottom: 2 }}>CHI-SQ</div>
              <div style={{ 
                color: (baseline && tooltip.seg.chi_square_score > (baseline.mean_chi + 3 * baseline.sigma_chi)) ? "#f59e0b" : "#6b8099", 
                fontWeight: 700, fontSize: 13 
              }}>
                {tooltip.seg.chi_square_score.toFixed(2)}
              </div>
            </div>
          </div>
          <div style={{ color: "#2e4257", marginTop: 6, fontSize: 10 }}>threshold {(tooltip.seg.entropy_score > 0 ? mean + sigma : 0).toFixed(2)}</div>
          {tooltip.isAnom && <div style={{ color: "#ef4444", marginTop: 6, fontSize: 10, fontWeight: 700 }}>ANOMALY DETECTED</div>}
        </div>
      )}
    </div>
  );
}

function AlertList({ alerts }) {
  if (!alerts.length) return <Mono color="#2a3d50">no alerts</Mono>;
  const sevColor = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#eab308" };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {alerts.map(a => (
        <div key={a.alert_id} style={{
          background: "#08101a", border: "1px solid #141f2e",
          borderLeft: `3px solid ${sevColor[a.severity] || "#6b8099"}`,
          borderRadius: "0 8px 8px 0", padding: "12px 14px",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <Tag color={sevColor[a.severity] || "#6b8099"}>{a.severity}</Tag>
            <Mono color={sevColor[a.severity] || "#6b8099"} size={13}>{a.entropy_score?.toFixed(4)}</Mono>
          </div>
          <div style={{ fontSize: 12, color: "#4a6070", lineHeight: 1.5 }}>{a.description || "High entropy segment detected"}</div>
          <div style={{ marginTop: 6 }}><Mono>{new Date(a.created_at).toLocaleString()}</Mono></div>
        </div>
      ))}
    </div>
  );
}

function Panel({ children, style = {} }) {
  return (
    <div style={{
      background: "#0b1019", border: "1px solid #141f2e",
      borderRadius: 10, padding: "20px 22px", ...style,
    }}>{children}</div>
  );
}

function PanelTitle({ children }) {
  return (
    <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ width: 3, height: 14, background: "#f59e0b", borderRadius: 2 }} />
      <span style={{ fontSize: 11, fontFamily: "'Space Mono', monospace", color: "#4a6070", letterSpacing: 1, textTransform: "uppercase" }}>
        {children}
      </span>
    </div>
  );
}

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Login failed");
      onLogin(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#060910" }}>
      <div style={{ width: 400, padding: 40, background: "#0b1019", border: "1px solid #141f2e", borderRadius: 16, boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 32, justifyContent: "center" }}>
            <div style={{ width: 38, height: 38, borderRadius: 8, background: "#f59e0b", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#060910" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            </div>
            <div style={{ fontSize: 24, fontWeight: 600, color: "#e2eaf4", letterSpacing: -0.5 }}>LumenAid</div>
        </div>
        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <label style={{ fontSize: 11, color: "#4a6070", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6, display: "block" }}>Username</label>
            <input type="text" className="login-input" value={username} onChange={e=>setUsername(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: "#4a6070", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6, display: "block" }}>Password</label>
            <input type="password" className="login-input" value={password} onChange={e=>setPassword(e.target.value)} />
          </div>
          {error && <div style={{ color: "#ef4444", fontSize: 13, background: "rgba(239,68,68,0.1)", padding: 10, borderRadius: 6, border: "1px solid #ef444430" }}>{error}</div>}
          <button type="submit" disabled={loading} style={{ background: "#f59e0b", color: "#060910", padding: "14px 16px", border: "none", borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: loading ? "default" : "pointer", marginTop: 8 }}>
            {loading ? "Authenticating..." : "System Login"}
          </button>
        </form>
        <div style={{ marginTop: 24, textAlign: "center", fontSize: 11, color: "#2e4257" }}>
          <Mono>Week 3 Deliverable: Authentication Portal</Mono>
        </div>
      </div>
    </div>
  );
}

function HexDumpModal({ chunk, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("analysis"); // "analysis" | "raw"

  useEffect(() => {
    fetch(`${API}/chunks/${chunk.raw_chunk_ref}/hex`)
      .then(r => r.json())
      .then(d => setData(d))
      .finally(() => setLoading(false));
  }, [chunk]);

  const Tab = ({ id, label }) => (
    <button 
      onClick={() => setActiveTab(id)}
      style={{
        padding: "8px 16px", border: "none", background: "transparent",
        color: activeTab === id ? "#f59e0b" : "#4a6070",
        borderBottom: `2px solid ${activeTab === id ? "#f59e0b" : "transparent"}`,
        fontSize: 12, fontWeight: 600, cursor: "pointer", transition: "all 0.2s"
      }}
    >{label}</button>
  );

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid #141f2e", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: "#e2eaf4" }}>Deep-Dive Sandbox</div>
              <Mono color="#4a6070">seg #{chunk.segment_index} · {chunk.raw_chunk_ref}</Mono>
            </div>
            <div style={{ display: "flex", gap: 8, background: "#060910", padding: 2, borderRadius: 6 }}>
              <Tab id="analysis" label="THREAT ANALYSIS" />
              <Tab id="raw" label="RAW PAYLOAD" />
            </div>
          </div>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: "#4a6070", cursor: "pointer", fontSize: 20 }}>&times;</button>
        </div>
        
        <div style={{ padding: 20, overflow: "auto", background: "#060910", flex: 1, display: "flex", flexDirection: "column" }}>
          {loading ? (
            <Mono color="#2e4257">Decompiling MongoDB shard...</Mono>
          ) : (
            activeTab === "analysis" ? (
              <div className="fade-up" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
                {/* Metrics Row */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                  <div style={{ padding: 16, background: "#0b1019", borderRadius: 8, border: "1px solid #141f2e" }}>
                    <div style={{ fontSize: 10, color: "#4a6070", marginBottom: 8, textTransform: "uppercase" }}>Entropy Density</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                       <div style={{ flex: 1, height: 6, background: "#141f2e", borderRadius: 3, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${(data.entropy / 8) * 100}%`, background: data.is_suspicious ? "#ef4444" : "#10b981" }} />
                       </div>
                       <Mono color={data.is_suspicious ? "#ef4444" : "#10b981"} size={14}>{data.entropy}</Mono>
                    </div>
                  </div>
                  <div style={{ padding: 16, background: "#0b1019", borderRadius: 8, border: "1px solid #141f2e" }}>
                    <div style={{ fontSize: 10, color: "#4a6070", marginBottom: 8, textTransform: "uppercase" }}>Security Verdict</div>
                    <div style={{ fontSize: 13, color: data.is_suspicious ? "#ef4444" : "#c8d6e8", fontWeight: 500 }}>{data.verdict}</div>
                  </div>
                </div>

                {/* Strings Section */}
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11, color: "#4a6070", marginBottom: 12, textTransform: "uppercase", letterSpacing: 1 }}>Extracted Human-Readable Strings</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {data.strings.length > 0 ? data.strings.map((s, i) => (
                      <div key={i} style={{ padding: "6px 10px", background: "#141f2e", borderRadius: 4, border: "1px solid #1e2d3d" }}>
                        <Mono color="#e2eaf4" size={11}>{s}</Mono>
                      </div>
                    )) : <Mono color="#2e4257">No readable strings found in this segment.</Mono>}
                  </div>
                </div>

                <div style={{ marginTop: "auto", padding: 12, background: "rgba(245,158,11,0.03)", border: "1px dashed #f59e0b40", borderRadius: 8 }}>
                   <div style={{ fontSize: 12, color: "#f59e0b", marginBottom: 4, fontWeight: 600 }}>💡 Analyst Tip</div>
                   <div style={{ fontSize: 11, color: "#6b8099", lineHeight: 1.4 }}>
                     This segment has been isolated because its entropy signature deviates from the file's baseline. Switch to the <b>Raw Payload</b> tab to inspect the bytecode for hidden exfiltration patterns.
                   </div>
                </div>
              </div>
            ) : (
              <pre className="hex-dump fade-up">{data?.hex_dump}</pre>
            )
          )}
        </div>
        <div style={{ padding: "12px 20px", borderTop: "1px solid #141f2e", background: "#0b1019", display: "flex", justifyContent: "space-between" }}>
          <Mono color="#2e4257" size={10}>Hybrid Engine: PostgreSQL Metadata + MongoDB Payload</Mono>
          <Mono color="#2e4257" size={10}>v1.2.0-secure</Mono>
        </div>
      </div>
    </div>
  );
}

function TelemetryPanel({ telemetry }) {
  if (!telemetry.length) return <Mono color="#2a3d50">no telemetry logs yet</Mono>;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {telemetry.map(t => (
        <div key={t._id} style={{
          background: "#08101a", border: "1px solid #141f2e",
          borderRadius: 8, padding: "10px 12px",
          borderLeft: `2px solid ${t.flagged ? "#ef4444" : "#10b981"}`,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <Mono size={10}>ID:{t.file_id} · {t.file_type}</Mono>
            <Mono size={10}>{t.analysis_duration_ms}ms</Mono>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 4, height: 4, borderRadius: "50%", background: t.flagged ? "#ef4444" : "#10b981" }} />
            <span style={{ fontSize: 11, color: "#c8d6e8", fontFamily: "'Space Mono', monospace" }}>
              {(t.file_size_bytes / 1024).toFixed(1)}KB · {t.total_segments} segments
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [auth, setAuth] = useState(() => JSON.parse(localStorage.getItem("lumen_auth")));
  const [files, setFiles] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loadingAna, setLoadingAna] = useState(false);
  const [analysisError, setAnalysisError] = useState("");
  const [activeChunk, setActiveChunk] = useState(null);
  const [telemetry, setTelemetry] = useState([]);
  const [showCalibrated, setShowCalibrated] = useState(false);

  const isAdmin = auth?.role === "admin";
  const selectedFile = files.find(f => f.file_id === selectedId) || null;

  const fetchTelemetry = useCallback(async () => {
    if (!isAdmin) return;
    try { const res = await fetch(`${API}/telemetry`); setTelemetry(await res.json()); } catch { }
  }, [isAdmin]);
  const handleLogin = (data) => {
    setAuth(data);
    localStorage.setItem("lumen_auth", JSON.stringify(data));
  };

  const handleLogout = () => {
    setAuth(null);
    localStorage.removeItem("lumen_auth");
  };

  const fetchFiles = useCallback(async () => {
    try { const res = await fetch(`${API}/files`); setFiles(await res.json()); } catch { }
  }, []);

  const fetchAnalysis = useCallback(async (id) => {
    setLoadingAna(true);
    setAnalysis(null);
    setAnalysisError("");
    try {
      const res = await fetch(`${API}/files/${id}/analysis`);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to load file analysis");
      }
      setAnalysis(data);
    } catch (err) {
      setAnalysisError(err.message || "Failed to load file analysis");
    } finally {
      setLoadingAna(false);
    }
  }, []);

  useEffect(() => { 
    fetchFiles(); 
    if (isAdmin) {
      fetchTelemetry();
      const interval = setInterval(fetchTelemetry, 10000);
      return () => clearInterval(interval);
    }
  }, [fetchFiles, fetchTelemetry, isAdmin]);

  const handleSelect = (id) => { setSelectedId(id); fetchAnalysis(id); };

  const flagged = files.filter(f => f.status === "FLAGGED").length;
  const clean = files.filter(f => f.status === "CLEAN").length;
  const alerts = analysis?.alerts?.length || 0;
  const isFlagged = analysis?.status?.toUpperCase() === "FLAGGED";

  if (!auth) return <LoginScreen onLogin={handleLogin} />;

  return (
    <div style={{ minHeight: "100vh", background: "#060910", padding: "28px 24px" }}>
      <style>{css}</style>
      {activeChunk && <HexDumpModal chunk={activeChunk} onClose={() => setActiveChunk(null)} />}

      <div style={{ maxWidth: 1280, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 28 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div style={{
              width: 38, height: 38, borderRadius: 8,
              background: isAdmin ? "#f59e0b" : "#3b82f6", display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#060910" strokeWidth="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <div style={{ fontSize: 17, fontWeight: 600, color: "#e2eaf4", letterSpacing: -0.3 }}>LumenAid</div>
              <Mono color="#2e4257">steganographic detection engine</Mono>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div onClick={handleLogout} style={{ cursor: "pointer", padding: "6px 14px", background: "#0b1019", border: "1px solid #141f2e", borderRadius: 20, display: "flex", alignItems: "center", gap: 8 }}>
               <Mono color="#e2eaf4">{auth.username}</Mono>
               <Tag color="#4a6070">{auth.role}</Tag>
               <div style={{ width: 1, height: 10, background: "#141f2e" }} />
               <Mono color="#ef4444" size={10}>LOGOUT</Mono>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", background: "#0b1019", border: "1px solid #141f2e", borderRadius: 20 }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#10b981" }} />
              <Mono color="#10b981">system online</Mono>
            </div>
          </div>
        </div>

        {/* Metrics */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
          <MetricCard label="Files scanned" value={files.length} accent="#3b82f6" sub="all time" />
          <MetricCard label="Threats detected" value={flagged} accent="#ef4444" sub="flagged files" />
          <MetricCard label="Alerts raised" value={alerts || "—"} accent="#f59e0b" sub="anomalous segments" />
          <MetricCard label="Clean files" value={clean} accent="#10b981" sub="passed scan" />
        </div>

        {/* Main layout */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 16 }}>

          {/* Left */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <Panel>
              <PanelTitle>Upload & Scan</PanelTitle>
              <UploadZone onUploaded={fetchFiles} />
            </Panel>

            <Panel>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                <PanelTitle>{showCalibrated ? "Reference Calibration Samples" : "Scanned files"}</PanelTitle>
                <button 
                  onClick={() => setShowCalibrated(!showCalibrated)}
                  style={{
                    background: "#08101a", border: "1px solid #141f2e",
                    borderRadius: 6, padding: "6px 12px", color: showCalibrated ? "#f59e0b" : "#6b8099",
                    fontSize: 10, fontFamily: "'Space Mono', monospace", cursor: "pointer",
                    transition: "all 0.2s"
                  }}
                >
                  {showCalibrated ? "VIEW TESTING FILES" : "VIEW CALIBRATED FILES"}
                </button>
              </div>
              <FileTable 
                files={files.filter(f => f.is_calibrated === showCalibrated)} 
                selectedId={selectedId} 
                onSelect={handleSelect} 
              />
            </Panel>

            {analysis && !loadingAna && (
              <Panel className="fade-up" style={{
                borderColor: isFlagged ? "#ef444330" : "#10b98130",
                borderTop: `2px solid ${isFlagged ? "#ef4444" : "#10b981"}`,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
                  <div style={{
                    width: 40, height: 40, borderRadius: 8, flexShrink: 0,
                    background: isFlagged ? "rgba(239,68,68,0.12)" : "rgba(16,185,129,0.12)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                      stroke={isFlagged ? "#ef4444" : "#10b981"} strokeWidth="2">
                      {isFlagged
                        ? <><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></>
                        : <path d="M22 11.08V12a10 10 0 11-5.93-9.14M22 4L12 14.01l-3-3" />
                      }
                    </svg>
                  </div>
                  <div>
                    <div style={{ fontSize: 16, fontWeight: 600, color: isFlagged ? "#ef4444" : "#10b981" }}>
                      {isFlagged ? "Threat Detected" : "File Clean"}
                    </div>
                    <div style={{ fontSize: 12, color: "#4a6070", marginTop: 2 }}>
                      <Mono>{selectedFile?.file_name || `file_${analysis.file_id}`}</Mono>
                      &nbsp;·&nbsp;<Tag>{analysis.file_type}</Tag>
                      &nbsp;·&nbsp;<Mono>{analysis.segments.length} segments</Mono>
                    </div>
                  </div>
                  {analysis.baseline && (
                    <div style={{ marginLeft: "auto", textAlign: "right" }}>
                      <div style={{ fontSize: 10, color: "#2e4257", marginBottom: 4, fontFamily: "'Space Mono', monospace" }}>BASELINE</div>
                      <Mono color="#f59e0b" size={13}>μ={analysis.baseline.mean_entropy.toFixed(2)} σ={analysis.baseline.threshold_sigma.toFixed(2)}</Mono>
                    </div>
                  )}
                </div>

                {/* Signals Fired Breakdown */}
                {analysis.signals_fired && (() => {
                  const sf = analysis.signals_fired;
                  const signals = [
                    { key: "signal_1_entropy", label: "Shannon Entropy",       weight: "+3 pts", desc: "Randomness spike above baseline" },
                    { key: "signal_2_chi",     label: "Chi-Square Dist.",      weight: "+3 pts", desc: "Byte DNA deviates from natural pattern" },
                    { key: "signal_3_pattern", label: "Pattern Consistency",   weight: "+2 pts", desc: "Sustained anomaly run (3+ consecutive)" },
                    { key: "signal_4_size",    label: "File Size Delta",       weight: "+2 pts", desc: "File larger than historical average" },
                  ];
                  return (
                    <div style={{ marginBottom: 18 }}>
                      <div style={{ fontSize: 10, color: "#2e4257", fontFamily: "'Space Mono', monospace", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>Detection Signals</div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                        {signals.map(sig => {
                          const fired = sf[sig.key];
                          return (
                            <div key={sig.key} style={{
                              display: "flex", alignItems: "center", gap: 10,
                              padding: "10px 12px", borderRadius: 8,
                              background: fired ? "rgba(239,68,68,0.06)" : "#08101a",
                              border: `1px solid ${fired ? "#ef444330" : "#141f2e"}`,
                            }}>
                              <div style={{
                                width: 22, height: 22, borderRadius: "50%", flexShrink: 0,
                                background: fired ? "#ef444420" : "#141f2e",
                                display: "flex", alignItems: "center", justifyContent: "center",
                                fontSize: 12, fontWeight: 700,
                                color: fired ? "#ef4444" : "#2e4257",
                              }}>
                                {fired ? "✓" : "–"}
                              </div>
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontSize: 11, color: fired ? "#e2eaf4" : "#4a6070", fontWeight: 500, marginBottom: 2 }}>{sig.label}</div>
                                <div style={{ fontSize: 10, color: "#2e4257" }}>{sig.desc}</div>
                              </div>
                              <Mono color={fired ? "#ef4444" : "#2e4257"} size={10}>{fired ? sig.weight : "0 pts"}</Mono>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })()}

                <PanelTitle>Entropy Heatmap (Click segment for Hex Dump)</PanelTitle>
                <EntropyHeatmap 
                  segments={analysis.segments} 
                  baseline={analysis.baseline} 
                  onChunkClick={(seg) => setActiveChunk(seg)}
                />
              </Panel>
            )}

            {loadingAna && (
              <Panel style={{ textAlign: "center", padding: "40px 0" }}>
                <div style={{ width: 22, height: 22, border: "2px solid #141f2e", borderTop: "2px solid #f59e0b", borderRadius: "50%", animation: "spin 0.8s linear infinite", margin: "0 auto 12px" }} />
                <Mono color="#2e4257">loading analysis...</Mono>
              </Panel>
            )}

            {!loadingAna && analysisError && (
              <Panel style={{ textAlign: "center", padding: "20px 18px", borderTop: "2px solid #ef4444" }}>
                <div style={{ fontSize: 13, color: "#ef4444", marginBottom: 6 }}>failed to load selected file analysis</div>
                <Mono color="#6b8099">{analysisError}</Mono>
              </Panel>
            )}
          </div>

          {/* Right sidebar */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {isAdmin && (
              <Panel style={{ borderTop: "2px solid #f59e0b" }}>
                <PanelTitle>System Audit Logs (MongoDB Telemetry)</PanelTitle>
                <TelemetryPanel telemetry={telemetry} />
              </Panel>
            )}

            {isAdmin && (
              <Panel>
                <PanelTitle>Detection thresholds (Admin Only)</PanelTitle>
                {[
                  { type: "TEXT", mean: 4.5, sigma: 0.4, color: "#3b82f6" },
                  { type: "PDF", mean: 7.7, sigma: 0.2, color: "#f59e0b" },
                  { type: "JPG", mean: 7.75, sigma: 0.15, color: "#10b981" },
                  { type: "PNG", mean: 7.5, sigma: 0.15, color: "#8b5cf6" },
                ].map(b => (
                  <div key={b.type} style={{ marginBottom: 14 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <Tag color={b.color}>{b.type}</Tag>
                      <Mono color={b.color} size={11}>threshold {(b.mean + b.sigma).toFixed(2)}</Mono>
                    </div>
                    <div style={{ height: 4, background: "#0d1520", borderRadius: 2, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${((b.mean / 8) * 100).toFixed(1)}%`, background: b.color + "60", borderRadius: 2 }} />
                    </div>
                  </div>
                ))}
              </Panel>
            )}

            <Panel style={{ flex: 1 }}>
              <PanelTitle>
                {isFlagged ? `Threat alerts (${analysis?.alerts?.length || 0})` : "Threat alerts"}
              </PanelTitle>
              {analysis
                ? <AlertList alerts={analysis.alerts} />
                : <Mono color="#2a3d50">select a file to view alerts</Mono>
              }
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}