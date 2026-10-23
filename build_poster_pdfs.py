import os
import base64
import subprocess

BASE_DIR = r"c:\wamp64\www\soc-chess"
ASSETS_DIR = os.path.join(BASE_DIR, "poster_assets")
EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

def get_b64(filename):
    path = os.path.join(ASSETS_DIR, filename)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return "data:image/png;base64," + base64.b64encode(f.read()).decode("utf-8")
    return ""

# Load all images as base64 for 100% self-contained offline rendering
img_fig1 = get_b64("fig1_model_comparison.png")
img_fig2 = get_b64("fig2_neural_loss_curve.png")
img_fig3 = get_b64("fig3_feature_importance.png")
img_fig4 = get_b64("fig4_confusion_matrix.png")
img_fig5 = get_b64("fig5_system_architecture.png")
img_page2 = get_b64("page2_ai_alerts.png")
img_page3 = get_b64("page3_incident_response.png")

# ==============================================================================
# 1. BUILD PORTRAIT POSTER (EXACT STYLE OF PAGE 3 IN GUIDELINES)
# ==============================================================================
html_portrait = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SOC CHESS - Academic Poster (Portrait A2)</title>
<style>
@page {{
    size: 420mm 594mm;
    margin: 0;
}}
* {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}
body {{
    width: 420mm;
    height: 594mm;
    background: #ffffff;
    font-family: 'Cambria', Georgia, serif;
    color: #111111;
    padding: 10mm 12mm;
    position: relative;
    overflow: hidden;
}}

/* HEADER BAR */
.header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2.5px solid #222222;
    padding-bottom: 7mm;
    margin-bottom: 7mm;
}}
.logo-left {{
    width: 75mm;
    display: flex;
    align-items: center;
    gap: 12px;
}}
.ppsu-badge {{
    display: flex;
    flex-direction: column;
}}
.ppsu-emblem {{
    font-size: 24pt;
    font-weight: bold;
    color: #b22222;
    letter-spacing: 1px;
    line-height: 1.1;
}}
.ppsu-sub {{
    font-size: 11pt;
    font-weight: bold;
    color: #333333;
    letter-spacing: 0.5px;
}}
.naac-tag {{
    display: inline-block;
    background: #a91d22;
    color: #ffffff;
    font-size: 8.5pt;
    font-weight: bold;
    padding: 2px 7px;
    border-radius: 4px;
    margin-top: 4px;
    text-align: center;
    width: fit-content;
}}
.header-center {{
    text-align: center;
    flex: 1;
    padding: 0 10mm;
}}
.poster-title {{
    font-size: 34pt;
    font-weight: bold;
    color: #111111;
    line-height: 1.18;
    margin-bottom: 4mm;
}}
.poster-authors {{
    font-size: 16pt;
    font-weight: bold;
    color: #222222;
    margin-bottom: 2mm;
}}
.author-sup {{
    font-size: 10pt;
    vertical-align: super;
}}
.poster-affil {{
    font-size: 12pt;
    color: #444444;
    line-height: 1.3;
}}
.logo-right {{
    width: 65mm;
    text-align: right;
}}
.school-badge {{
    background: #43a047;
    color: #ffffff;
    padding: 9px 16px;
    border-radius: 6px;
    display: inline-block;
    text-align: left;
    box-shadow: 0 2px 5px rgba(0,0,0,0.15);
}}
.school-badge .school-title {{
    font-size: 15pt;
    font-weight: normal;
    display: block;
    line-height: 1.1;
}}
.school-badge .school-name {{
    font-size: 22pt;
    font-weight: bold;
    display: block;
    line-height: 1.1;
}}

/* 3-COLUMN MASONRY GRID */
.grid-container {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    column-gap: 8mm;
    height: 520mm;
}}
.col {{
    display: flex;
    flex-direction: column;
    gap: 5mm;
}}

/* SECTION BOX STYLES */
.section-pill {{
    background: #b22222;
    color: #ffffff;
    font-size: 19pt;
    font-weight: bold;
    padding: 4px 18px;
    border-radius: 18px;
    display: inline-block;
    margin-bottom: 3.5mm;
    letter-spacing: 0.5px;
}}
.content-box {{
    font-size: 13.5pt;
    line-height: 1.34;
    color: #1a1a1a;
    text-align: justify;
}}
.content-box p {{
    margin-bottom: 3mm;
}}
ul.poster-list {{
    list-style: none;
    padding-left: 0;
    margin-bottom: 3mm;
}}
ul.poster-list li {{
    position: relative;
    padding-left: 16px;
    margin-bottom: 2.5mm;
}}
ul.poster-list li::before {{
    content: "○";
    position: absolute;
    left: 0;
    color: #b22222;
    font-weight: bold;
    font-size: 13pt;
}}

/* EQUATION BOX */
.equation-card {{
    background: #fbfbfb;
    border: 1px solid #dcdcdc;
    border-left: 4px solid #b22222;
    padding: 3mm 4mm;
    margin: 3mm 0;
    font-family: 'Cambria Math', Cambria, serif;
    font-size: 12.5pt;
    text-align: center;
    border-radius: 4px;
}}

/* FIGURE STYLING */
.figure-wrapper {{
    background: #ffffff;
    border: 1px solid #e0e0e0;
    border-radius: 5px;
    padding: 2.5mm;
    margin: 2mm 0;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}}
.figure-wrapper img {{
    width: 100%;
    display: block;
    border-radius: 3px;
}}
.fig-caption {{
    font-size: 10.5pt;
    color: #333333;
    line-height: 1.25;
    margin-top: 2mm;
    text-align: left;
    font-style: normal;
}}
.fig-caption strong {{
    color: #111111;
}}

/* BENCHMARK TABLE */
.bench-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 11pt;
    margin: 2.5mm 0;
}}
.bench-table th, .bench-table td {{
    border: 1px solid #cccccc;
    padding: 4px 6px;
    text-align: center;
}}
.bench-table th {{
    background: #f0f0f0;
    color: #111111;
    font-weight: bold;
}}
.bench-table tr:nth-child(even) {{
    background: #fafafa;
}}
.bench-table td.model-name {{
    text-align: left;
    font-weight: bold;
}}

/* REFERENCES BOX */
.ref-box {{
    font-size: 9.5pt;
    line-height: 1.25;
    color: #444444;
}}
.ref-box ol {{
    padding-left: 14px;
}}
.ref-box li {{
    margin-bottom: 1.5mm;
}}
</style>
</head>
<body>

<!-- HEADER SECTION -->
<div class="header">
    <div class="logo-left">
        <div class="ppsu-badge">
            <span class="ppsu-emblem">PPSU</span>
            <span class="ppsu-sub">P P SAVANI UNIVERSITY</span>
            <span class="naac-tag">NAAC A+ ACCREDITED</span>
        </div>
    </div>
    <div class="header-center">
        <div class="poster-title">SOC CHESS: Intelligent Real-Time Security Operations & AI Threat Detection Platform</div>
        <div class="poster-authors">Sai<span class="author-sup">1</span>, [Faculty Guide Name]<span class="author-sup">2</span></div>
        <div class="poster-affil">
            1. Student, B.Tech Computer Engineering (Enrollment: 23SE02CB014)<br>
            2. Department of Computer Science & Engineering, School of Engineering, P. P. Savani University, Surat, Gujarat
        </div>
    </div>
    <div class="logo-right">
        <div class="school-badge">
            <span class="school-title">School of</span>
            <span class="school-name">Engineering</span>
        </div>
    </div>
</div>

<!-- 3-COLUMN CONTENT GRID -->
<div class="grid-container">

    <!-- COLUMN 1: INTRODUCTION & TELEMETRY INGESTION -->
    <div class="col">
        <div>
            <div class="section-pill">Introduction</div>
            <div class="content-box">
                <ul class="poster-list">
                    <li><strong>Modern SOC Bottlenecks:</strong> Enterprise analysts face alert fatigue with 70%+ false positives, siloed network PCAP streams, and disconnected SIEM log indexes.</li>
                    <li><strong>Research Objective:</strong> Architect a local-first cybersecurity platform combining real-time packet capture, enterprise SIEM queries, and dual-tier machine learning.</li>
                    <li><strong>Mathematical Risk Formulation:</strong> Multi-factor risk engine synthesizes ML attack probability, failed attempt counts, and target asset value:</li>
                </ul>
                <div class="equation-card">
                    <em>Risk Score</em> = min(100.0, <em>P</em>(Attack) × 80 + ∑<em>w<sub>i</sub></em>·Severity<sub><em>i</em></sub> + AssetWeight)
                </div>
                <ul class="poster-list">
                    <li>Dynamic thresholds: <strong>Low</strong> (0–39), <strong>Medium</strong> (40–69), <strong>High</strong> (70–89), and <strong>Critical</strong> (90–100).</li>
                </ul>
            </div>
        </div>

        <div>
            <div class="section-pill">Methodology & Architecture</div>
            <div class="content-box">
                <ul class="poster-list">
                    <li><strong>Telemetry Ingestion:</strong> Continuous packet capture via TShark CLI / Wireshark (`socchess://`) plus Splunk Enterprise REST API (Port 8089).</li>
                    <li><strong>Big Data Streaming:</strong> Apache Spark 3.5.3 normalizes 12 raw log formats across 3,708 dataset files (CIC-IDS, UNSW-NB15, KDD-99).</li>
                </ul>
                
                <div class="figure-wrapper">
                    <img src="{img_fig5}" alt="System Architecture">
                    <div class="fig-caption"><strong>Figure 1.</strong> High-level system architecture of the SOC CHESS platform: Ingestion, Spark feature extraction, dual-tier ML, and SOAR containment.</div>
                </div>

                <ul class="poster-list">
                    <li><strong>19 Canonical Features:</strong> Extracted flow rates, packet lengths, TCP flags (SYN, ACK, PSH, FIN, RST), and window sizes.</li>
                    <li><strong>Pre-processing:</strong> Symmetrical Log1p smoothing <em>x' = ln(1 + |x|)</em> and Z-score standardization.</li>
                </ul>

                <div class="figure-wrapper">
                    <img src="{img_fig3}" alt="Feature Importance">
                    <div class="fig-caption"><strong>Figure 2.</strong> Top 10 canonical flow features ranked by information gain in detecting malicious network traffic.</div>
                </div>
            </div>
        </div>
    </div>

    <!-- COLUMN 2: DUAL-TIER ML & MODEL BENCHMARKS -->
    <div class="col">
        <div>
            <div class="section-pill">Dual-Tier AI Detection Engine</div>
            <div class="content-box">
                <ul class="poster-list">
                    <li><strong>Tier 1 (Real-Time Stream):</strong> 3-Layer Multi-Layer Perceptron (128 → 64 → 32 ReLU + Softmax) operating at <strong>&lt; 1.2 ms</strong> latency per event.</li>
                    <li><strong>Tier 2 (Batch Champion):</strong> Scikit-Learn Random Forest (200 trees) + XGBoost achieving <strong>99.39% accuracy</strong>.</li>
                </ul>

                <div class="figure-wrapper">
                    <img src="{img_fig1}" alt="Model Comparison">
                    <div class="fig-caption"><strong>Figure 3.</strong> Comparative detection accuracy, weighted F1-score, and ROC-AUC across all four operational model pipelines.</div>
                </div>

                <table class="bench-table">
                    <thead>
                        <tr>
                            <th>Pipeline</th>
                            <th>Algorithm</th>
                            <th>Acc (%)</th>
                            <th>F1 (%)</th>
                            <th>ROC-AUC</th>
                            <th>Latency</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td class="model-name">Network Batch</td>
                            <td>Random Forest</td>
                            <td>99.39%</td>
                            <td>99.39%</td>
                            <td>0.9991</td>
                            <td>0.42 ms</td>
                        </tr>
                        <tr>
                            <td class="model-name">Network Secondary</td>
                            <td>XGBoost</td>
                            <td>99.37%</td>
                            <td>99.37%</td>
                            <td>0.9988</td>
                            <td>0.48 ms</td>
                        </tr>
                        <tr>
                            <td class="model-name">Real-Time Stream</td>
                            <td>3-Layer MLP</td>
                            <td>98.20%</td>
                            <td>98.10%</td>
                            <td>0.9920</td>
                            <td>0.85 ms</td>
                        </tr>
                        <tr>
                            <td class="model-name">Security Logs</td>
                            <td>Log RF Classifier</td>
                            <td>91.86%</td>
                            <td>91.03%</td>
                            <td>0.9540</td>
                            <td>1.10 ms</td>
                        </tr>
                    </tbody>
                </table>

                <div class="figure-wrapper">
                    <img src="{img_fig2}" alt="Loss Curve">
                    <div class="fig-caption"><strong>Figure 4.</strong> Training loss convergence curve of the real-time neural network over 24 epochs using Adam optimization.</div>
                </div>

                <div class="figure-wrapper">
                    <img src="{img_fig4}" alt="Confusion Matrix">
                    <div class="fig-caption"><strong>Figure 5.</strong> Confusion matrix across 22,501 test instances showing robust multi-class separation of DoS, Botnets, and Port Scans.</div>
                </div>
            </div>
        </div>
    </div>

    <!-- COLUMN 3: RESULTS, SOAR AUTOMATION & CONCLUSION -->
    <div class="col">
        <div>
            <div class="section-pill">SOAR & Live Verification</div>
            <div class="content-box">
                <ul class="poster-list">
                    <li><strong>4-Tier Cascading LLM Gateway:</strong> NVIDIA NIM (Llama-3.2) → OpenAI GPT-4o → Google Gemini → Local Deterministic Rule Fallback.</li>
                    <li><strong>Auto Firewall Containment:</strong> Dynamically generates OS-specific mitigation scripts (Linux <code>iptables DROP</code>, Windows <code>netsh advfirewall</code>).</li>
                </ul>

                <div class="figure-wrapper">
                    <img src="{img_page2}" alt="AI Alerts Console">
                    <div class="fig-caption"><strong>Figure 6.</strong> React 18 Glassmorphic SOC Console: Live threat radar, continuous risk scoring, and MITRE ATT&CK kill-chain mapper.</div>
                </div>

                <div class="figure-wrapper">
                    <img src="{img_page3}" alt="SOAR Playbook">
                    <div class="fig-caption"><strong>Figure 7.</strong> 5-Stage SOAR Incident Response Playbook executing dynamic firewall script isolation on active threat IP.</div>
                </div>
            </div>
        </div>

        <div>
            <div class="section-pill">Conclusions</div>
            <div class="content-box">
                <ul class="poster-list">
                    <li><strong>Unified Telemetry:</strong> Successfully bridged live PCAP dissection and enterprise SIEM indexes into a synchronized command center.</li>
                    <li><strong>Exceptional Precision:</strong> Champion Random Forest achieved <strong>99.39% accuracy</strong> and MLP achieved <strong>&lt; 1.2 ms</strong> latency, effectively solving alert fatigue.</li>
                    <li><strong>Future Work:</strong> Integrate kernel-level <strong>eBPF / DPDK</strong> for 10Gbps line-rate packet capture and Graph Neural Networks (GNNs) for Active Directory attack graphs.</li>
                </ul>
            </div>
        </div>

        <div>
            <div class="section-pill">References</div>
            <div class="ref-box">
                <ol>
                    <li>Sharafaldin, I., et al. "Toward Generating a New Intrusion Detection Dataset (CIC-IDS2017)", ICISSP, 2018.</li>
                    <li>Moustafa, N., & Slay, J. "UNSW-NB15: Network Intrusion Detection Dataset", IEEE MilCIS, 2015.</li>
                    <li>MITRE Corporation. "MITRE ATT&CK Enterprise Matrix", attack.mitre.org, 2024.</li>
                    <li>Pedregosa, F., et al. "Scikit-learn: Machine Learning in Python", JMLR, 2011.</li>
                    <li>Zaharia, M., et al. "Apache Spark: Unified Big Data Engine", CACM, 2016.</li>
                </ol>
            </div>
        </div>
    </div>

</div>

</body>
</html>"""

# ==============================================================================
# 2. BUILD LANDSCAPE POSTER (EXACT 8-CARD STYLE OF PAGE 4 TEMPLATE)
# ==============================================================================
html_landscape = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SOC CHESS - Academic Poster (Landscape A2)</title>
<style>
@page {{
    size: 594mm 420mm;
    margin: 0;
}}
* {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}
body {{
    width: 594mm;
    height: 420mm;
    background: #f4f6f8;
    font-family: 'Cambria', Georgia, serif;
    color: #111111;
    padding: 10mm 12mm;
    overflow: hidden;
}}

/* HEADER */
.header {{
    background: #ffffff;
    border-radius: 8px;
    padding: 6mm 10mm;
    margin-bottom: 6mm;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 6px rgba(0,0,0,0.08);
}}
.ppsu-emblem {{
    font-size: 26pt;
    font-weight: bold;
    color: #b22222;
}}
.ppsu-sub {{
    font-size: 11pt;
    font-weight: bold;
    color: #333;
}}
.naac-tag {{
    background: #a91d22;
    color: #ffffff;
    font-size: 8.5pt;
    font-weight: bold;
    padding: 2px 7px;
    border-radius: 4px;
    display: inline-block;
    margin-top: 3px;
}}
.header-center {{
    text-align: center;
    flex: 1;
    padding: 0 10mm;
}}
.poster-title {{
    font-size: 30pt;
    font-weight: bold;
    color: #111111;
    line-height: 1.15;
    margin-bottom: 2mm;
}}
.poster-authors {{
    font-size: 15pt;
    font-weight: bold;
    color: #333333;
}}
.poster-affil {{
    font-size: 11.5pt;
    color: #555555;
}}
.school-badge {{
    background: #43a047;
    color: #ffffff;
    padding: 8px 16px;
    border-radius: 6px;
    text-align: left;
}}
.school-badge .school-title {{ font-size: 14pt; }}
.school-badge .school-name {{ font-size: 20pt; font-weight: bold; }}

/* 8-CARD GRID LAYOUT (Page 4 Template) */
.card-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    grid-template-rows: 1fr 1fr;
    gap: 6mm;
    height: 330mm;
}}
.card {{
    background: #ffffff;
    border-radius: 8px;
    padding: 5mm;
    box-shadow: 0 2px 5px rgba(0,0,0,0.06);
    display: flex;
    flex-direction: column;
    overflow: hidden;
}}
.card-header {{
    font-size: 18pt;
    font-weight: bold;
    color: #1e3a8a;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 2mm;
    margin-bottom: 3mm;
}}
.card-body {{
    font-size: 11.5pt;
    line-height: 1.32;
    color: #222222;
    flex: 1;
    overflow: hidden;
}}
.card-body p {{
    margin-bottom: 2mm;
}}
ul.card-list {{
    list-style: none;
    padding-left: 0;
}}
ul.card-list li {{
    position: relative;
    padding-left: 14px;
    margin-bottom: 1.8mm;
}}
ul.card-list li::before {{
    content: "■";
    position: absolute;
    left: 0;
    color: #2563eb;
    font-size: 8pt;
    top: 2px;
}}
.figure-landscape {{
    margin-top: 2mm;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    padding: 1.5mm;
    background: #fafafa;
}}
.figure-landscape img {{
    width: 100%;
    display: block;
    border-radius: 3px;
}}
.fig-cap {{
    font-size: 9pt;
    color: #475569;
    margin-top: 1.5mm;
    line-height: 1.2;
}}
table.l-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 9.5pt;
    margin: 2mm 0;
}}
table.l-table th, table.l-table td {{
    border: 1px solid #cbd5e1;
    padding: 3px 5px;
    text-align: center;
}}
table.l-table th {{
    background: #f1f5f9;
    font-weight: bold;
}}
</style>
</head>
<body>

<div class="header">
    <div>
        <div class="ppsu-emblem">PPSU</div>
        <div class="ppsu-sub">P P SAVANI UNIVERSITY</div>
        <span class="naac-tag">NAAC A+ ACCREDITED</span>
    </div>
    <div class="header-center">
        <div class="poster-title">SOC CHESS: Intelligent Real-Time Security Operations & AI Threat Detection Platform</div>
        <div class="poster-authors">Sai (Enrollment: 23SE02CB014) | Guide: [Faculty Mentor Name]</div>
        <div class="poster-affil">Department of Computer Science & Engineering, School of Engineering, P. P. Savani University</div>
    </div>
    <div class="school-badge">
        <div class="school-title">School of</div>
        <div class="school-name">Engineering</div>
    </div>
</div>

<div class="card-grid">

    <!-- CARD 1: ABSTRACT -->
    <div class="card">
        <div class="card-header">1. Abstract</div>
        <div class="card-body">
            <p>Modern enterprise SOCs face severe alert fatigue and fragmented telemetry. <strong>SOC CHESS</strong> is a local-first cybersecurity platform combining real-time packet inspection (Wireshark/TShark), enterprise log search (Splunk REST API), Apache Spark Big Data streaming, and dual-tier machine learning.</p>
            <p>Achieving <strong>99.39% accuracy</strong> and <strong>&lt; 1.2 ms latency</strong>, the platform automates threat categorization across the MITRE ATT&CK matrix and synthesizes active firewall containment scripts.</p>
            <div class="figure-landscape">
                <img src="{img_fig1}" alt="Model Benchmarks">
                <div class="fig-cap"><strong>Figure 1.</strong> Accuracy, F1, and ROC-AUC benchmarks across models.</div>
            </div>
        </div>
    </div>

    <!-- CARD 2: INTRODUCTION -->
    <div class="card">
        <div class="card-header">2. Introduction & Objectives</div>
        <div class="card-body">
            <ul class="card-list">
                <li><strong>Alert Fatigue:</strong> Over 70% of SOC alerts are false positives.</li>
                <li><strong>Data Silos:</strong> Network packets and host logs reside in disconnected systems, delaying critical incident response.</li>
                <li><strong>Project Objectives:</strong>
                    <ul>
                        <li>Unify TShark packet stream with Splunk REST queries.</li>
                        <li>Standardize 12 log formats into 19 canonical features.</li>
                        <li>Deploy sub-millisecond MLP neural net for live triage.</li>
                        <li>Synthesize instant firewall containment scripts via LLM.</li>
                    </ul>
                </li>
            </ul>
            <div class="figure-landscape">
                <img src="{img_fig3}" alt="Feature Importance">
                <div class="fig-cap"><strong>Figure 2.</strong> Top features in malicious flow detection.</div>
            </div>
        </div>
    </div>

    <!-- CARD 3: MATERIALS & DATASETS -->
    <div class="card">
        <div class="card-header">3. Materials & Big Data</div>
        <div class="card-body">
            <ul class="card-list">
                <li><strong>Dataset Scale:</strong> 3,708 files (~8.1 GB) combining CIC-IDS-2017, CSE-CIC-IDS2018, UNSW-NB15, and Splunk Attack Logs.</li>
                <li><strong>Big Data Engine:</strong> Apache Spark 3.5.3 (PySpark structured streaming, 8 partitions).</li>
                <li><strong>Hardware & Ports:</strong> Local FastAPI server (:8001), Splunk (:8089), MySQL (:3306), React UI (:5173).</li>
            </ul>
            <div class="figure-landscape">
                <img src="{img_fig2}" alt="Loss Curve">
                <div class="fig-cap"><strong>Figure 3.</strong> Neural network loss convergence (Adam optimizer).</div>
            </div>
        </div>
    </div>

    <!-- CARD 4: METHODOLOGY -->
    <div class="card">
        <div class="card-header">4. Methodology & Architecture</div>
        <div class="card-body">
            <div class="figure-landscape">
                <img src="{img_fig5}" alt="System Architecture">
                <div class="fig-cap"><strong>Figure 4.</strong> 5-Layer end-to-end processing pipeline.</div>
            </div>
            <ul class="card-list" style="margin-top: 2mm;">
                <li><strong>Dual-Tier ML:</strong> 3-Layer MLP (128-64-32) + Random Forest (200 trees).</li>
                <li><strong>Risk Score Formula:</strong> min(100.0, P(Attack)*80 + ∑w_i*Sev_i + AssetWeight).</li>
            </ul>
        </div>
    </div>

    <!-- CARD 5: RESULTS & DISCUSSION -->
    <div class="card">
        <div class="card-header">5. Results & Discussion</div>
        <div class="card-body">
            <table class="l-table">
                <thead>
                    <tr><th>Model</th><th>Acc</th><th>F1</th><th>ROC</th><th>Latency</th></tr>
                </thead>
                <tbody>
                    <tr><td><strong>Network RF</strong></td><td>99.39%</td><td>99.39%</td><td>0.9991</td><td>0.42 ms</td></tr>
                    <tr><td><strong>XGBoost</strong></td><td>99.37%</td><td>99.37%</td><td>0.9988</td><td>0.48 ms</td></tr>
                    <tr><td><strong>3-Layer MLP</strong></td><td>98.20%</td><td>98.10%</td><td>0.9920</td><td>0.85 ms</td></tr>
                    <tr><td><strong>Security Log</strong></td><td>91.86%</td><td>91.03%</td><td>0.9540</td><td>1.10 ms</td></tr>
                </tbody>
            </table>
            <div class="figure-landscape">
                <img src="{img_fig4}" alt="Confusion Matrix">
                <div class="fig-cap"><strong>Figure 5.</strong> Confusion matrix across 22,501 test instances.</div>
            </div>
        </div>
    </div>

    <!-- CARD 6: CONCLUSION -->
    <div class="card">
        <div class="card-header">6. Conclusion & SOAR Verification</div>
        <div class="card-body">
            <p><strong>Proven Defense:</strong> Successfully mitigated volumetric DDoS (Risk 100/100) and reverse shell intrusions in sub-second timelines.</p>
            <div class="figure-landscape">
                <img src="{img_page2}" alt="AI Alerts Console">
                <div class="fig-cap"><strong>Figure 6.</strong> React SOC command console with threat radar.</div>
            </div>
        </div>
    </div>

    <!-- CARD 7: RECOMMENDATIONS -->
    <div class="card">
        <div class="card-header">7. Recommendations & Future Scope</div>
        <div class="card-body">
            <ul class="card-list">
                <li><strong>Kernel-Level Ingestion:</strong> Migrate packet sniffing to eBPF / DPDK for 10 Gbps+ line rates.</li>
                <li><strong>Graph AI:</strong> Implement Graph Neural Networks (GNN) for Active Directory lateral movement tracking.</li>
                <li><strong>Decentralized CTI:</strong> Ingest automated STIX/TAXII threat intelligence feeds.</li>
            </ul>
            <div class="figure-landscape">
                <img src="{img_page3}" alt="SOAR Containment">
                <div class="fig-cap"><strong>Figure 7.</strong> Automated SOAR firewall script generation.</div>
            </div>
        </div>
    </div>

    <!-- CARD 8: ACKNOWLEDGEMENTS -->
    <div class="card">
        <div class="card-header">8. References & Acknowledgements</div>
        <div class="card-body">
            <p><strong>References:</strong></p>
            <ol style="padding-left: 12px; font-size: 8.5pt; line-height: 1.25; color: #475569;">
                <li>Sharafaldin et al. (2018), "CIC-IDS2017 Dataset", ICISSP.</li>
                <li>Moustafa & Slay (2015), "UNSW-NB15 Dataset", IEEE MilCIS.</li>
                <li>MITRE Corporation (2024), "ATT&CK Enterprise Matrix".</li>
            </ol>
            <p style="margin-top: 3mm;"><strong>Acknowledgements:</strong></p>
            <p style="font-size: 8.5pt; color: #475569;">We thank <strong>P. P. Savani University</strong>, School of Engineering, and Department of Computer Science & Engineering for their academic guidance and high-performance computing facilities.</p>
        </div>
    </div>

</div>

</body>
</html>"""

# Write HTML files
portrait_html_path = os.path.join(ASSETS_DIR, "poster_portrait.html")
landscape_html_path = os.path.join(ASSETS_DIR, "poster_landscape.html")

with open(portrait_html_path, "w", encoding="utf-8") as f:
    f.write(html_portrait)
print(f"[OK] Wrote {portrait_html_path}")

with open(landscape_html_path, "w", encoding="utf-8") as f:
    f.write(html_landscape)
print(f"[OK] Wrote {landscape_html_path}")

# Output PDF paths
portrait_pdf_path = os.path.join(BASE_DIR, "SOC_CHESS_POSTER_PORTRAIT.pdf")
landscape_pdf_path = os.path.join(BASE_DIR, "SOC_CHESS_POSTER_LANDSCAPE.pdf")

# Generate Portrait PDF via Edge headless
print("Generating Portrait A2 PDF...")
subprocess.run([
    EDGE_PATH,
    "--headless",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    f"--print-to-pdf={portrait_pdf_path}",
    "--no-pdf-header-footer",
    f"file:///{portrait_html_path.replace(os.sep, '/')}"
], check=True)
print(f"[SUCCESS] Created Portrait PDF: {portrait_pdf_path}")

# Generate Landscape PDF via Edge headless
print("Generating Landscape A2 PDF...")
subprocess.run([
    EDGE_PATH,
    "--headless",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    f"--print-to-pdf={landscape_pdf_path}",
    "--no-pdf-header-footer",
    f"file:///{landscape_html_path.replace(os.sep, '/')}"
], check=True)
print(f"[SUCCESS] Created Landscape PDF: {landscape_pdf_path}")
