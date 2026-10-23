import altair as alt
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime

st.set_page_config(page_title="ZT Assurance | IoT Security", page_icon="◈", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"] {font-family:'DM Sans',sans-serif;}
.stApp {background:#F4F6F8;color:#182536;}
.block-container {padding-top:1.5rem;padding-bottom:2.5rem;max-width:1500px;}
h1,h2,h3 {font-family:'Manrope',sans-serif;color:#14263D;}
h1 {font-size:2.15rem!important;letter-spacing:-.04em;}
h2 {font-size:1.35rem!important;letter-spacing:-.02em;}
h3 {font-size:1.05rem!important;}
[data-testid="stMetric"] {background:#FFFFFF;border:1px solid #DFE5EB;border-radius:9px;padding:16px 18px;box-shadow:0 2px 8px rgba(18,38,58,.025);}
[data-testid="stMetricLabel"] {color:#637286;font-size:.82rem;}
[data-testid="stMetricValue"] {color:#14263D;font-family:'Manrope',sans-serif;}
[data-testid="stMetricDelta"] {font-size:.78rem;}
div[data-testid="stTabs"] button {font-weight:600;}
div[data-testid="stTabs"] button[aria-selected="true"] {color:#087E8B;border-bottom-color:#087E8B;}
div.stButton > button {border-radius:7px;font-weight:700;min-height:2.8rem;}
div[data-testid="stAlert"] {border-radius:8px;}
section[data-testid="stSidebar"] {background:#14263D;}
section[data-testid="stSidebar"] * {color:#F3F6F9;}
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {color:#D8E1EA;}
hr {border-color:#DDE4EA;}
.eyebrow {font-size:.72rem;font-weight:800;letter-spacing:.13em;color:#087E8B;text-transform:uppercase;}
.panel {background:#FFFFFF;border:1px solid #DFE5EB;border-radius:9px;padding:18px 20px;}
.muted {color:#657487;font-size:.9rem;}
.status {font-weight:700;letter-spacing:.02em;}
</style>
""", unsafe_allow_html=True)

def section(label):
    st.markdown(f'<div class="eyebrow">{label}</div>', unsafe_allow_html=True)

st.markdown('<div class="eyebrow">CYBERSECURITY ASSURANCE OFFICE &nbsp; / &nbsp; POLICY OPERATIONS</div>', unsafe_allow_html=True)
st.title("Zero Trust Assurance Console")
st.markdown("**IoT Behavioural Risk & Access Governance**")
st.markdown('<p class="muted">Decision-support prototype for continuous device verification. Review network behaviour, inspect the policy rationale, and record simulated access decisions.</p>', unsafe_allow_html=True)

SCENARIOS = {
    "Expected camera activity": {"proto":"tcp","dest_port":443,"duration":2.4,"sent_bytes":740,"recv_bytes":3100,
        "description":"Routine encrypted web or cloud communication consistent with a common camera profile."},
    "Expected sensor heartbeat": {"proto":"udp","dest_port":123,"duration":.32,"sent_bytes":160,"recv_bytes":230,
        "description":"Small periodic message with a low data volume."},
    "Destination-port probing": {"proto":"tcp","dest_port":22,"duration":.018,"sent_bytes":92,"recv_bytes":38,
        "description":"Short connection attempt to an administrative port; potentially consistent with probing."},
    "Mirai-like traffic pattern": {"proto":"udp","dest_port":23,"duration":.06,"sent_bytes":52000,"recv_bytes":100,
        "description":"Unusual high-volume outbound traffic directed at a legacy service port."},
    "Unusual protocol and volume": {"proto":"icmp","dest_port":8080,"duration":.012,"sent_bytes":21000,"recv_bytes":25,
        "description":"Protocol, port and volume combination differs from the generated benign baseline."}
}

def model_result(row):
    # Transparent rule-based anomaly heuristic; no native ML libraries required.
    score = 0.0
    proto = str(row["proto"]).lower()
    port = int(row["dest_port"])
    duration = float(row["duration"])
    sent = float(row["sent_bytes"])
    received = float(row["recv_bytes"])

    common_ports = {53, 80, 123, 443, 1883, 8883}
    if port not in common_ports:
        score += 22
    if port in {21, 22, 23, 2323, 3389}:
        score += 22
    if duration < 0.05:
        score += 18
    if sent > 20000:
        score += 28
    elif sent > 8000:
        score += 14
    if received > 20000:
        score += 16
    if proto == "icmp" and port not in {0, 1}:
        score += 18
    if sent > 10000 and received < 100:
        score += 15

    trust = int(np.clip(96 - score, 1, 99))
    label = -1 if score >= 35 else 1
    margin = (trust - 50) / 260.0
    return label, margin, trust

def decision_for(trust, block_threshold, allow_threshold):
    if trust < block_threshold:
        return "BLOCK", "High", "Recommend deny and isolate pending investigation."
    if trust < allow_threshold:
        return "REASSESS", "Moderate", "Require additional verification and reassess behaviour."
    return "ALLOW", "Low", "Permit in this simulation while continuing verification."

if "audit" not in st.session_state:
    st.session_state.audit = []

with st.sidebar:
    st.markdown("## ZT Assurance")
    st.caption("POLICY ADMINISTRATION")
    st.markdown("---")
    st.markdown("**Decision policy**")
    block_threshold = st.slider("Block below trust score", 10, 50, 38, 1)
    allow_threshold = st.slider("Allow from trust score", 40, 90, 58, 1)
    if allow_threshold <= block_threshold:
        st.warning("Allow threshold should exceed block threshold.")
        allow_threshold = min(90, block_threshold + 1)
    st.markdown("---")
    st.markdown("**Prototype status**")
    st.markdown("Detector: transparent rule-based heuristic")
    st.markdown("Input: connection metadata")
    st.markdown("Mode: offline simulation")
    st.markdown("---")
    st.caption("No live packets are captured. No firewall rules are changed.")

def evaluate(row):
    label, margin, trust = model_result(row)
    decision, risk, action = decision_for(trust, block_threshold, allow_threshold)
    if label == -1 and decision == "ALLOW":
        # Keep the policy transparent: model anomaly can trigger reassessment.
        decision, risk, action = "REASSESS", "Moderate", "Model flagged unusual behaviour; require verification before granting continued access."
    return trust, decision, risk, action, label, margin

# Synthetic inventory for the executive dashboard.
inventory_specs = [
    ("IOT-CAM-014","IP camera","Expected camera activity"),
    ("IOT-SNS-022","Environmental sensor","Expected sensor heartbeat"),
    ("IOT-GW-008","Unknown gateway","Destination-port probing"),
    ("IOT-DEV-031","Unclassified device","Mirai-like traffic pattern"),
    ("IOT-CAM-019","IP camera","Unusual protocol and volume"),
    ("IOT-SNS-017","Environmental sensor","Expected sensor heartbeat"),
]
inventory = []
for dev, kind, scen in inventory_specs:
    row = SCENARIOS[scen]
    trust, decision, risk, action, label, margin = evaluate(row)
    inventory.append({"Device ID":dev,"Asset class":kind,"Protocol":row["proto"].upper(),
                      "Destination port":row["dest_port"],"Trust index":trust,
                      "Risk level":risk,"Policy outcome":decision})
inventory_df = pd.DataFrame(inventory)

overview, assessment, inventory_tab, governance = st.tabs([
    "Executive overview", "Device assessment", "Asset register", "Architecture & governance"
])

with overview:
    section("01 / Executive overview")
    st.subheader("Current simulated posture")
    st.markdown("A concise view of device trust and policy outcomes across the demonstration inventory.")
    m1,m2,m3,m4 = st.columns(4)
    m1.metric("Assets assessed", f"{len(inventory_df):,}", "Illustrative inventory")
    m2.metric("Block recommendations", int((inventory_df["Policy outcome"]=="BLOCK").sum()), "Threshold-based")
    m3.metric("Require reassessment", int((inventory_df["Policy outcome"]=="REASSESS").sum()), "Additional verification")
    m4.metric("Mean trust index", f'{inventory_df["Trust index"].mean():.0f}/100', "Not a probability")
    st.markdown("")
    left,right = st.columns([1.25,1])
    with left:
        st.markdown("### Trust index by device")
        st.caption("Higher values indicate closer alignment with the generated benign baseline.")
        trust_chart = alt.Chart(inventory_df).mark_bar(
            color="#4F8FEF",
            cornerRadiusTopLeft=4,
            cornerRadiusTopRight=4
        ).encode(
            x=alt.X("Device ID:N", sort=None, title=None,
                    axis=alt.Axis(labelAngle=-35, labelLimit=100)),
            y=alt.Y("Trust index:Q", title="Trust index",
                    scale=alt.Scale(domain=[0, 100])),
            tooltip=["Device ID:N", alt.Tooltip("Trust index:Q", format=".0f")]
        ).properties(
            height=280,
            background="#FFFFFF"
        ).configure_view(
            stroke=None
        ).configure_axis(
            labelColor="#475569",
            titleColor="#334155",
            gridColor="#E2E8F0",
            domainColor="#CBD5E1"
        )
        st.altair_chart(trust_chart, use_container_width=True)
    with right:
        st.markdown("### Policy distribution")
        counts = inventory_df["Policy outcome"].value_counts().reindex(["ALLOW","REASSESS","BLOCK"],fill_value=0)
        counts_df = counts.rename_axis("Policy outcome").reset_index(name="Devices")
        policy_chart = alt.Chart(counts_df).mark_bar(
            cornerRadiusTopLeft=4,
            cornerRadiusTopRight=4
        ).encode(
            x=alt.X("Policy outcome:N", title=None,
                    axis=alt.Axis(labelAngle=0)),
            y=alt.Y("Devices:Q", title="Number of devices",
                    scale=alt.Scale(domain=[0, max(1, int(counts.max()))])),
            color=alt.Color(
                "Policy outcome:N",
                scale=alt.Scale(
                    domain=["ALLOW", "REASSESS", "BLOCK"],
                    range=["#16A34A", "#F59E0B", "#DC2626"]
                ),
                legend=None
            ),
            tooltip=["Policy outcome:N", "Devices:Q"]
        ).properties(
            height=280,
            background="#FFFFFF"
        ).configure_view(
            stroke=None
        ).configure_axis(
            labelColor="#475569",
            titleColor="#334155",
            gridColor="#E2E8F0",
            domainColor="#CBD5E1"
        )
        st.altair_chart(policy_chart, use_container_width=True)
        st.markdown('<div class="panel"><b>Interpretation</b><p class="muted">The policy outcome is a decision recommendation based on the trust index and configured thresholds. It is not evidence that a device is definitively compromised.</p></div>', unsafe_allow_html=True)
    st.markdown("### Priority review queue")
    queue = inventory_df[inventory_df["Policy outcome"] != "ALLOW"].copy()
    if queue.empty:
        st.success("No assets currently require policy review under these settings.")
    else:
        st.dataframe(queue, use_container_width=True, hide_index=True)
    st.caption("All devices and traffic shown here are generated demonstration records. Replace them with prepared IoT-23 connection records for an empirical evaluation.")

with assessment:
    section("02 / Device assessment")
    st.subheader("Evaluate a connection record")
    st.markdown("Inspect the feature vector, run the anomaly detector, and review the corresponding policy rationale.")
    scenario_name = st.selectbox("Scenario profile", list(SCENARIOS.keys()))
    preset = SCENARIOS[scenario_name]
    st.info(preset["description"])
    a,b = st.columns(2)
    with a:
        device_id = st.text_input("Device identifier", "IOT-DEMO-001")
        proto = st.selectbox("Transport protocol", ["tcp","udp","icmp"], index=["tcp","udp","icmp"].index(preset["proto"]))
        port = st.number_input("Destination port", 1, 65535, int(preset["dest_port"]))
    with b:
        duration = st.number_input("Connection duration (seconds)", min_value=.001, max_value=100000.0, value=float(preset["duration"]), format="%.3f")
        sent = st.number_input("Bytes sent by device", min_value=0, max_value=1000000000, value=int(preset["sent_bytes"]))
        received = st.number_input("Bytes received by device", min_value=0, max_value=1000000000, value=int(preset["recv_bytes"]))
    if st.button("Run policy assessment", type="primary", use_container_width=True):
        row = {"proto":proto,"dest_port":int(port),"duration":float(duration),
               "sent_bytes":float(sent),"recv_bytes":float(received)}
        trust, decision, risk, action, label, margin = evaluate(row)
        event = {"Timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "Device ID":device_id or "UNNAMED","Protocol":proto.upper(),"Destination port":int(port),
                 "Duration (s)":duration,"Bytes sent":int(sent),"Bytes received":int(received),
                 "Trust index":trust,"Risk":risk,"Policy outcome":decision,
                 "Model flag":"Anomaly" if label == -1 else "Within baseline"}
        st.session_state.audit.insert(0,event)
        x,y,z = st.columns(3)
        x.metric("Trust index",f"{trust}/100")
        y.metric("Model assessment","Anomaly" if label == -1 else "Within baseline")
        z.metric("Policy outcome",decision)
        st.progress(trust/100, text=f"Behavioural trust index: {trust}/100")
        if decision == "BLOCK":
            st.error("BLOCK RECOMMENDATION — " + action)
        elif decision == "REASSESS":
            st.warning("REASSESS RECOMMENDATION — " + action)
        else:
            st.success("ALLOW RECOMMENDATION — " + action)
        with st.expander("Technical explanation", expanded=True):
            st.markdown(f"- **Features evaluated:** protocol `{proto.upper()}`, destination port `{int(port)}`, duration `{duration:.3f}s`, sent `{int(sent):,}` bytes, received `{int(received):,}` bytes.")
            st.markdown(f"- **Rule-based detector output:** `{'anomaly pattern' if label == -1 else 'within configured heuristics'}`.")
            st.markdown(f"- **Decision function margin:** `{margin:.4f}`. This is model-specific and is not a probability.")
            st.markdown(f"- **Policy rationale:** {action}")
            st.markdown("- **Operational status:** simulated recommendation only; no actual device access is changed.")
    if st.session_state.audit:
        st.markdown("### Assessment audit trail")
        audit_df = pd.DataFrame(st.session_state.audit)
        st.dataframe(audit_df, use_container_width=True, hide_index=True)
        st.download_button("Export audit trail (.csv)", audit_df.to_csv(index=False).encode("utf-8"),
                           "zt_assessment_audit.csv", "text/csv")

with inventory_tab:
    section("03 / Asset register")
    st.subheader("Registered demonstration assets")
    filter_value = st.selectbox("Filter by policy outcome", ["All outcomes","ALLOW","REASSESS","BLOCK"])
    view = inventory_df if filter_value == "All outcomes" else inventory_df[inventory_df["Policy outcome"] == filter_value]
    st.dataframe(view, use_container_width=True, hide_index=True)
    st.download_button("Export asset register (.csv)", inventory_df.to_csv(index=False).encode("utf-8"),
                       "zt_asset_register.csv", "text/csv")
    st.markdown("### Register interpretation")
    st.markdown("""
    - **Trust index:** a human-readable index derived from the model's decision margin.
    - **Risk level:** a simplified label for prototype review.
    - **Policy outcome:** a configurable decision recommendation, not an enforcement action.
    """)

with governance:
    section("04 / Architecture & governance")
    st.subheader("Decision path")
    stages = [
        ("01","IoT endpoint","A camera, sensor or gateway produces network activity."),
        ("02","Policy Enforcement Point (PEP)","A real deployment would collect connection metadata at an authorized gateway."),
        ("03","AI Policy Engine","Isolation Forest compares the metadata against a benign behavioural baseline."),
        ("04","Policy Administrator (PA)","Configured thresholds translate the trust index into ALLOW, REASSESS or BLOCK."),
        ("05","Audit & review","Decision context is recorded for security review and later model evaluation.")
    ]
    for number,title,desc in stages:
        st.markdown(f'<div class="panel" style="margin-bottom:10px;"><span class="eyebrow">{number}</span><br><b>{title}</b><p class="muted">{desc}</p></div>',unsafe_allow_html=True)
    st.markdown("### Feature set aligned with the report")
    st.dataframe(pd.DataFrame([
        {"Feature":"Protocol","Example":"TCP / UDP / ICMP","Purpose":"Connection behaviour"},
        {"Feature":"Destination port","Example":"443 / 22 / 23","Purpose":"Service access pattern"},
        {"Feature":"Duration","Example":"Seconds","Purpose":"Connection timing"},
        {"Feature":"Bytes sent","Example":"Source-to-destination volume","Purpose":"Outbound behaviour"},
        {"Feature":"Bytes received","Example":"Destination-to-source volume","Purpose":"Inbound behaviour"},
    ]), use_container_width=True, hide_index=True)
    st.markdown("### Validation and limitations")
    st.warning("This fallback uses a rule-based heuristic for demonstration, not Isolation Forest or IoT-23 benchmark results. Do not present its scores as validated research performance.")
    st.markdown("""
    **To move from demonstration to research validation:**
    1. Load and clean labelled IoT-23 connection logs.
    2. Fit the detector using benign training records only.
    3. Evaluate on a separate labelled test set containing benign and malicious records.
    4. Report confusion matrix, precision, recall, F1-score and false-positive rate.
    5. Measure inference latency before proposing gateway deployment.

    **Security boundary:** no live packet capture, quarantine, firewall change, or production access control is implemented here.
    """)

st.markdown("---")
foot1,foot2 = st.columns([3,1])
with foot1:
    st.caption("ZT ASSURANCE CONSOLE  •  ACADEMIC PROOF OF CONCEPT  •  SIMULATION MODE")
with foot2:
    st.caption("Policy status: DEMONSTRATION")
