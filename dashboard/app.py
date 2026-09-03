#!/usr/bin/env streamlit run
"""SIH26145 — Live dashboard.

Shows: diode topology, live packet/byte rate (from the ingest feed), running
threat score gauge, and the alert feed with model reasoning. Polls the FastAPI
service; no direct access to models.

Run: .venv/bin/streamlit run dashboard/app.py --server.port 8400
"""
import time

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

API = "http://127.0.0.1:8200"

st.set_page_config(page_title="SIH26145 — Diode IDS", layout="wide", page_icon="🛡")

st.title("AI Threat Detection across a Unidirectional Link")
st.caption("software-emulated data diode · forward-only features · hybrid detector "
           "(XGBoost known-attacks + LSTM-AE novel-threats)")

# topology strip
st.markdown(
    """
    `ns-source 10.200.0.1` ═══▶ **[ DATA DIODE ]** ═══▶ `ns-monitor 10.200.0.2` ──▶ extractor ──▶ fusion
    <sub>&nbsp;&nbsp;&nbsp;&nbsp;(no return path exists — verified zero reverse packets)</sub>
    """,
    unsafe_allow_html=True)

c1, c2 = st.columns([1, 2])
with c1:
    st.subheader("Service health")
    try:
        h = requests.get(f"{API}/health", timeout=2).json()
        st.json(h)
    except Exception as e:                              # noqa: BLE001
        st.error(f"API unreachable: {e}")
with c2:
    st.subheader("Latest verdict")
    alerts = []
    try:
        alerts = requests.get(f"{API}/recent_alerts?n=50", timeout=2).json()
    except Exception:                                   # noqa: BLE001
        pass
    if alerts:
        last = alerts[-1]
        color = {"CRITICAL": "#d62728", "HIGH": "#ff7f0e", "MEDIUM": "#bcbd22"}.get(
            last["verdict"], "#2ca02c")
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=last["threat_score"],
            title={"text": f"threat score — {last.get('predicted_label','')}" },
            gauge={"axis": {"range": [0, 1]},
                   "bar": {"color": color},
                   "steps": [{"range": [0, .25], "color": "#e8f5e9"},
                             {"range": [.25, .5], "color": "#fffde7"},
                             {"range": [.5, .75], "color": "#fff3e0"},
                             {"range": [.75, 1], "color": "#ffebee"}]}))
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("no alerts yet — start the live demo")

st.subheader("Alert feed (newest first)")
if alerts:
    rows = [{
        "time": time.strftime("%H:%M:%S", time.localtime(a["ts"])),
        "verdict": a["verdict"],
        "score": a["threat_score"],
        "label": a.get("predicted_label", ""),
        "reasons": " | ".join(a.get("reasons", [])),
        "latency_ms": a.get("latency_ms"),
    } for a in reversed(alerts)]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, height=420)
else:
    st.write("_waiting for traffic…_")

st.button("refresh")
time.sleep(1)
st.rerun() if st.session_state.get("autorefresh", True) else None
