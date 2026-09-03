#!/usr/bin/env python3
"""SIH26145 — FastAPI inference service.

Endpoints:
  GET  /health          model/artifact status
  POST /score           full-pipeline scoring of ONE window
                        {features: {...}, sequence?: [[...], ...]}
                        -> threat score + verdict + reasons (+ latency)
  POST /score_batch     list version
  GET  /recent_alerts   last N alert rows for the dashboard (poll)
  WS   /ws/alerts       live push channel (dashboard subscribes)

Latency is measured per request and averaged in /health — the number goes on a
slide ("low-latency detection in a constrained one-way environment").

Run: .venv/bin/uvicorn serving.app:app --host 127.0.0.1 --port 8200
"""
import json
import threading
import time
from collections import deque
from pathlib import Path

from fastapi import FastAPI, WebSocket
from pydantic import BaseModel, Field

ART = Path("models/artifacts")
sys_path = str(Path(__file__).resolve().parents[1])

app = FastAPI(title="SIH26145 diode-IDS", version="0.1")
_state: dict = {"xgb": None, "columns": None, "classes": None, "ae": None,
                "ae_cfg": None, "dev": "cpu", "lat_ms": deque(maxlen=200)}
_alerts: deque = deque(maxlen=200)
_ws_clients: set = set()


class ScoreReq(BaseModel):
    features: dict = Field(default_factory=dict)
    sequence: list[list[float]] | None = None


@app.on_event("startup")
def load_models() -> None:
    import joblib
    import sys
    sys.path.insert(0, sys_path)
    if (ART / "xgb_model.joblib").exists():
        _state["xgb"] = joblib.load(ART / "xgb_model.joblib")
        _state["columns"] = json.loads((ART / "feature_columns.json").read_text())
        _state["classes"] = json.loads((ART / "label_classes.json").read_text())
    cfg_f = ART / "lstm_ae_config.json"
    if cfg_f.exists() and (ART / "lstm_ae.pt").exists():
        import torch
        from models.lstm_ae import LSTMAE
        cfg = json.loads(cfg_f.read_text())
        m = LSTMAE(feat_dim=cfg["feat_dim"])
        m.load_state_dict(torch.load(ART / "lstm_ae.pt", map_location="cpu"))
        m.eval()
        _state["ae"], _state["ae_cfg"] = m, cfg
        _state["dev"] = "cuda" if torch.cuda.is_available() else "cpu"


def ae_error(seq) -> float | None:
    """Reconstruction error for one [T,F] sequence window."""
    if _state["ae"] is None or not seq:
        return None
    import numpy as np
    import torch
    cfg = _state["ae_cfg"]
    x = np.asarray(seq, dtype=np.float32)[-cfg["seq_len"]:]
    if x.shape[0] < cfg["seq_len"]:
        pad = np.tile(x[:1], (cfg["seq_len"] - x.shape[0], 1))
        x = np.vstack([pad, x])
    xn = (x - np.asarray(cfg["mu"])) / np.asarray(cfg["sd"])
    t = torch.tensor(xn[None], dtype=torch.float32)
    with torch.no_grad():
        r = _state["ae"](t)
    return float(((r - t) ** 2).mean())


def classify(features: dict) -> tuple[float, str, list[str]]:
    if _state["xgb"] is None:
        return 0.0, "", []
    import numpy as np
    import pandas as pd
    row = {c: (float(features[c]) if c in features and features[c] is not None
               else float("nan"))
           for c in _state["columns"]}
    proba = _state["xgb"].predict_proba(pd.DataFrame([row]))[0]
    classes = _state["classes"]
    bi = classes.index("BENIGN")
    p_attack = float((proba.sum() - proba[bi]) / len(classes))
    top_i = int(np.argmax(proba))
    # feature attributions on demand are expensive; use precomputed importances
    top_feats = json.loads((ART / "classical_metrics.json").read_text()) \
        .get("shap_top_features", []) if (ART / "classical_metrics.json").exists() else []
    return p_attack, classes[top_i], top_feats


def do_score(req: ScoreReq) -> dict:
    t0 = time.perf_counter()
    from fusion.score import fuse                      # repo-root import
    p_attack, pred_label, top_feats = classify(req.features)
    err = ae_error(req.sequence) if req.sequence else None
    out = fuse(p_attack, err, pred_label, top_feats)
    out["predicted_label"] = pred_label or "n/a"
    out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    _state["lat_ms"].append(out["latency_ms"])
    return out


@app.post("/score")
def score(req: ScoreReq) -> dict:
    out = do_score(req)
    if out["verdict"] != "OK":
        row = {"ts": time.time(), **out}
        _alerts.append(row)
        _broadcast(row)
    return out


@app.post("/score_batch")
def score_batch(reqs: list[ScoreReq]) -> list[dict]:
    return [do_score(r) for r in reqs]


@app.get("/recent_alerts")
def recent(n: int = 25) -> list[dict]:
    return list(_alerts)[-n:]


@app.get("/health")
def health() -> dict:
    lat = list(_state["lat_ms"])
    return {
        "classifier": _state["xgb"] is not None,
        "autoencoder": _state["ae"] is not None,
        "device": _state["dev"],
        "avg_latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
        "p95_latency_ms": round(sorted(lat)[int(len(lat) * 0.95)], 2) if lat else None,
    }


async def _ws_loop(ws: WebSocket):
    try:
        while True:
            await ws.receive_text()            # keepalive pings from dashboard
    except Exception:                          # noqa: BLE001
        _ws_clients.discard(ws)


def _broadcast(row: dict):
    import asyncio
    dead = []
    for ws in _ws_clients:
        try:
            asyncio.get_event_loop().create_task(ws.send_json(row))
        except Exception:                      # noqa: BLE001
            dead.append(ws)
    for ws in dead:
        _ws_clients.discard(ws)


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    _ws_clients.add(ws)
    await _ws_loop(ws)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8200)
