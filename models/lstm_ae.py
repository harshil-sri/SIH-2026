#!/usr/bin/env python3
"""SIH26145 — Novel-threat detector: LSTM Autoencoder on benign-only sequences.

Trained exclusively on sequence windows from slices labeled BENIGN (Monday +
benign context margins). At inference, reconstruction error above a tuned
threshold flags traffic whose temporal *texture* was never seen in normal
one-way streams — the zero-day/novel-threat story.

Outputs (models/artifacts/):
  lstm_ae.pt            model weights
  lstm_ae_config.json   dims, threshold, normalization constants
  ae_metrics.json       separation AUC, chosen percentile, error stats
  ae_errors.png         benign-vs-attack reconstruction-error histogram

Usage: python models/lstm_ae.py [--features-dir data/features]
"""
import argparse
import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn


class LSTMAE(nn.Module):
    def __init__(self, feat_dim: int = 3, hidden: int = 64, latent: int = 16):
        super().__init__()
        self.enc = nn.LSTM(feat_dim, hidden, batch_first=True)
        self.to_latent = nn.Linear(hidden, latent)
        self.dec = nn.LSTM(latent, hidden, batch_first=True)
        self.out = nn.Linear(hidden, feat_dim)

    def forward(self, x):
        _, (h, _) = self.enc(x)                     # h: (1, B, H)
        z = self.to_latent(h[-1])                   # (B, latent) bottleneck
        z_t = z.unsqueeze(1).repeat(1, x.size(1), 1)  # (B, T, latent)
        h0 = h                                       # reuse encoder state to init decoder
        c0 = torch.zeros_like(h0)
        y, _ = self.dec(z_t, (h0, c0))
        return self.out(y)


def load_windows(features_dir: Path, want_attack: bool):
    Xs, sl_ids = [], []
    for f in sorted(features_dir.glob("seqs_*.npz")):
        z = np.load(f, allow_pickle=True)
        mask = z["is_attack"].astype(bool)
        sel = mask if want_attack else ~mask
        if sel.any():
            Xs.append(z["X"][sel])
            sl_ids.extend([f.stem] * int(sel.sum()))
    if not Xs:
        return None, []
    return np.concatenate(Xs), sl_ids


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features-dir", default="data/features")
    ap.add_argument("--artifacts-dir", default="models/artifacts")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--batch", type=int, default=512)
    args = ap.parse_args()

    from sklearn.metrics import roc_auc_score
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    dev = "cuda" if torch.cuda.is_available() else "cpu"
    art = Path(args.artifacts_dir)
    art.mkdir(parents=True, exist_ok=True)

    Xb, b_slices = load_windows(Path(args.features_dir), want_attack=False)
    if Xb is None or len(Xb) < 200:
        raise SystemExit("not enough benign windows — run replay + extractor first")
    Xa, _ = load_windows(Path(args.features_dir), want_attack=True)

    # normalization constants from benign train split
    rng = np.random.default_rng(42)
    perm = rng.permutation(len(Xb))
    n_val = max(200, int(0.15 * len(Xb)))
    val_idx, tr_idx = perm[:n_val], perm[n_val:]
    mu = Xb[tr_idx].reshape(-1, Xb.shape[-1]).mean(0)
    sd = Xb[tr_idx].reshape(-1, Xb.shape[-1]).std(0) + 1e-6
    norm = lambda a: (a - mu) / sd                                    # noqa: E731

    Xtr = torch.tensor(norm(Xb[tr_idx]), dtype=torch.float32, device=dev)
    Xval = torch.tensor(norm(Xb[val_idx]), dtype=torch.float32, device=dev)

    model = LSTMAE(feat_dim=Xb.shape[-1]).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs)
    lossf = nn.MSELoss(reduction="none")

    best_val, patience, bad = float("inf"), 8, 0
    for ep in range(args.epochs):
        model.train()
        p = torch.randperm(Xtr.size(0), device=dev)
        tot = 0.0
        for s in range(0, len(p), args.batch):
            xb = Xtr[p[s:s + args.batch]]
            opt.zero_grad()
            loss = lossf(model(xb), xb).mean()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
            tot += float(loss) * len(xb)
        model.eval()
        with torch.no_grad():
            vloss = lossf(model(Xval), Xval).mean().item()
        sched.step()
        bad = bad + 1 if vloss > best_val * 0.999 else 0
        best_val = min(best_val, vloss)
        if ep % 10 == 0:
            print(f"ep {ep:03d}  train {tot/len(Xtr):.5f}  val {vloss:.5f}")
        if bad >= patience:
            print(f"early stop @ ep{ep} (best val {best_val:.5f})")
            break

    def errors(a: np.ndarray) -> np.ndarray:
        out = []
        with torch.no_grad():
            for s in range(0, len(a), 4096):
                xa = torch.tensor(norm(a[s:s + 4096]), dtype=torch.float32, device=dev)
                e = lossf(model(xa), xa).mean(dim=(1, 2))
                out.append(e.cpu().numpy())
        return np.concatenate(out) if out else np.array([])

    val_err = errors(Xb[val_idx])
    thr_grid = np.quantile(val_err, [0.90, 0.95, 0.97, 0.99, 0.995, 0.999])
    info = {"val_error_mean": float(val_err.mean()), "val_error_std": float(val_err.std())}

    eval_rows = {"auc": None}
    if Xa is not None and len(Xa):
        ea = errors(Xa)
        ybin = np.r_[np.zeros(len(val_err)), np.ones(len(ea))]
        auc = roc_auc_score(ybin, np.r_[val_err, ea])
        eval_rows["auc"] = round(float(auc), 4)
        eval_rows["attack_err_mean"] = float(ea.mean())
        plt.figure(figsize=(8, 5))
        plt.hist(val_err, bins=80, alpha=0.65, density=True, label="benign (val)")
        plt.hist(ea, bins=80, alpha=0.65, density=True, label="attack")
        for t in thr_grid:
            plt.axvline(t, color="gray", lw=0.5, alpha=0.6)
        if eval_rows["auc"] is not None and eval_rows["auc"] > 0.5:
            plt.legend()
        plt.xlabel("reconstruction error (MSE)")
        plt.title(f"LSTM-AE separation ROC-AUC={eval_rows['auc']}")
        plt.tight_layout()
        plt.savefig(art / "ae_errors.png", dpi=130)

    torch.save(model.state_dict(), art / "lstm_ae.pt")
    config = {
        "feat_dim": int(Xb.shape[-1]), "seq_len": int(Xb.shape[1]),
        "mu": mu.tolist(), "sd": sd.tolist(),
        "threshold": float(thr_grid[1]),          # default: 95th pct of benign val err
        "threshold_candidates": {str(q): float(t) for q, t in zip(
            [0.90, 0.95, 0.97, 0.99, 0.995, 0.999], thr_grid)},
        **info,
    }
    (art / "lstm_ae_config.json").write_text(json.dumps(config, indent=2))
    (art / "ae_metrics.json").write_text(json.dumps(eval_rows, indent=2))
    print(json.dumps(eval_rows, indent=2))
    print(f"artifacts -> {art}/ (device={dev})")


if __name__ == "__main__":
    main()
