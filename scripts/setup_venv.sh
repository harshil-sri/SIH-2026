#!/usr/bin/env bash
# SIH26145 — Python environment. No sudo required.
# Usage: bash scripts/setup_venv.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip wheel setuptools

# Core numerics / extraction
pip install numpy pandas pyarrow polars scapy dpkt tqdm
# Classical ML + explainability
pip install scikit-learn xgboost imbalanced-learn shap matplotlib joblib
# Deep learning (CUDA build auto-selected by pip on this box)
pip install torch --index-url https://download.pytorch.org/whl/cu121
# Serving + dashboard
pip install fastapi "uvicorn[standard]" websockets streamlit plotly

python - <<'PY'
import numpy, pandas, sklearn, xgboost, torch
print("numpy", numpy.__version__)
print("pandas", pandas.__version__)
print("sklearn", sklearn.__version__)
print("xgboost", xgboost.__version__)
print("torch", torch.__version__, "| cuda:", torch.cuda.is_available())
PY
echo "venv ready: source $ROOT/.venv/bin/activate"
