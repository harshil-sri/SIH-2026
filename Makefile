# SIH26145 — build & demo targets
PY    = .venv/bin/python
SHELL := /bin/bash

.PHONY: setup venv download windows slices replay extract train report serve dashboard demo-live diode clean-data

setup:            ## one-time: apt tooling + scoped sudoers (needs password once)
	sudo bash scripts/bootstrap_sudo.sh

venv:             ## python environment
	bash scripts/setup_venv.sh

download:         ## resumable dataset fetch (~50GB)
	bash scripts/download_datasets.sh

windows:          ## attack windows from CSV labels, then verified against pcaps
	$(PY) replay/build_windows.py && $(PY) replay/derive_windows_from_pcap.py

slices:           ## cut replay slices per data/windows_pcap.json
	$(PY) replay/make_slices.py --windows data/windows_pcap.json

replay:           ## replay all slices through the diode, capture monitor-side
	$(PY) replay/run_plan.py

extract:          ## forward-only features for every captured slice
	$(PY) extraction/batch_extract.py

train:            ## both models + fusion config
	$(PY) models/train_xgb.py && $(PY) models/lstm_ae.py

report:           ## evaluation summary -> evaluation/REPORT.md
	$(PY) evaluation/make_report.py

serve:
	$(PY) -m uvicorn serving.app:app --port 8200

dashboard:
	$(PY) -m streamlit run dashboard/app.py --server.port 8400

demo-live:        ## full live demo loop through the emulated diode
	bash scripts/live_demo.sh

diode:
	bash diode/setup_diode.sh && bash diode/verify_diode.sh

clean-data:       ## remove derived artifacts, keep raw datasets
	rm -rf data/features data/captures replay/slices models/artifacts/*
