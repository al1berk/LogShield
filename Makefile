PYTHON ?= python3
PYTHONPATH := src
export PYTHONPATH

.PHONY: data train calibrate evaluate ablation test api dashboard demo report

data:
	$(PYTHON) scripts/build_dataset.py
	$(PYTHON) scripts/build_ood_stress_test.py

train:
	$(PYTHON) scripts/train_all.py
	$(PYTHON) scripts/calibrate_threshold.py

calibrate:
	$(PYTHON) scripts/calibrate_threshold.py

evaluate:
	$(PYTHON) scripts/evaluate_all.py

ablation:
	$(PYTHON) scripts/run_ablation.py

test:
	$(PYTHON) -m pytest -q

api:
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

dashboard:
	streamlit run dashboard/app.py

demo:
	docker compose up --build

report:
	$(PYTHON) scripts/export_report.py
