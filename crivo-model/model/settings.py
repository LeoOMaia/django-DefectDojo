import os
from pathlib import Path

WORKDIR = Path(os.getenv("CRIVO_STORAGE_PATH"))
TOKEN_FILE = WORKDIR / "api-token.env"
CVE2META_PICKLE_FP = WORKDIR / "cve-metadata/cve2meta.pkl.gz"
PREDICT_DIR = WORKDIR / "model/predict_inferences"
URL_API = "http://nginx:8080/api/v2/risk_triggers/"
TARGET_COLUMN = "ranking"
XGBOOST_NUM_ESTIMATORS = 100
XGBOOST_MAX_DEPTH = 10
XGBOOST_LEARNING_RATE = 0.2
SEVERITY_LABELS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
    "Undefined": -1,
}
