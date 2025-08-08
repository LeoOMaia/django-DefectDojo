import logging
import pickle
import re
import signal
import time
from contextlib import contextmanager
from pathlib import Path

import dojolib
import numpy as np
import pandas as pd
import psutil
import requests
from datastore import DataStore
from settings import (
    CVE2META_PICKLE_FP,
    PREDICT_DIR,
    TARGET_COLUMN,
    TOKEN_FILE,
    URL_API,
    WORKDIR,
    XGBOOST_LEARNING_RATE,
    XGBOOST_MAX_DEPTH,
    XGBOOST_NUM_ESTIMATORS,
)
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from xgboost import XGBRegressor

shutdown_flag = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

ASSESSMENT_DIR = WORKDIR / "model/user_assessments"
FEATURES_DIR = WORKDIR / "model/finding_features"
CLASS_LABELS = {v: k for k, v in dojolib.DojoRanking.CLASS_MAP.items() if v is not None}


def load_token_from_envfile(env_path):
    if not env_path.exists():
        return ""
    with env_path.open() as f:
        for line in f:
            if line.startswith("TOKEN_API_KEY="):
                return line.strip().split("=", 1)[1]
    return ""


def load_combined_data(assessment_fp: Path, features_fp: Path, datastore: DataStore) -> pd.DataFrame:
    class_features, class_rankings = dojolib.load_features_rankings(features_fp, assessment_fp, datastore)
    return dojolib.get_merged_df(class_features, class_rankings)


def prepare_training_data(training_df: pd.DataFrame) -> pd.DataFrame:
    training_df = training_df[training_df[TARGET_COLUMN].notna()].copy()

    if "risk_class" in training_df.columns:
        training_df = training_df[training_df["risk_class"] != "NA"]
    if "risk_num" in training_df.columns:
        training_df = training_df[training_df["risk_num"] != "NV"]

    for col in dojolib.DojoFindingFeatures.CATEGORICAL_FEATURES:
        training_df[col] = training_df[col].astype(str).astype("category")

    return training_df


def prepare_prediction_data(pred_df: pd.DataFrame, training_df: pd.DataFrame) -> pd.DataFrame:
    pred_df = pred_df[pred_df[TARGET_COLUMN].isna()].copy()
    pred_df = pred_df.set_index("fid", drop=False)

    for col in dojolib.DojoFindingFeatures.CATEGORICAL_FEATURES:
        train_cats = training_df[col].cat.categories
        pred_df[col] = pred_df[col].astype(str).astype(pd.CategoricalDtype(categories=train_cats))

    return pred_df


def train_model(x: pd.DataFrame, y: pd.Series) -> XGBRegressor:
    model = XGBRegressor(
        n_estimators=XGBOOST_NUM_ESTIMATORS,
        learning_rate=XGBOOST_LEARNING_RATE,
        max_depth=XGBOOST_MAX_DEPTH,
        verbosity=0,
        enable_categorical=True,
    )
    model.fit(x, y)
    return model


def predict(df: pd.DataFrame, model: XGBRegressor, feature_columns: list[str]) -> pd.DataFrame:
    df["predicted_raw_score"] = model.predict(df[feature_columns])
    df["predicted_risk_class"] = np.round(df["predicted_raw_score"])
    df["predicted_risk_label"] = df["predicted_risk_class"].map(CLASS_LABELS)
    return df


def export_predictions_to_pickle(predictions_df: pd.DataFrame, output_path: Path) -> None:
    df_to_pickle = predictions_df.assign(id=predictions_df.index)[
        ["id", "user_id", "predicted_risk_label", "predicted_risk_class"]
    ].to_dict(orient="records")
    with Path.open(output_path, "wb") as f:
        pickle.dump(df_to_pickle, f)
    logger.info(f"Exported prediction results to {output_path} as pickle")


def request_create_inferences(predict_file_path: Path, total_inferences: int) -> None:
    authorization = load_token_from_envfile(TOKEN_FILE)
    if authorization is None:
        logger.error("AUTHORIZATION token is not set. Cannot make API request.")
        return

    headers = {
        "Authorization": f"Token {authorization}",
    }
    payload = {
        "inferences": str(predict_file_path),
    }

    try:
        response = requests.post(
            URL_API,
            headers=headers,
            json=payload,
            verify=True,
            timeout=20,
        )
    except requests.RequestException:
        logger.exception(f"Request to {URL_API} failed")
        return

    try:
        resp_json = response.json()
    except ValueError:
        resp_json = None

    if response.status_code // 100 == 2:
        if resp_json and "imported" in resp_json:
            if resp_json["imported"] == total_inferences:
                logger.info(f"Successfully created {total_inferences} inferences.")
            else:
                logger.warning(
                    f"Created {resp_json['imported']} inferences, expected {total_inferences} inferences.",
                )
        else:
            logger.info(f"Response from API: {response.status_code} - {response.text}")
    else:
        logger.error(f"API error response: {response.status_code} - {response.text}")


def process_prediction_pipeline(assessment_fp: Path, features_fp: Path, datastore: DataStore):
    logger.info(f"Processing files:\n- Assessments: {assessment_fp}\n- Features: {features_fp}")
    class_df = load_combined_data(assessment_fp, features_fp, datastore)
    unique_users = class_df["user_id"].dropna().unique()
    if len(unique_users) != 1:
        error_message = (
            f"Expected exactly one user_id in the data, but found {len(unique_users)}: {unique_users}"
        )
        logger.error(error_message)
    else:
        user_id = int(unique_users[0])
        class_df = class_df.drop(columns=["user_id"])
        training_df = prepare_training_data(class_df)
        columns_to_exclude = ["id", "fid", "ranking", "risk_class", "risk_num"]
        feature_columns = [col for col in training_df.columns if col not in columns_to_exclude]
        model = train_model(training_df[feature_columns], training_df[TARGET_COLUMN])
        prediction_df = prepare_prediction_data(class_df, training_df)
        prediction_result = predict(prediction_df, model, feature_columns)
        prediction_result["user_id"] = user_id

        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        predict_file = PREDICT_DIR / f"user2data_{user_id}_{timestamp}.pkl"
        export_predictions_to_pickle(prediction_result, predict_file)

        total_inferences = len(prediction_result)
        request_create_inferences(predict_file, total_inferences)

    if assessment_fp.exists():
        assessment_fp.unlink()
    else:
        logger.warning(f"Assessment file {assessment_fp} was missing during cleanup.")

    if features_fp.exists():
        features_fp.unlink()
    else:
        logger.warning(f"Features file {features_fp} was missing during cleanup.")
    logger.info("Cleanup temporary files completed.")


def handle_event(event, datastore):
    assessment_fp = Path(event.src_path)
    if assessment_fp.suffix != ".pkl":
        logger.debug(f"Ignoring non-pkl file in assessment directory: {assessment_fp}")
        return
    logger.info(f"Detected new assessment file: {assessment_fp.name}")
    match = re.search(r"([^_]+)_(\d{8}_\d{6})_assessments\.pkl", assessment_fp.name)
    if not match:
        logger.warning(f"Filename does not match expected pattern: {assessment_fp.name}")
        return
    user_id = match.group(1)
    timestamp = match.group(2)
    features_fp = FEATURES_DIR / f"{user_id}_{timestamp}_features.pkl"
    if features_fp.exists():
        process_prediction_pipeline(assessment_fp, features_fp, datastore)
    else:
        logger.warning(f"Features file not found: {features_fp}")


def handle_shutdown(signum, frame):
    global shutdown_flag
    shutdown_flag = True


@contextmanager
def managed_observer(observer):
    observer.start()
    try:
        yield observer
    finally:
        logger.info("Stopping observer...")
        observer.stop()
        observer.join()
        logger.info("Shutdown complete.")


def main():
    logger.info("Loading datastore...")
    datastore = DataStore()
    datastore.load(metadata_fp=CVE2META_PICKLE_FP)

    process = psutil.Process()
    mem_info = process.memory_info()
    ram_used_mb = mem_info.rss / (1024 * 1024)  # Convert bytes to MB
    logger.info(f"RAM usage after loading DataStore: {ram_used_mb:.2f} MB")

    logger.info(f"Watching directory: {ASSESSMENT_DIR}")
    observer = Observer()

    def on_created(event):
        handle_event(event, datastore)

    event_handler = FileSystemEventHandler()
    event_handler.on_created = on_created
    observer.schedule(event_handler, str(ASSESSMENT_DIR), recursive=False)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)
    with managed_observer(observer):
        if hasattr(signal, "pause"):
            while not shutdown_flag:
                signal.pause()
        else:
            while not shutdown_flag:
                time.sleep(3600)


if __name__ == "__main__":
    main()
