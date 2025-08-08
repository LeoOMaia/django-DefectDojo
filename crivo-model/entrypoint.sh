#!/bin/sh
set -eu

# create directories in CRIVO_STORAGE_PATH if not exist
mkdir -p "$CRIVO_STORAGE_PATH/model/user_assessments"
mkdir -p "$CRIVO_STORAGE_PATH/model/finding_features"
mkdir -p "$CRIVO_STORAGE_PATH/model/predict_inferences"

# Permissions: 
# 755 - owner can read/write/execute, others can read/execute
# 777 - needed to remove files created by the model and to allow the model to write to these directories
chmod 755 "$CRIVO_STORAGE_PATH/model"
chmod 777 "$CRIVO_STORAGE_PATH/model/predict_inferences"
chmod 777 "$CRIVO_STORAGE_PATH/model/user_assessments"
chmod 777 "$CRIVO_STORAGE_PATH/model/finding_features"

python3 /usr/src/app/model/update_model.py