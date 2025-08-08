#!/bin/bash

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh
. /reach_database.sh

# Allow for bind-mount multiple settings.py overrides
FILES=$(ls /app/docker/extra_settings/* 2>/dev/null || true)
NUM_FILES=$(echo "$FILES" | wc -w)
if [ "$NUM_FILES" -gt 0 ]; then
    COMMA_LIST=$(echo "$FILES" | tr -s '[:blank:]' ', ')
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with multiple"
    echo "     Files: $COMMA_LIST"
    echo "============================================================"
    cp /app/docker/extra_settings/* /app/dojo/settings/
    rm -f /app/dojo/settings/README.md
fi

umask 0002

wait_for_database_to_be_reachable
python manage.py complete_initialization

echo $CRIVO_STORAGE_PATH
mkdir -p "$CRIVO_STORAGE_PATH"
cat <<EOD | python manage.py shell
import os
import sys
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
crivo_path = os.getenv('CRIVO_STORAGE_PATH', '/app/crivo-metadata')
user = User.objects.filter(username=os.getenv('DD_ADMIN_USER', 'admin')).first()
if not user:
    print("Admin user not found. Exiting.")
    sys.exit(1)
token, created = Token.objects.get_or_create(user=user)
with open(os.path.join(crivo_path, "api-token.env"), "w") as f:
    f.write(f"TOKEN_API_KEY={token.key}\n")
EOD

exec "$@"
