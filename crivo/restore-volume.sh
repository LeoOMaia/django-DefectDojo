#!/bin/bash
set -eu

TARFILE=$(pwd)/backup-2025-05-07-norisk.tar.gz
# https://www.dcc.ufmg.br/~cunha/hosted/crivo-metadata-d1a2c69c-1ebd-11f0-a0cf-a7cc2967d76b/backup-2025-05-07-norisk.tar.gz
VOLUME=test_defectdojo_crivo

if [[ "$TARFILE" != /* ]]; then
    echo "Error: TARFILE path must be absolute"
    exit 1
fi

if ! docker volume ls -q | grep -w $VOLUME &>/dev/null; then
    echo "docker volume $VOLUME not found, creating"
    docker volume create $VOLUME
fi

docker run --rm \
	-v $VOLUME:/volume \
	-v "$TARFILE:/app/backup.tar.gz" \
	busybox \
	sh -c "cd /volume && tar xzf /app/backup.tar.gz && chmod -R 777 ."
