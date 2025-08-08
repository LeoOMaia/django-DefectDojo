#!/bin/bash
set -eu

VOLUME=projectname_defectdojo_crivo

if ! docker volume ls -q | grep -w $VOLUME &>/dev/null; then
    echo "docker volume $VOLUME not found, aborting"
    exit 1
fi

DATE=$(date +%Y-%m-%d)
BACKUP=$(pwd)/backup
mkdir -p "$BACKUP"

docker run --rm \
  -v $VOLUME:/volume \
  -v "$BACKUP:/backup" \
  busybox \
  tar --exclude=findings_risk.db -czf /backup/backup-$DATE-norisk.tar.gz \
    -C /volume .

docker run --rm \
  -v $VOLUME:/volume \
  -v "$BACKUP:/backup" \
  busybox \
  cp /volume/findings_risk.db /backup/findings_risk.db
