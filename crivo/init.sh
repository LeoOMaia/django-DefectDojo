#!/bin/sh
set -eux

METADIR=$CRIVO_STORAGE_PATH
CVEDIR=$METADIR/cve-metadata

mkdir -p $METADIR
chmod 777 $METADIR

mkdir -p $CVEDIR
chmod 777 $CVEDIR

curl --silent --output $CVEDIR/classification.pkl.gz \
        https://pugna.snes.dcc.ufmg.br/defectdojo/cve-classification.pkl.gz

curl --location --silent --output $CVEDIR/epss.csv.gz \
        https://epss.empiricalsecurity.com/epss_scores-current.csv.gz

curl --location --silent --output $CVEDIR/kev.json \
        https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

curl --location --silent --output $CVEDIR/cwe.xml.zip \
        https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
unzip -u $CVEDIR/cwe.xml.zip -d $CVEDIR/cwe

for year in $(seq 2002 2025) ; do
    curl --silent --output $CVEDIR/nvdcve-2.0-$year.json.gz \
			https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$year.json.gz
done

/app/process-metadata.py

ls -al $METADIR
ls -al $CVEDIR
