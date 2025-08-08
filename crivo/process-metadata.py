#!/usr/bin/env python3
import csv
import gzip
import json
import logging
import os
import pickle
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# ruff: noqa: S314

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

WORKPATH = os.getenv("CRIVO_STORAGE_PATH", "")
if not WORKPATH:
    logger.fatal("CRIVO_STORAGE_PATH is not set")
    sys.exit(1)
WORKDIR: Path = Path(WORKPATH) / "cve-metadata"


def process_epss_csv(basedir: Path, cve2meta: defaultdict[str, dict]):
    fp = basedir / "epss.csv.gz"
    if not fp.exists():
        logger.error("EPSS file not found (%s)", fp)
        msg = "EPSS file missing"
        raise ValueError(msg)
    logger.info("Loading EPSS data from %s", fp)
    with gzip.open(fp, "rt") as fd:
        _ = fd.readline()
        reader = csv.DictReader(fd)
        # todo: skip lines of current header
        if reader.fieldnames != ["cve", "epss", "percentile"]:
            logger.error("EPSS CVS file format changed, aborting")
            msg = "EPSS file format changed"
            raise ValueError(msg)
        for row in reader:
            cve2meta[row["cve"].lower()]["epss"] = {
                "epss_score": float(row["epss"]),
                "epss_percentile": float(row["percentile"]),
            }


def process_kev_db(basedir: Path, cve2meta: dict[str, dict]):
    fp = basedir / "kev.json"
    if not fp.exists():
        logger.error("KEV file not found (%s)", fp)
        msg = "KEV file missing"
        raise ValueError(msg)
    logger.info("Loading KVE database from %s", fp)
    with Path.open(fp, encoding="utf8") as fd:
        kevdb = json.load(fd)
        for vuln in kevdb["vulnerabilities"]:
            cve = vuln.pop("cveID").lower()
            cve2meta[cve]["kev"] = {
                "dateAdded": vuln["dateAdded"],
                "knownRansomwareCampaignUse": vuln["knownRansomwareCampaignUse"],
            }


def merge_cve_classification(basedir: Path, cve2meta: dict[str, dict]):
    fp = basedir / "classification.pkl.gz"
    if not fp.exists():
        logger.warning("CVE classification file not found (%s)", fp)
        msg = "CVE classification file missing"
        raise ValueError(msg)
    logger.info("Loading CVE classification data from %s", fp)
    with gzip.open(fp, "rb") as fd:
        cve2classification = pickle.load(fd)
    for cve, classification in cve2classification.items():
        cve2meta[cve.lower()]["classification"] = dict(classification[1])


def get_cwes(cvedata: dict, cwe2name: dict[str, str]) -> list[tuple[str, str]]:
    cwes: list[tuple[str, str]] = []
    try:
        weaknesses = cvedata["cve"].get("weaknesses", [])
        for entry in weaknesses:
            for description in entry["description"]:
                if description["value"].startswith("CWE"):
                    cweid = description["value"].lower()
                    cwes.append((cweid, cwe2name[cweid]))
    except KeyError:
        return []
    return cwes


def get_cpes(cvedata: dict) -> list[str]:
    cpes: list[str] = []
    try:
        configurations = cvedata["cve"].get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                cpes.extend(
                    match_entry["criteria"]
                    for match_entry in node.get("cpeMatch", [])
                    if match_entry["vulnerable"] and "criteria" in match_entry
                )
    except KeyError:
        return []
    return cpes


def process_cve_files(basedir: Path, cwe2name: dict[str, str], cve2meta: dict[str, dict]):
    for fn in basedir.glob("nvdcve-2.0-*.json.gz"):
        logger.info("Loading CVE data from %s", fn)
        with gzip.open(fn, "r") as fd:
            data = json.load(fd)
        for cvedata in data["vulnerabilities"]:
            cveid = cvedata["cve"]["id"].lower()
            # https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
            for name in ["cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if (cvss := cvedata["cve"]["metrics"].get(name)) is not None:
                    cve2meta[cveid]["impact"] = {
                        "cvss_score": float(cvss[0]["cvssData"]["baseScore"]),
                        "cvss_vector": cvss[0]["cvssData"]["vectorString"],
                        "cvss_version": cvss[0]["cvssData"]["version"],
                    }
                    break
            cve2meta[cveid]["cwes"] = get_cwes(cvedata, cwe2name)
            cve2meta[cveid]["cpes"] = get_cpes(cvedata)


def process_cwe_db(basedir: Path) -> dict[str, str]:
    cwe2name = {}
    for fn in basedir.glob("cwe/*.xml"):
        logger.info("Loading CWE data from %s", fn)
        with Path.open(fn, encoding="utf8") as fd:
            tree = ET.parse(fd)

        root = tree.getroot()
        ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
        for weakness in root.findall(".//cwe:Weaknesses/cwe:Weakness", ns):
            cwe_id = f"cwe-{int(weakness.get('ID', 0))}"
            cwe_name = weakness.get("Name")
            if cwe_id and cwe_name:
                cwe2name[cwe_id] = cwe_name
        for category in root.findall(".//cwe:Categories/cwe:Category", ns):
            cwe_id = f"cwe-{int(category.get('ID', 0))}"
            cwe_name = category.get("Name")
            if cwe_id and cwe_name:
                cwe2name[cwe_id] = cwe_name

    return cwe2name


# cve2meta[cveid]["epss"]: dict[str, float] = {epss_score: value, epss_percentile: value}
# cve2meta[cveid]["kev"]: dict = {dateAdded: "%Y-%m-%d", knownRansomwareCampaignUse: str}
# cve2meta[cveid]["cve"]: dict = {impact: cvss_dict, cwes: list[(cwe, name)], cpes: list[str]}
# cve2meta[cveid]["classification"]: dict[str, float] = {classname: probability}

# example cvss_dicts:
# "metrics" : {
#   "cvssMetricV31" : [ {
#     "source" : "134c704f-9b21-4f2e-91b3-4a467353bcc0",
#     "type" : "Secondary",
#     "cvssData" : {
#       "version" : "3.1",
#       "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
#       "baseScore" : 8.8,
#       "baseSeverity" : "HIGH",
#       "attackVector" : "NETWORK",
#       "attackComplexity" : "LOW",
#       "privilegesRequired" : "NONE",
#       "userInteraction" : "REQUIRED",
#       "scope" : "UNCHANGED",
#       "confidentialityImpact" : "HIGH",
#       "integrityImpact" : "HIGH",
#       "availabilityImpact" : "HIGH"
#     },
#     "exploitabilityScore" : 2.8,
#     "impactScore" : 5.9
#   } ],
#   "cvssMetricV2" : [ {
#     "source" : "nvd@nist.gov",
#     "type" : "Primary",
#     "cvssData" : {
#       "version" : "2.0",
#       "vectorString" : "AV:N/AC:L/Au:N/C:P/I:P/A:P",
#       "baseScore" : 7.5,
#       "accessVector" : "NETWORK",
#       "accessComplexity" : "LOW",
#       "authentication" : "NONE",
#       "confidentialityImpact" : "PARTIAL",
#       "integrityImpact" : "PARTIAL",
#       "availabilityImpact" : "PARTIAL"
#     },
#     "baseSeverity" : "HIGH",
#     "exploitabilityScore" : 10.0,
#     "impactScore" : 6.4,
#     "acInsufInfo" : false,
#     "obtainAllPrivilege" : false,
#     "obtainUserPrivilege" : false,
#     "obtainOtherPrivilege" : false,
#     "userInteractionRequired" : false
#   } ]
# },


def main():
    cve2meta = defaultdict(dict)
    process_epss_csv(WORKDIR, cve2meta)
    process_kev_db(WORKDIR, cve2meta)
    cwe2name = process_cwe_db(WORKDIR)
    process_cve_files(WORKDIR, cwe2name, cve2meta)
    merge_cve_classification(WORKDIR, cve2meta)
    cve2meta = dict(cve2meta)  # remove defaultdict before pickle
    with gzip.open(WORKDIR / "cve2meta.pkl.gz", "w") as fd:
        pickle.dump(cve2meta, fd)
    with Path.open(WORKDIR / "cve2meta.json", "w", encoding="utf8") as fd:
        json.dump(cve2meta, fd)


if __name__ == "__main__":
    main()
