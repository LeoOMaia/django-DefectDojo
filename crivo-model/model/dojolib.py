from __future__ import annotations

import dataclasses
import enum
import pickle
import re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

import pandas as pd
from settings import SEVERITY_LABELS

if TYPE_CHECKING:
    import datastore


@dataclasses.dataclass
class DojoFinding:
    id: int
    title: str
    date: str
    description: str
    severity: str
    vuln_id_from_tool: str
    epss_score: float
    epss_percentile: float
    mitigation: str
    cve: str

    FINDING_DESCRIPTION_GET_HOSTNAME: ClassVar[re.Pattern] = re.compile(r"\*\*Hostname\*\*: (.+)")
    HOSTNAME_KEYWORD_REGEX: ClassVar[re.Pattern] = re.compile(r"-[^0-9]")

    def parse_hostname(self) -> str | None:
        match = DojoFinding.FINDING_DESCRIPTION_GET_HOSTNAME.search(self.description)
        if not match:
            return None
        return match.group(1).strip()

    @staticmethod
    def anonymized_hostname_has_keyword(anon_hostname: str | None) -> bool:
        if anon_hostname is None:
            return False
        return bool(DojoFinding.HOSTNAME_KEYWORD_REGEX.search(anon_hostname))

    def compute_features(self, ds: datastore.DataStore) -> DojoFindingFeatures:
        cve_data = ds.get_data()
        cve_list = ds.parse_desc(self.description) or []
        hostname = self.parse_hostname()
        # metadata = DojoFindingsMetadata(cve_list, hostname)

        max_cvss_score = 0
        max_epss_score = 0
        max_epss_percentile = 0
        max_epss_num_cwes = 0
        max_epss_num_cpes = 0
        num_cves_epss_p80 = 0
        remote_code_execution = 0
        privilege_escalation = 0
        information_disclosure = 0
        denial_of_service = 0
        buffer_overflow = 0
        cross_site_request_forgery = 0
        sql_injection = 0
        cross_site_scripting = 0
        in_kev = False

        for raw_cve in cve_list:
            cve = raw_cve.lower()
            impact = cve_data.get(cve, {}).get("impact", {})
            cvss_score_candidate = impact.get("cvss_score", 0)
            max_cvss_score = max(max_cvss_score, cvss_score_candidate)

            epss = cve_data.get(cve, {}).get("epss", {})
            if epss.get("epss_percentile", 0) >= 0.8:
                num_cves_epss_p80 += 1

            epss_score_candidate = epss.get("epss_score", 0)
            if max_epss_score < epss_score_candidate:
                cve_class = cve_data.get(cve, {}).get("classification", {})
                cwes = cve_data.get(cve, {}).get("cwes", [])
                cpes = cve_data.get(cve, {}).get("cpes", [])
                max_epss_score = epss_score_candidate
                max_epss_percentile = epss.get("epss_percentile", 0)
                max_epss_num_cwes = len(set(cwes))
                max_epss_num_cpes = len(set(cpes))
                remote_code_execution = cve_class.get("remote code execution", 0)
                privilege_escalation = cve_class.get("privilege escalation", 0)
                information_disclosure = cve_class.get("information disclosure", 0)
                denial_of_service = cve_class.get("denial of service", 0)
                buffer_overflow = cve_class.get("buffer overflow", 0)
                cross_site_request_forgery = cve_class.get("cross site request forgery", 0)
                sql_injection = cve_class.get("sql injection", 0)
                cross_site_scripting = cve_class.get("cross site scripting", 0)

            in_kev = max(in_kev, "kev" in cve_data.get(cve, {}))

        return DojoFindingFeatures(
            fid=self.id,
            severity=SEVERITY_LABELS.get(self.severity, -1),
            max_cvss_score=max_cvss_score,
            max_epss_score=max_epss_score,
            max_epss_percentile=max_epss_percentile,
            max_epss_num_cwes=max_epss_num_cwes,
            max_epss_num_cpes=max_epss_num_cpes,
            num_cves=len(cve_list),
            num_cves_epss_p80=num_cves_epss_p80,
            num_cves_2020=len([c for c in cve_list if int(c.split("-")[1]) >= 2020]),
            cve_remote_code_execution=remote_code_execution,
            cve_privilege_escalation=privilege_escalation,
            cve_information_disclosure=information_disclosure,
            cve_denial_of_service=denial_of_service,
            cve_buffer_overflow=buffer_overflow,
            cve_cross_site_request_forgery=cross_site_request_forgery,
            cve_sql_injection=sql_injection,
            cve_cross_site_scripting=cross_site_scripting,
            in_kev=in_kev,
            has_dns_keyword=DojoFinding.anonymized_hostname_has_keyword(hostname),
            os=OperatingSystem.from_description(self.description),
            mitigation=MitigationType.parse_raw(self.mitigation),
        )


@dataclasses.dataclass
class DojoRanking:
    id: int
    user_id: int
    timestamp: str
    risk_class: str | None = None
    risk_num: int | None = None
    ranking: int | None = dataclasses.field(init=False)

    CLASS_MAP: ClassVar[dict[str, float | None]] = {
        "Mild": 1.0,
        "Moderate": 2.0,
        "Severe": 3.0,
        "Critical": 4.0,
        "NA": None,
    }

    def __post_init__(self):
        if self.risk_num is not None:
            self.ranking = int(self.risk_num)
        elif self.risk_class is not None:
            self.ranking = DojoRanking.CLASS_MAP[self.risk_class]
        else:
            self.ranking = None


@dataclasses.dataclass
class DojoFindingsMetadata:
    cve_list: list[str]
    hostname: str | None


@dataclasses.dataclass
class DojoFindingFeatures:
    fid: int
    severity: int
    max_cvss_score: float
    max_epss_score: float
    max_epss_percentile: float
    max_epss_num_cwes: int
    max_epss_num_cpes: int
    num_cves: int
    num_cves_epss_p80: int
    num_cves_2020: int
    cve_remote_code_execution: float
    cve_privilege_escalation: float
    cve_information_disclosure: float
    cve_denial_of_service: float
    cve_buffer_overflow: float
    cve_cross_site_request_forgery: float
    cve_sql_injection: float
    cve_cross_site_scripting: float
    in_kev: bool
    has_dns_keyword: bool
    os: OperatingSystem
    mitigation: MitigationType

    CATEGORICAL_FEATURES: ClassVar[list[str]] = ["in_kev", "has_dns_keyword", "os", "mitigation"]


FEATURE_NAMES = {
    "max_cvss_score": "Maximum CVSS",
    "max_epss_score": "Maximum EPSS",
    "max_epss_percentile": "Maximum EPSS Percentile",
    "max_epss_num_cwes": "Number of CWEs",
    "max_epss_num_cpes": "Number of CPEs",
    "num_cves": "Number of CVEs",
    "num_cves_epss_p80": "Num. CVEs with EPSS in p80",
    "num_cves_2020": "Num. of Recent CVEs",
    "cve_remote_code_execution": "Remote Code Execution",
    "cve_privilege_escalation": "Privilege Escalation",
    "cve_information_disclosure": "Information Disclosure",
    "cve_denial_of_service": "Denial of Service",
    "cve_buffer_overflow": "Buffer Overflow",
    "cve_cross_site_request_forgery": "Cross-site Request Forgery",
    "cve_sql_injection": "SQL Injection",
    "cve_cross_site_scripting": "XSS",
    "in_kev": "CVE in KEV Database",
    "has_dns_keyword": "Hostname has sensitive keyword",
    "severity": "OpenVAS Severity",
    "os": "Operating System",
    "mitigation": "Mitigation Type",
}


OS_VENDOR_REGEX = re.compile(r"\*\*OS\*\*: cpe:/o:([^:]+):.*")
OS_VENDOR_MAP = {
    "canonical": "linux",
    "centos": "linux",
    "debian": "linux",
    "linux": "linux",
    "redhat": "linux",
    "ubuntu": "linux",
    "microsoft": "windows",
    None: "unknown",
}


class OperatingSystem(enum.StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"
    OTHER = "other"

    @staticmethod
    def from_description(finding_description: str) -> OperatingSystem:
        match = OS_VENDOR_REGEX.search(finding_description)
        if not match:
            return OperatingSystem.UNKNOWN
        os_raw = match.group(1).strip()
        return OperatingSystem(OS_VENDOR_MAP.get(os_raw, "other"))


class MitigationType(enum.StrEnum):
    MITIGATION = "Mitigation"
    VENDORFIX = "VendorFix"
    WORKAROUND = "Workaround"
    WILLNOTFIX = "WillNotFix"
    NONEAVAILABLE = "NoneAvailable"
    EMPTY = "Empty"
    OTHERS = "Others"

    @staticmethod
    def parse_raw(mitigation_raw: str | None) -> MitigationType:
        if mitigation_raw is None:
            return MitigationType.EMPTY
        mitigation = mitigation_raw.strip()
        if not mitigation:
            return MitigationType.EMPTY
        first_line = mitigation.split("\n")[0]
        if not first_line:
            return MitigationType.EMPTY
        if first_line in {"None", "N/A", "NoneAvailable"}:
            return MitigationType.NONEAVAILABLE
        try:
            return MitigationType(first_line)
        except ValueError:
            return MitigationType.OTHERS


def load_features_rankings(
    features_file: Path,
    risk_file: Path,
    ds: datastore.DataStore,
) -> tuple[list[DojoFindingFeatures], list[DojoRanking]]:
    findings_raw: list[dict] = pickle.load(Path.open(features_file, "rb"))
    findings: list[DojoFinding] = [DojoFinding(**f) for f in findings_raw]
    features: list[DojoFindingFeatures] = [f.compute_features(ds) for f in findings]

    rankings_raw: list[dict] = pickle.load(Path.open(risk_file, "rb"))
    rankings = [DojoRanking(**r) for r in rankings_raw]

    return features, rankings


def get_merged_df(
    findings: list[DojoFindingFeatures], rankings: list[DojoRanking],
) -> pd.DataFrame:
    df_features = pd.DataFrame(findings)
    for col in DojoFindingFeatures.CATEGORICAL_FEATURES:
        df_features[col] = df_features[col].astype(str).astype("category")
    df_rankings = pd.DataFrame(rankings)
    df_rankings = df_rankings.drop(columns=["timestamp", "risk_class", "risk_num"])
    df_merged = df_features.merge(df_rankings, left_on="fid", right_on="id", how="left")
    if "id_y" in df_merged.columns:
        df_merged = df_merged.drop(columns=["id_y"])
    return df_merged
