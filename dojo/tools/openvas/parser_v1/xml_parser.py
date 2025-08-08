import contextlib
import logging
from xml.dom import NamespaceErr

from defusedxml import ElementTree
from django.conf import settings

from dojo.crivo.datastore import DataStore
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

logger = logging.getLogger(__name__)


class OpenVASXMLParser:
    def get_findings(self, filename, test):
        findings = []
        tree = ElementTree.parse(filename)
        root = tree.getroot()
        if "report" not in root.tag:
            msg = "This doesn't seem to be a valid Greenbone OpenVAS XML file."
            raise NamespaceErr(msg)
        report = root.find("report")
        hosts = report.findall("host")
        hosts_os = self.get_host_os(hosts)
        results = report.find("results")

        cve_dataset = {}

        datastore = DataStore()
        cve_dataset = datastore.get_data()

        for result in results:
            script_id = None
            loc_host = ""
            loc_port = None
            loc_protocol = ""

            for field in result:
                if field.tag == "name":
                    title = field.text
                    description = [f"**Name**: {field.text}"]
                if field.tag == "hostname":
                    title = title + "_" + field.text
                    description.append(f"**Hostname**: {field.text}")
                    if field.text:
                        host_val = field.text.strip()  # strip due to https://github.com/greenbone/gvmd/issues/2378
                        loc_host = host_val
                if field.tag == "host":
                    title = title + "_" + field.text
                    description.append(f"**Host**: {field.text}")
                    if not loc_host and field.text:
                        host_val = field.text.strip()  # strip due to https://github.com/greenbone/gvmd/issues/2378
                        loc_host = host_val
                if field.tag == "port":
                    title = title + "_" + field.text
                    description.append(f"**Port**: {field.text}")
                    if field.text:
                        port_str, protocol = field.text.split("/")
                        with contextlib.suppress(ValueError):
                            loc_port = int(port_str)
                        loc_protocol = protocol
                if field.tag == "nvt":
                    description.append(f"**NVT**: {field.text}")
                    script_id = field.get("oid") or field.text

                    # capture CVEs
                    refs = field.find("refs")
                    cve_list = []

                    if refs is not None:
                        cve_list = [ref.get("id") for ref in refs.findall("ref") if ref.get("type") == "cve"]

                    if cve_list:
                        description.append(f"**CVEs**: {', '.join(cve_list)}")

                    # capture solution attribute and type
                    solution = field.find("solution").attrib["type"]
                    solution_text = field.find("solution").text
                    mitigation_text = str(solution) + "\n\n" + str(solution_text)

                if field.tag == "severity":
                    description.append(f"**Severity**: {field.text}")
                if field.tag == "threat":
                    description.append(f"**Threat**: {field.text}")
                    severity = field.text if field.text in {"Info", "Low", "Medium", "High", "Critical"} else "Info"
                if field.tag == "qod":
                    description.append(f"**QOD**: {field.text}")
                if field.tag == "description":
                    description.append(f"**Description**: {field.text}")

            epss_score, epss_percentile, cve = self.get_epss_data(cve_list, cve_dataset)

            finding = Finding(
                title=str(title),
                test=test,
                description="\n".join(description),
                severity=severity,
                dynamic_finding=True,
                static_finding=False,
                vuln_id_from_tool=script_id,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                cve=cve,
                mitigation=mitigation_text,
            )
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations = [LocationData.url(
                    host=loc_host, port=loc_port, protocol=loc_protocol,
                )]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [Endpoint(host=loc_host, port=loc_port, protocol=loc_protocol)]
            findings.append(finding)
        return findings

    def get_epss_data(self, cve_list: list, cve_dataset: dict):
        if not cve_list:
            return None, None, None

        if not cve_dataset:
            logger.debug("No cve_dataset, check for dataset in /app/crivo-metadata/cve-metadata")
            return None, None, None

        filtered_cves = [
            (
                cve_dataset[cveid.lower()]["epss"]["epss_score"],
                cve_dataset[cveid.lower()]["epss"]["epss_percentile"],
                cveid,
            )
            for cveid in cve_list if cveid.lower() in cve_dataset
        ]
        filtered_cves.sort(reverse=True)

        if not filtered_cves:
            logger.info("All CVEs are missing from metadata: %s", ",".join(cve_list))
            return None, None, None

        return filtered_cves[0]

    def convert_cvss_score(self, raw_value):
        val = float(raw_value)
        if val == 0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"

    def get_host_os(self, hosts):
        host_os = {}
        for host in hosts:
            ip = host.find("ip")
            if ip is None:
                continue
            ip = ip.text
            details = host.findall("detail")
            for detail in details:
                tag_name = detail.find("name")
                if tag_name is None:
                    continue
                if tag_name.text == "best_os_cpe":
                    tag_value = detail.find("value")
                    if tag_value is None:
                        continue
                    os = tag_value.text
                    if os is not None:
                        host_os[ip] = os
                        break
        return host_os
