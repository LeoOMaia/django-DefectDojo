import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache

import redis
from django.utils.safestring import mark_safe

from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}
MODES = ["vuln_id_from_tool", "title", "cve"]
CHOSEN_GROUP_MODE = "finding_groups_mode"
SYSTEM_CHANGE = "last_finding_change"


@dataclass
class DynamicFindingGroups:
    finding_group_id: str
    name: str = ""
    severity: str = "Info"
    main_finding_id: int = None
    sla_finding_id: int = None
    finding_ids: set = field(default_factory=set)

    def to_dict(self):
        return {
            "name": self.name,
            "finding_group_id": self.finding_group_id,
            "severity": self.severity,
            "main_finding_id": self.main_finding_id,
            "sla_finding_id": self.sla_finding_id,
            "finding_ids": list(self.finding_ids),
        }

    @staticmethod
    def from_dict(data):
        return DynamicFindingGroups(
            name=data["name"],
            finding_group_id=data["finding_group_id"],
            severity=data["severity"],
            main_finding_id=data.get("main_finding_id"),
            sla_finding_id=data.get("sla_finding_id"),
            finding_ids=set(data.get("finding_ids", [])),
        )

    @staticmethod
    def load_from_id(finding_group_id, fg_key, redis_client):
        finding_group_data = redis_client.hget(fg_key, finding_group_id)
        if finding_group_data:
            return DynamicFindingGroups.from_dict(json.loads(finding_group_data))
        return None

    def persist(self, fg_key, redis_client):
        if not self.finding_ids:
            redis_client.hdel(fg_key, self.finding_group_id)
        else:
            redis_client.hset(fg_key, self.finding_group_id, json.dumps(self.to_dict()))

    def update_sev_sla(self, finding):
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[self.severity]:
            self.severity = finding.severity
            self.main_finding_id = finding.id
        if finding.active and finding.sla_days_remaining():
            if not self.sla_finding_id or finding.sla_days_remaining() < Finding.objects.get(id=self.sla_finding_id).sla_days_remaining():
                self.sla_finding_id = finding.id

    def reconfig_finding_group(self):
        self.severity = "Info"
        self.sla_finding_id = None
        findings = Finding.objects.filter(id__in=self.finding_ids)
        for finding in findings:
            self.update_sev_sla(finding)

    @staticmethod
    def get_group_names(finding, group_by) -> list:
        if group_by == "vuln_id_from_tool":
            return [finding.vuln_id_from_tool]
        if group_by == "title":
            return [finding.title]
        if group_by == "cve":
            cves = list(
                finding.vulnerability_id_set.values_list("vulnerability_id", flat=True),
            )
            if cves:
                return cves
        return None

    @staticmethod
    def set_last_finding_change():
        redis_client = get_redis_client()
        redis_client.set(SYSTEM_CHANGE, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    @staticmethod
    def set_last_update(mode, timestamp):
        if mode in MODES:
            redis_client = get_redis_client()
            redis_client.set(f"last_update_{mode}", timestamp)

    @staticmethod
    def add_finding(finding, mode):
        finding_groups = DynamicFindingGroups.get_group_names(finding, mode)
        if not finding_groups:
            return
        for finding_group_name in finding_groups:
            finding_group_id = base64.b64encode(finding_group_name.encode()).decode()
            redis_client = get_redis_client()
            fg_key = f"finding_groups_{mode}"
            id_map_key = f"id_to_finding_group_{mode}"

            finding_group = DynamicFindingGroups.load_from_id(finding_group_id, fg_key, redis_client)
            if not finding_group:
                finding_group = DynamicFindingGroups(finding_group_id=finding_group_id, name=finding_group_name)

            if finding.id not in finding_group.finding_ids:
                finding_group.update_sev_sla(finding)
                finding_group.finding_ids.add(finding.id)

            redis_client.hset(fg_key, finding_group_id, json.dumps(finding_group.to_dict()))
            group_ids_raw = redis_client.hget(id_map_key, finding.id)
            group_ids = json.loads(group_ids_raw) if group_ids_raw else []
            if finding_group_id not in group_ids:
                group_ids.append(finding_group_id)
            redis_client.hset(id_map_key, finding.id, json.dumps(group_ids))

    # This method is used in finding_groups table to show SLA
    def get_days_remaining(self):
        if self.sla_finding_id:
            finding = Finding.objects.filter(id=self.sla_finding_id).first()
            find_sla = finding.sla_days_remaining()
            sla_age, _ = finding.get_sla_period()
            severity = finding.severity
            status = "age-green"
            status_text = f"Remediation for {severity.lower()} findings in {sla_age} days or less since {finding.get_sla_start_date().strftime('%b %d, %Y')}"
            if find_sla and find_sla < 0:
                status = "age-red"
                status_text = f"Overdue: Remediation for {severity.lower()} findings in {sla_age} days or less since {finding.get_sla_start_date().strftime('%b %d, %Y')}"
                find_sla = abs(find_sla)
        elif any(
            Finding.objects.filter(
                id__in=self.finding_ids,
                active=True,
            ),
        ):
            status = "severity-Info"
            status_text = "No SLA set, but at least one finding is active"
            find_sla = "No SLA"
        else:
            status = "age-blue"
            status_text = "Any finding is active"
            find_sla = "Concluded"
        title = (
            f'<a class="has-popover" data-toggle="tooltip" data-placement="bottom" title="" href="#" data-content="{status_text}">'
            f'<span class="label severity {status}">{find_sla}</span></a>'
        )
        return mark_safe(title)


@lru_cache(maxsize=1)
def get_redis_client():
    return redis.Redis(host="redis", port=6379, decode_responses=True)


def actual_mode():
    redis_client = get_redis_client()
    if redis_client.exists(CHOSEN_GROUP_MODE):
        return json.loads(redis_client.get(CHOSEN_GROUP_MODE))
    return None


def set_mode(mode):
    if mode in MODES:
        redis_client = get_redis_client()
        redis_client.set(CHOSEN_GROUP_MODE, json.dumps(mode))
        logger.info(f"Dynamic finding groups mode set to {mode}")


def dict_finding_groups_findings(mode):
    if not mode or mode not in MODES:
        return {}
    redis_client = get_redis_client()
    fg_key = f"finding_groups_{mode}"
    id_map_key = f"id_to_finding_group_{mode}"
    if not redis_client.exists(SYSTEM_CHANGE):
        DynamicFindingGroups.set_last_finding_change()
    last_update = redis_client.get(f"last_update_{mode}")
    last_finding_change = redis_client.get(SYSTEM_CHANGE)

    # Check if finding_groups and id_map exist in Redis
    # If not, rebuild them
    if not redis_client.exists(fg_key) or not redis_client.exists(id_map_key) or last_update != last_finding_change:
        redis_client.delete(fg_key, id_map_key)
        for finding in Finding.objects.all():
            DynamicFindingGroups.add_finding(finding, mode)
        DynamicFindingGroups.set_last_update(mode, last_finding_change)
    return _load_finding_groups_from_redis(fg_key, redis_client)


def _load_finding_groups_from_redis(fg_key, redis_client):
    finding_groups_data = redis_client.hgetall(fg_key)
    if finding_groups_data:
        return {
            key: DynamicFindingGroups.from_dict(json.loads(value))
            for key, value in finding_groups_data.items()
        }
    return {}
